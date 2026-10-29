"""Suggest impact and feasibility ratings for one approved threat.

Suggestions are proposals for the expert; the numbers that follow are computed by engine.py.
With the live LLM off, or when the call fails, a deterministic rule from the asset's yes/no
security properties and the STRIDE category is used, and the suggestion says so.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from agents.risk_agent.schemas import (
    FeasibilityFactors,
    ImpactLevel,
    ImpactRatings,
    RiskInput,
)
from agents.threat_agent.schemas import AssetModel, ThreatScenario
from common.llm_client import LLMClientError, chat_completion
from common.pii_redaction import redact_pii
from config.settings import get_settings

logger = logging.getLogger(__name__)

PROMPT_VERSION = "risk-suggest-v1"

#: Which security property a STRIDE class mainly attacks.
_STRIDE_PROPERTY = {
    "Spoofing": "authenticity",
    "Tampering": "integrity",
    "Repudiation": "authenticity",
    "InformationDisclosure": "confidentiality",
    "DenialOfService": "availability",
    "ElevationOfPrivilege": "integrity",
}


def deterministic_suggestion(scenario: ThreatScenario, asset: AssetModel | None) -> RiskInput:
    """Rule-based starting point: the attacked property decides how many axes are hit."""
    prop = _STRIDE_PROPERTY.get(scenario.stride_category.value, "integrity")
    required = bool(asset and getattr(asset.security_attributes, prop))
    # a property the asset actually needs is hurt harder
    hit = ImpactLevel.SEVERE if required else ImpactLevel.MODERATE
    if prop == "confidentiality":
        impact = ImpactRatings(privacy=hit, financial=ImpactLevel.MODERATE)
    elif prop == "availability":
        impact = ImpactRatings(operational=hit, financial=ImpactLevel.MODERATE)
    else:
        impact = ImpactRatings(operational=hit, financial=ImpactLevel.MODERATE, safety=None)
    factors = FeasibilityFactors(
        elapsed_time="1_month",
        expertise="proficient",
        knowledge="restricted",
        window="moderate",
        equipment="specialized",
    )
    return RiskInput(
        tid=scenario.tid,
        impact=impact,
        feasibility_factors=factors,
        ai_suggested=True,
        suggestion_basis=(
            f"rule-based default: {scenario.stride_category.value} attacks {prop}"
            f" ({'required' if required else 'not required'} for this asset); "
            "feasibility is a neutral starting value, please review"
        ),
    )


def _system_prompt(valid: dict[str, list[str]]) -> str:
    return (
        "You assist an automotive/IoT security expert with ISO/SAE 21434 risk assessment. "
        "For ONE threat, propose impact per axis and the five attack-feasibility factors. "
        "Answer with JSON only, no prose, in exactly this shape: "
        '{"impact": {"safety": L|null, "financial": L|null, "operational": L|null, '
        '"privacy": L|null}, "feasibility": {"elapsed_time": V, "expertise": V, '
        '"knowledge": V, "window": V, "equipment": V}, "reason": "one or two sentences"}. '
        "L is one of Negligible, Moderate, Major, Severe, or null when the axis does not apply. "
        f"Allowed values: {json.dumps(valid)}. "
        "Use only the facts given; do not invent facts about the product. "
        "Your answer is a proposal that a human will review."
    )


def _user_prompt(scenario: ThreatScenario, asset: AssetModel | None) -> str:
    facts: dict[str, Any] = {
        "asset": asset.name if asset else scenario.asset_id,
        "asset_properties_required": (
            asset.security_attributes.model_dump() if asset else "unknown"
        ),
        "asset_damage_scenario": getattr(asset, "damage_scenario", None) if asset else None,
        "stride": scenario.stride_category.value,
        "attack": scenario.attack_vector,
        "why_applicable": scenario.evidence_chain.applicability_reason,
        "catalogue_reference": scenario.kb_reference,
    }
    return redact_pii(json.dumps(facts, default=str))


def _parse(raw: str, valid: dict[str, list[str]], tid: str) -> RiskInput:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{") :]
    data = json.loads(text)
    feas = data["feasibility"]
    for key, allowed in valid.items():
        if feas[key] not in allowed:
            raise ValueError(f"{key}='{feas[key]}' not in {allowed}")
    return RiskInput(
        tid=tid,
        impact=ImpactRatings.model_validate(data["impact"]),
        feasibility_factors=FeasibilityFactors.model_validate(feas),
        ai_suggested=True,
        suggestion_basis=f"LLM suggestion: {str(data.get('reason', '')).strip()[:400]}",
    )


def suggest(
    scenario: ThreatScenario,
    asset: AssetModel | None,
    valid_factor_values: dict[str, list[str]],
) -> RiskInput:
    """LLM suggestion with deterministic fallback; never raises for model problems."""
    settings = get_settings()
    use_live = getattr(settings, "USE_LIVE_LLM", True)
    if os.environ.get("USE_LIVE_LLM", "").lower() in ("false", "0", "no"):
        use_live = False
    if not use_live:
        return deterministic_suggestion(scenario, asset)
    try:
        raw = chat_completion(
            system_prompt=_system_prompt(valid_factor_values),
            user_prompt=_user_prompt(scenario, asset),
            model=getattr(settings, "OPENAI_MODEL", None),
            prompt_version=PROMPT_VERSION,
            run_id=scenario.run_id,
        )
        return _parse(raw, valid_factor_values, scenario.tid)
    except (LLMClientError, ValueError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("risk suggestion fell back to rules for %s: %s", scenario.tid, exc)
        fallback = deterministic_suggestion(scenario, asset)
        return fallback.model_copy(
            update={"suggestion_basis": f"{fallback.suggestion_basis} (LLM unavailable)"}
        )
