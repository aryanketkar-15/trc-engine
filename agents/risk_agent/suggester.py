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

from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import (
    FeasibilityFactors,
    ImpactLevel,
    ImpactRatings,
    RiskInput,
)
from agents.threat_agent.schemas import AssetModel, ThreatScenario
from common.llm_client import LLMClientError, chat_completion
from common.llm_json import extract_json_text
from common.pii_redaction import redact_pii
from config.settings import get_settings

logger = logging.getLogger(__name__)

PROMPT_VERSION = "risk-suggest-v2"

# A suggestion is a short JSON object; a small cap keeps the call cheap and within credit limits.
_MAX_TOKENS = 700

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


_FACTOR_MEANING = {
    "elapsed_time": "time to prepare and carry out the attack",
    "expertise": "skill the attacker needs",
    "knowledge": "knowledge of the item the attacker needs",
    "window": "how long and how easily the attacker can reach the target",
    "equipment": "tools the attacker needs",
}

#: Plain words for values whose name does not explain itself (the points come from ratings.json).
_VALUE_WORDS = {
    "expertise": {
        "layman": "no special skill",
        "proficient": "knows this kind of system",
        "expert": "deep skill in the exact technique",
        "multiple_experts": "several experts with different skills",
    },
    "knowledge": {
        "public": "openly documented",
        "restricted": "shared only with partners or owners",
        "sensitive": "internal design documents",
        "critical": "secrets only a few insiders hold",
    },
    "window": {
        "unlimited": "always reachable, e.g. a service on the internet",
        "easy": "reachable most of the time with little effort",
        "moderate": "only while near the device (e.g. in Bluetooth range) or for a limited time",
        "difficult": "only at a rare moment, or physical access under tight limits",
    },
    "equipment": {
        "standard": "everyday tools: phone, laptop, free software",
        "specialized": "low-cost special hardware or software, e.g. a radio sniffer",
        "bespoke": "custom-built or costly lab equipment",
        "multiple_bespoke": "several different bespoke tools",
    },
}

_EXAMPLES = (
    "Three examples of different difficulty (other products, shown only to calibrate you):\n"
    'EASY: "An unauthenticated web endpoint of a fleet-management cloud service returns other '
    "customers' location histories when an ID is guessed. Interfaces: HTTPS, REST. Trust zone: "
    'internet-facing cloud." -> impact {"safety": null, "financial": "Major", "operational": '
    '"Moderate", "privacy": "Severe"}, feasibility {"elapsed_time": "1_day", "expertise": '
    '"layman", "knowledge": "public", "window": "unlimited", "equipment": "standard"}. '
    "Remote, no special tools, open all the time: an easy attack.\n"
    'MEDIUM: "An attacker who is already on the plant network changes the settings of an '
    "industrial gateway using the vendor's restricted maintenance guide. Interfaces: Ethernet, "
    'Modbus. Trust zone: plant network." -> impact {"safety": null, "financial": "Moderate", '
    '"operational": "Major", "privacy": null}, feasibility {"elapsed_time": "1_month", '
    '"expertise": "proficient", "knowledge": "restricted", "window": "moderate", '
    '"equipment": "standard"}. Needs network access and a restricted document: a medium '
    "attack.\n"
    'HARD: "A secret key is read out of a sealed engine-controller chip by removing its '
    'package and probing the silicon. Physical access to the device. Interfaces: none." -> '
    'impact {"safety": "Major", "financial": "Major", "operational": "Major", "privacy": null}, '
    'feasibility {"elapsed_time": "3_months", "expertise": "multiple_experts", "knowledge": '
    '"sensitive", "window": "difficult", "equipment": "bespoke"}. Physical access, a lab and '
    "several experts: a hard attack."
)


def _threshold_text(ratings: Ratings) -> str:
    parts: list[str] = []
    start = 0
    for max_points, level in ratings.thresholds:
        span = f"{start} or more" if max_points >= 1000 else f"{start}-{max_points}"
        parts.append(f"{span} points = {level.value} feasibility")
        start = max_points + 1
    return "; ".join(parts)


def _scale_text(valid: dict[str, list[str]], ratings: Ratings) -> str:
    """What each allowed value costs the attacker, from the rule tables, in plain words."""
    lines: list[str] = []
    for factor, values in valid.items():
        words = _VALUE_WORDS.get(factor, {})
        table = ratings.points.get(factor, {})
        entries = []
        for value in values:
            note = f" ({words[value]})" if value in words else ""
            entries.append(f"{value} = {table[value]} points{note}" if value in table else value)
        meaning = _FACTOR_MEANING.get(factor, factor)
        lines.append(f"- {factor} ({meaning}): " + "; ".join(entries))
    return "\n".join(lines)


def _system_prompt(valid: dict[str, list[str]]) -> str:
    ratings = Ratings.load()
    return (
        "You assist an automotive/IoT security expert with ISO/SAE 21434 risk assessment. "
        "For ONE threat, propose impact per axis and the five attack-feasibility factors. "
        "Answer with JSON only, no prose, in exactly this shape: "
        '{"impact": {"safety": L|null, "financial": L|null, "operational": L|null, '
        '"privacy": L|null}, "feasibility": {"elapsed_time": V, "expertise": V, '
        '"knowledge": V, "window": V, "equipment": V}, "reason": "one or two sentences"}. '
        "L is one of Negligible, Moderate, Major, Severe, or null when the axis does not apply. "
        f"Allowed values: {json.dumps(valid)}.\n"
        "How the factors are scored: every value carries points, the points of the five factors "
        "are added, and a HIGHER total means a HARDER attack (lower feasibility). "
        f"Totals: {_threshold_text(ratings)}.\n{_scale_text(valid, ratings)}\n"
        "Base each factor on the facts you are given, not on habit: where the attacker must be "
        "(remote over the internet, within Bluetooth or other radio range, or with physical access "
        "to the device), whether special equipment or insider knowledge is needed, and how long "
        "the window stays open. Threats differ in difficulty, so rate this one on its own facts. "
        "Choose the value the stated facts support: a value above the lowest one needs a stated "
        "fact that requires it (for example non-public documents for knowledge, special hardware "
        "for equipment, deep skill in one technique for expertise, weeks of work for elapsed "
        "time), and a very hard value needs several such facts. If a fact is not given, do not "
        "assume the easiest or the hardest value.\n"
        f"{_EXAMPLES}\n"
        "Use only the facts given; do not invent facts about the product. "
        "Your answer is a proposal that a human will review."
    )


def _user_prompt(
    scenario: ThreatScenario,
    asset: AssetModel | None,
    feedback: str | None = None,
    previous: RiskInput | None = None,
) -> str:
    facts: dict[str, Any] = {
        "asset": asset.name if asset else scenario.asset_id,
        "asset_properties_required": (
            asset.security_attributes.model_dump() if asset else "unknown"
        ),
        "asset_damage_scenario": getattr(asset, "damage_scenario", None) if asset else None,
        "asset_interfaces": asset.dfd_context.interfaces if asset else "unknown",
        "asset_trust_zone": asset.dfd_context.trust_zone if asset else "unknown",
        "stride": scenario.stride_category.value,
        "attack": scenario.attack_vector,
        "why_applicable": scenario.evidence_chain.applicability_reason,
        "catalogue_reference": scenario.kb_reference,
    }
    if feedback:
        facts["expert_rejected_previous_suggestion_because"] = feedback
        facts["previous_suggestion"] = (
            previous.model_dump(mode="json", exclude={"suggestion_basis"}) if previous else None
        )
        facts["instruction"] = "Give a different suggestion that addresses the expert's reason."
    return redact_pii(json.dumps(facts, default=str))


_NO_VALUE = {"null", "none", "n/a", "na", ""}


def _impact_values(impact: object) -> object:
    """Impact axes a model marks as "no value" in words ("Null", "N/A") become a real None.

    Only the impact object is read this way; feasibility values stay checked against the list.
    """
    if not isinstance(impact, dict):
        return impact
    return {
        axis: None if isinstance(value, str) and value.strip().lower() in _NO_VALUE else value
        for axis, value in impact.items()
    }


def _parse(raw: str, valid: dict[str, list[str]], tid: str) -> RiskInput:
    data = json.loads(extract_json_text(raw))
    feas = data["feasibility"]
    for key, allowed in valid.items():
        if feas[key] not in allowed:
            raise ValueError(f"{key}='{feas[key]}' not in {allowed}")
    return RiskInput(
        tid=tid,
        impact=ImpactRatings.model_validate(_impact_values(data["impact"])),
        feasibility_factors=FeasibilityFactors.model_validate(feas),
        ai_suggested=True,
        suggestion_basis=f"LLM suggestion: {str(data.get('reason', '')).strip()[:400]}",
    )


def _fallback(
    scenario: ThreatScenario,
    asset: AssetModel | None,
    feedback: str | None,
    previous: RiskInput | None,
    why: str,
) -> RiskInput:
    base = previous or deterministic_suggestion(scenario, asset)
    if feedback:
        return base.model_copy(
            update={
                "suggestion_basis": (
                    f"could not produce a new suggestion ({why}); the expert's reason was "
                    f"recorded: {feedback[:200]}. Please enter the ratings manually"
                )
            }
        )
    if why == "live LLM is off":
        return base
    return base.model_copy(update={"suggestion_basis": f"{base.suggestion_basis} ({why})"})


def suggest(
    scenario: ThreatScenario,
    asset: AssetModel | None,
    valid_factor_values: dict[str, list[str]],
    *,
    feedback: str | None = None,
    previous: RiskInput | None = None,
) -> RiskInput:
    """LLM suggestion with deterministic fallback; never raises for model problems.

    With ``feedback`` (the expert's reason for rejecting ``previous``) the model is asked for a
    different suggestion. Without the model the previous suggestion is returned unchanged and
    labelled so that the expert enters the ratings manually.
    """
    settings = get_settings()
    use_live = getattr(settings, "USE_LIVE_LLM", True)
    if os.environ.get("USE_LIVE_LLM", "").lower() in ("false", "0", "no"):
        use_live = False
    if not use_live:
        return _fallback(scenario, asset, feedback, previous, "live LLM is off")
    try:
        raw = chat_completion(
            system_prompt=_system_prompt(valid_factor_values),
            user_prompt=_user_prompt(scenario, asset, feedback, previous),
            model=getattr(settings, "OPENAI_MODEL", None),
            prompt_version=PROMPT_VERSION,
            max_tokens=_MAX_TOKENS,
            run_id=scenario.run_id,
        )
        return _parse(raw, valid_factor_values, scenario.tid)
    except (LLMClientError, ValueError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("risk suggestion fell back to rules for %s: %s", scenario.tid, exc)
        return _fallback(scenario, asset, feedback, previous, "LLM unavailable")
