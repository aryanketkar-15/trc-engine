"""Attack-resistance mapping (Compliance agent): a rule base, no AI inference.

risk + asset criticality -> attacker class (rules CR-1 to CR-5, expert confirms) -> required
resistance, JIL attack potential, assurance component, SESIP level and CC EAL. An LLM may add a
written rationale (explainer.py) but never decides a value. Every record is confirmed by a named
expert.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import BaseModel, Field, model_validator

from agents.risk_agent.schemas import RiskAssessment, RiskLevel, Treatment

if TYPE_CHECKING:
    from agents.threat_agent.schemas import AssetModel

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.json")
UNKNOWN = "Unknown"


class RulesError(ValueError):
    """The rule base is incomplete or a value is not in it."""


class ComplianceStatus(StrEnum):
    PENDING_HUMAN = "pending_human"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    STALE = "stale"


@dataclass(frozen=True)
class Rules:
    version: str
    classes: list[str]
    table: dict[str, dict[str, Any]]
    risk_to_class: dict[str, dict[str, str]]
    floors: list[dict[str, str]]
    criticality_floors: list[dict[str, str]]
    citations: list[dict[str, str]]
    high_at_least: int
    medium_at_least: int

    @classmethod
    def load(cls, path: Path | None = None) -> Rules:
        data = json.loads((path or DEFAULT_RULES_PATH).read_text(encoding="utf-8"))
        rules = cls(
            version=str(data["rules_version"]),
            classes=list(data["attacker_classes"]),
            table=data["class_table"],
            risk_to_class={r["risk"]: r for r in data["risk_to_class"]},
            floors=list(data.get("feasibility_floor", [])),
            criticality_floors=list(data.get("criticality_floor", [])),
            citations=list(data.get("citations", [])),
            high_at_least=int(data.get("asset_criticality", {}).get("high_at_least", 3)),
            medium_at_least=int(data.get("asset_criticality", {}).get("medium_at_least", 2)),
        )
        needed = ("required_resistance", "jil_attack_potential", "assurance_component")
        for name in rules.classes:
            row = rules.table.get(name)
            if row is None:
                raise RulesError(f"no table row for attacker class {name}")
            for key in (*needed, "sesip_level", "cc_eal"):
                if not row.get(key):
                    raise RulesError(f"attacker class {name} has no value for {key}")
        for level in RiskLevel:
            rule = rules.risk_to_class.get(level.value)
            if rule is None or rule["attacker_class"] not in rules.classes:
                raise RulesError(f"no rule maps {level.value} risk to an attacker class")
        for floor in (*rules.floors, *rules.criticality_floors):
            if floor["at_least"] not in rules.classes:
                raise RulesError(f"rule {floor['rule_id']} names an unknown attacker class")
        return rules


class ComplianceRecord(BaseModel):
    """Required attack resistance for one threat, as confirmed by an expert."""

    compliance_id: str
    tid: str
    risk_id: str
    project_id: str | None = None
    use_case_id: str | None = None
    asset_id: str
    effective_risk: RiskLevel
    suggested_attacker_class: str
    attacker_class: str
    required_resistance: str
    jil_attack_potential: str
    assurance_component: str
    sesip_level: str
    cc_eal: str
    rule_id: str
    asset_criticality: str = UNKNOWN
    citations: list[dict[str, str]] = Field(default_factory=list)
    ai_rationale: str | None = None
    ai_evidence: list[dict[str, Any]] = Field(default_factory=list)
    ai_confidence: float | None = None
    ai_model: str | None = None
    ai_prompt_version: str | None = None
    overridden: bool = False
    override_reason: str | None = None
    notes: str | None = None
    justification: str
    status: ComplianceStatus = ComplianceStatus.PENDING_HUMAN
    confirmed_by: str | None = None
    risk_fingerprint: str
    rules_version: str
    run_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ComplianceDecision(BaseModel):
    """The expert's confirmation, optionally with a different attacker class."""

    approver: Annotated[str, Field(min_length=1)]
    attacker_class: str | None = Field(
        default=None, description="Leave empty to confirm the suggested class."
    )
    override_reason: str | None = None
    notes: str | None = None

    @model_validator(mode="after")
    def _override_needs_reason(self) -> ComplianceDecision:
        if self.attacker_class and not (self.override_reason or "").strip():
            raise ValueError("choosing a different attacker class needs an override_reason")
        return self


def risk_fingerprint(risk: RiskAssessment) -> str:
    """What the mapping depends on; a change means the mapping must be redone."""
    treatment = risk.treatment.value if risk.treatment else ""
    return f"{risk.risk_id}|{risk.effective_risk.value}|{risk.attack_feasibility.value}|{treatment}"


def applies(risk: RiskAssessment, *, include_all: bool = False) -> bool:
    """Resistance is required for threats that are reduced; accepted or avoided ones skip it."""
    if risk.status.value != "approved":
        return False
    return include_all or risk.treatment == Treatment.REDUCE


def _lookup(rules: Rules, attacker_class: str) -> dict[str, Any]:
    row = rules.table.get(attacker_class)
    if row is None:
        raise RulesError(f"unknown attacker class '{attacker_class}'; use one of {rules.classes}")
    return row


def asset_criticality(asset: AssetModel | None, rules: Rules) -> str:
    """High, Medium or Low from how many security properties the asset requires."""
    if asset is None:
        return UNKNOWN
    required = sum(1 for v in asset.security_attributes.model_dump().values() if v)
    if required >= rules.high_at_least:
        return "High"
    return "Medium" if required >= rules.medium_at_least else "Low"


def suggested_class(
    risk: RiskAssessment, rules: Rules, criticality: str = UNKNOWN
) -> tuple[str, str]:
    """Attacker class by rule: from the effective risk, raised by the floor rules."""
    rule = rules.risk_to_class[risk.effective_risk.value]
    chosen, rule_id = rule["attacker_class"], rule["rule_id"]
    for floor in rules.floors:
        raises = rules.classes.index(floor["at_least"]) > rules.classes.index(chosen)
        if floor["attack_feasibility"] == risk.attack_feasibility.value and raises:
            chosen, rule_id = floor["at_least"], f"{rule_id}+{floor['rule_id']}"
    for floor in rules.criticality_floors:
        raises = rules.classes.index(floor["at_least"]) > rules.classes.index(chosen)
        applies_here = (
            floor["asset_criticality"] == criticality
            and floor["effective_risk"] == risk.effective_risk.value
        )
        if applies_here and raises:
            chosen, rule_id = floor["at_least"], f"{rule_id}+{floor['rule_id']}"
    return chosen, rule_id


def propose(risk: RiskAssessment, rules: Rules, *, criticality: str = UNKNOWN) -> ComplianceRecord:
    """Suggest the mapping for one approved risk (status pending_human)."""
    chosen, rule_id = suggested_class(risk, rules, criticality)
    return _build(risk, rules, chosen, rule_id, overridden=False, criticality=criticality)


def _build(
    risk: RiskAssessment,
    rules: Rules,
    attacker_class: str,
    rule_id: str,
    *,
    overridden: bool,
    override_reason: str | None = None,
    notes: str | None = None,
    criticality: str = UNKNOWN,
) -> ComplianceRecord:
    row = _lookup(rules, attacker_class)
    suggested, _ = suggested_class(risk, rules, criticality)
    why = (
        f"Risk {risk.effective_risk.value} "
        f"({'expert-adjusted' if risk.adjusted_risk else 'computed'}) with attack feasibility "
        f"{risk.attack_feasibility.value} and asset criticality {criticality} maps by rule "
        f"{rule_id} to attacker class {suggested}."
    )
    if overridden:
        why += f" The expert chose {attacker_class} instead: {override_reason}."
    why += (
        f" Class {attacker_class} requires: {row['required_resistance']}; JIL attack potential "
        f"{row['jil_attack_potential']}; assurance component {row['assurance_component']}; "
        f"{row['sesip_level']}; {row['cc_eal']}."
    )
    return ComplianceRecord(
        compliance_id=f"CMP-{risk.tid}",
        tid=risk.tid,
        risk_id=risk.risk_id,
        project_id=risk.project_id,
        use_case_id=risk.use_case_id,
        asset_id=risk.asset_id,
        effective_risk=risk.effective_risk,
        suggested_attacker_class=suggested,
        attacker_class=attacker_class,
        required_resistance=str(row["required_resistance"]),
        jil_attack_potential=str(row["jil_attack_potential"]),
        assurance_component=str(row["assurance_component"]),
        sesip_level=str(row["sesip_level"]),
        cc_eal=str(row["cc_eal"]),
        rule_id=rule_id if not overridden else "EXPERT-OVERRIDE",
        asset_criticality=criticality,
        citations=list(rules.citations),
        overridden=overridden,
        override_reason=override_reason if overridden else None,
        notes=notes,
        justification=why,
        risk_fingerprint=risk_fingerprint(risk),
        rules_version=rules.version,
        run_id=risk.run_id,
    )


def confirm(
    risk: RiskAssessment,
    rules: Rules,
    decision: ComplianceDecision,
    *,
    criticality: str = UNKNOWN,
) -> ComplianceRecord:
    """Apply the expert's decision and return the confirmed record."""
    proposed = propose(risk, rules, criticality=criticality)
    chosen = decision.attacker_class
    if chosen and chosen != proposed.suggested_attacker_class:
        record = _build(
            risk,
            rules,
            chosen,
            proposed.rule_id,
            overridden=True,
            override_reason=decision.override_reason,
            notes=decision.notes,
            criticality=criticality,
        )
    else:
        record = proposed.model_copy(update={"notes": decision.notes})
    return record.model_copy(
        update={"status": ComplianceStatus.CONFIRMED, "confirmed_by": decision.approver}
    )


def load_records(raw: dict[str, Any]) -> list[ComplianceRecord]:
    """Stored records as objects; records in an older format are skipped until they are redone."""
    records: list[ComplianceRecord] = []
    for item in raw.values():
        try:
            records.append(ComplianceRecord.model_validate(item))
        except ValueError:
            continue
    return records


def protection_targets(records: list[ComplianceRecord], rules: Rules) -> dict[str, Any]:
    """Required protection level per asset and for the product: the strongest class that applies."""

    def strongest(items: list[ComplianceRecord]) -> dict[str, Any]:
        top = max(items, key=lambda r: rules.classes.index(r.attacker_class))
        return {
            "attacker_class": top.attacker_class,
            "required_resistance": top.required_resistance,
            "jil_attack_potential": top.jil_attack_potential,
            "assurance_component": top.assurance_component,
            "sesip_level": top.sesip_level,
            "cc_eal": top.cc_eal,
            "driven_by": sorted(r.tid for r in items if r.attacker_class == top.attacker_class),
        }

    grouped: dict[str, list[ComplianceRecord]] = {}
    for rec in records:
        grouped.setdefault(rec.asset_id, []).append(rec)
    return {
        "per_asset": {asset: strongest(items) for asset, items in sorted(grouped.items())},
        "product": strongest(records) if records else None,
    }


def check_compliance_staleness(
    records: dict[str, Any], risks: dict[str, Any]
) -> tuple[list[tuple[str, str]], list[str]]:
    """Return ([(tid, reason)] stale records, [tid] Reduce-risks without a record)."""
    stale: list[tuple[str, str]] = []
    for tid, rec in records.items():
        risk = risks.get(tid)
        if not isinstance(rec, dict):
            continue
        if not isinstance(risk, dict):
            stale.append((tid, "risk assessment was retired or removed"))
            continue
        current = RiskAssessment.model_validate(risk)
        if rec.get("risk_fingerprint") != risk_fingerprint(current):
            stale.append((tid, "risk or treatment changed after the mapping was confirmed"))
    unmapped = []
    for tid, risk in risks.items():
        if tid in records or not isinstance(risk, dict):
            continue
        if applies(RiskAssessment.model_validate(risk)):
            unmapped.append(tid)
    return stale, unmapped
