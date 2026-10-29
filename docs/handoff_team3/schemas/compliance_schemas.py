"""Attack-resistance mapping (Compliance agent): a rule base, no AI inference.

risk -> attacker class (provisional rule, expert confirms) -> required resistance, JIL attack
potential, SESIP level and CC EAL (company rows). Every record is confirmed by a named expert.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

from risk_schemas import RiskAssessment, RiskLevel, Treatment

DEFAULT_RULES_PATH = Path(__file__).with_name("rules_placeholder.json")
NEEDS_VALUE = "needs company value"


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

    @classmethod
    def load(cls, path: Path | None = None) -> Rules:
        data = json.loads((path or DEFAULT_RULES_PATH).read_text(encoding="utf-8"))
        rules = cls(
            version=str(data["rules_version"]),
            classes=list(data["attacker_classes"]),
            table=data["class_table"],
            risk_to_class={r["risk"]: r for r in data["risk_to_class"]},
        )
        for name in rules.classes:
            if name not in rules.table:
                raise RulesError(f"no table row for attacker class {name}")
        for level in RiskLevel:
            rule = rules.risk_to_class.get(level.value)
            if rule is None or rule["attacker_class"] not in rules.classes:
                raise RulesError(f"no rule maps {level.value} risk to an attacker class")
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
    sesip_level: str
    cc_eal: str
    rule_id: str
    rule_basis: Literal["company", "derived", "provisional"]
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
    return f"{risk.risk_id}|{risk.effective_risk.value}|{treatment}"


def applies(risk: RiskAssessment, *, include_all: bool = False) -> bool:
    """Resistance is required for threats that are reduced; accepted or avoided ones skip it."""
    if risk.status.value != "approved":
        return False
    return include_all or risk.treatment == Treatment.REDUCE


def _lookup(rules: Rules, attacker_class: str) -> tuple[dict[str, Any], str]:
    row = rules.table.get(attacker_class)
    if row is None:
        raise RulesError(f"unknown attacker class '{attacker_class}'; use one of {rules.classes}")
    return row, str(row["source"])


def propose(risk: RiskAssessment, rules: Rules) -> ComplianceRecord:
    """Suggest the mapping for one approved risk (status pending_human)."""
    rule = rules.risk_to_class[risk.effective_risk.value]
    return _build(risk, rules, rule["attacker_class"], rule["rule_id"], overridden=False)


def _build(
    risk: RiskAssessment,
    rules: Rules,
    attacker_class: str,
    rule_id: str,
    *,
    overridden: bool,
    override_reason: str | None = None,
    notes: str | None = None,
) -> ComplianceRecord:
    row, basis = _lookup(rules, attacker_class)
    suggested = rules.risk_to_class[risk.effective_risk.value]["attacker_class"]
    jil = row["jil_attack_potential"] or NEEDS_VALUE
    sesip = row["sesip_level"] or NEEDS_VALUE
    eal = row["cc_eal"] or NEEDS_VALUE
    why = (
        f"Risk {risk.effective_risk.value} "
        f"({'expert-adjusted' if risk.adjusted_risk else 'computed'})"
        f" maps by rule {rule_id} to attacker class {suggested}."
    )
    if overridden:
        why += f" The expert chose {attacker_class} instead: {override_reason}."
    why += (
        f" Class {attacker_class} requires: {row['required_resistance']}; JIL attack potential"
        f" {jil}; {sesip}; {eal}. Table row is {basis}"
        + (
            " (a value given by the company)."
            if basis == "company"
            else " (follows the company's pattern, not given by the company)."
            if basis == "derived"
            else "."
        )
    )
    missing = [n for n, v in (("JIL", jil), ("SESIP", sesip), ("EAL", eal)) if v == NEEDS_VALUE]
    if missing:
        why += f" Missing company values: {', '.join(missing)}."
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
        jil_attack_potential=jil,
        sesip_level=sesip,
        cc_eal=eal,
        rule_id=rule_id if not overridden else "EXPERT-OVERRIDE",
        rule_basis=basis if not overridden else "provisional",  # type: ignore[arg-type]
        overridden=overridden,
        override_reason=override_reason if overridden else None,
        notes=notes,
        justification=why,
        risk_fingerprint=risk_fingerprint(risk),
        rules_version=rules.version,
        run_id=risk.run_id,
    )


def confirm(risk: RiskAssessment, rules: Rules, decision: ComplianceDecision) -> ComplianceRecord:
    """Apply the expert's decision and return the confirmed record."""
    proposed = propose(risk, rules)
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
        )
    else:
        record = proposed.model_copy(update={"notes": decision.notes})
    return record.model_copy(
        update={"status": ComplianceStatus.CONFIRMED, "confirmed_by": decision.approver}
    )


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
