"""A risk assessment is only valid for the threat it was scored for."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskStaleness:
    stale: list[tuple[str, str]] = field(default_factory=list)  # (tid, reason)
    fresh: list[str] = field(default_factory=list)
    unscored: list[str] = field(default_factory=list)  # approved threats with no risk yet

    @property
    def has_changes(self) -> bool:
        return bool(self.stale)


def _fp(threat: dict[str, Any]) -> str:
    return f"{threat.get('asset_fingerprint') or ''}|{threat.get('context_fingerprint') or ''}"


def check_risk_staleness(
    risks: dict[str, Any],
    threats: dict[str, Any],
    project_id: str | None = None,
    use_case_id: str | None = None,
) -> RiskStaleness:
    """Compare stored risks with the currently approved threats (same project and use case)."""
    report = RiskStaleness()
    for tid, risk in risks.items():
        if not isinstance(risk, dict):
            continue
        if project_id and risk.get("project_id") not in (None, project_id):
            continue
        if use_case_id and risk.get("use_case_id") not in (None, use_case_id):
            continue
        threat = threats.get(tid)
        if not isinstance(threat, dict):
            report.stale.append((tid, "threat was retired or removed"))
        elif risk.get("threat_fingerprint") and risk["threat_fingerprint"] != _fp(threat):
            report.stale.append((tid, "threat was re-generated from changed asset or context"))
        else:
            report.fresh.append(tid)
    for tid, threat in threats.items():
        if not isinstance(threat, dict) or tid in risks:
            continue
        if project_id and threat.get("project_id") not in (None, project_id):
            continue
        if use_case_id and threat.get("use_case_id") not in (None, use_case_id):
            continue
        report.unscored.append(tid)
    return report
