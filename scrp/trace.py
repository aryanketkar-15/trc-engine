"""Forward and backward links for every approved artefact, and the gaps in them.

Backward: threat to run, use case, project, asset and catalogue item. Forward: threat to risk to
resistance record, and to the security requirement Team 3 must derive for a Reduce decision.
"""

from __future__ import annotations

from typing import Any

from scrp.state_manager import StateManager


def _dicts(items: dict[str, object]) -> dict[str, dict[str, Any]]:
    return {str(k): v for k, v in items.items() if isinstance(v, dict)}


def build_trace(state: StateManager) -> dict[str, Any]:
    threats = _dicts(state.get_threat_scenarios())
    risks = _dicts(state.get_risk_assessments())
    resistance = _dicts(state.get_compliance_records())

    rows = []
    for tid, threat in sorted(threats.items()):
        risk = risks.get(tid)
        record = resistance.get(tid)
        rows.append(
            {
                "tid": tid,
                "backward": {
                    "project_id": threat.get("project_id"),
                    "use_case_id": threat.get("use_case_id"),
                    "asset_id": threat.get("asset_id"),
                    "asset_version": threat.get("asset_version"),
                    "run_id": threat.get("run_id"),
                    "kb_reference": threat.get("kb_reference"),
                    "kb_snapshot_version": threat.get("kb_snapshot_version"),
                },
                "forward": {
                    "risk_id": risk.get("risk_id") if risk else None,
                    "treatment": risk.get("treatment") if risk else None,
                    "compliance_id": record.get("compliance_id") if record else None,
                    "requirement_needed": bool(risk and risk.get("treatment") == "Reduce"),
                },
            }
        )

    return {
        "links": rows,
        "gaps": {
            "threats_without_risk": sorted(set(threats) - set(risks)),
            "risks_without_threat": sorted(set(risks) - set(threats)),
            "resistance_without_risk": sorted(set(resistance) - set(risks)),
            "reduce_without_resistance": sorted(
                t
                for t, r in risks.items()
                if r.get("treatment") == "Reduce" and t not in resistance
            ),
        },
    }
