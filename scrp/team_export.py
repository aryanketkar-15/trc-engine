# ruff: noqa: E501
"""Publish our approved results in the shapes Team 1's orchestrator and Team 3's agents read.

One use case at a time, five documents: ``threats``, ``risks``, ``compliance``, ``versions`` and
``audit_trail``. The field names are the ones Team 1's hand-over kit already uses for Team 2
(``id``, ``asset_ids``, ``stride``, ``references``, ``threat_id``, ``risk_level``, ``treatment``,
``mappings`` ...), so Team 3's code needs no change; our extra detail rides along in extra fields.

Threat numbers (``T1``, ``T2`` ...) follow the order in which threats were first approved, read from
the append-only audit log. A number is never reused: a retired threat keeps its number, so the IDs
Team 3 links against stay valid when threats are added or removed later.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scrp.state_manager import StateManager

STRIDE_LETTER = {
    "Spoofing": "S",
    "Tampering": "T",
    "Repudiation": "R",
    "InformationDisclosure": "I",
    "DenialOfService": "D",
    "ElevationOfPrivilege": "E",
}
_THREAT_CHANGES = {"write", "revise", "stale", "add"}
_RISK_CHANGES = {"risk_approve", "risk_supersede", "risk_stale"}
_COMPLIANCE_CHANGES = {
    "compliance_confirm",
    "compliance_override",
    "compliance_supersede",
    "compliance_stale",
}
_APPROVALS = {"approve", "risk_approve", "compliance_confirm", "compliance_override", "add"}
_REJECTIONS = {"reject", "risk_reject", "compliance_reject", "prune"}


def reference(kb_reference: str) -> dict[str, str]:
    """Our catalogue reference in Team 1's spelling: family, and the ID as the catalogue writes it."""
    ref = (kb_reference or "").strip()
    attack = re.fullmatch(r"(?:ATT&CK|ATTACK|ATTCK)[-: ]?(T\d{4}(?:\.\d{3})?)", ref, re.IGNORECASE)
    if attack:
        return {"source": "ATT&CK", "reference_id": attack.group(1).upper()}
    if re.fullmatch(r"T\d{4}(\.\d{3})?", ref):
        return {"source": "ATT&CK", "reference_id": ref}
    for family in ("CAPEC", "CWE"):
        if ref.upper().startswith(family + "-"):
            return {"source": family, "reference_id": ref.upper()}
    if ref.upper().startswith("STRIDE"):
        return {"source": "STRIDE", "reference_id": ref}
    return {"source": "OTHER", "reference_id": ref}


def _dicts(items: dict[str, object]) -> dict[str, dict[str, Any]]:
    return {str(k): v for k, v in items.items() if isinstance(v, dict)}


def _history_scenarios(state: StateManager) -> dict[str, dict[str, Any]]:
    """Every scenario that ever left the active set, by tid (retired, superseded, rejected)."""
    found: dict[str, dict[str, Any]] = {}
    history = state.get_revision_history()
    if isinstance(history, dict):
        for rounds in history.values():
            for entry in rounds:
                for scenario in entry.get("scenarios", []) if isinstance(entry, dict) else []:
                    if isinstance(scenario, dict) and scenario.get("tid"):
                        found.setdefault(str(scenario["tid"]), scenario)
    return found


def threat_numbers(state: StateManager) -> dict[tuple[str | None, str | None], dict[str, str]]:
    """``T<n>`` for every threat that was ever approved, per (project, use case)."""
    known = {**_history_scenarios(state), **_dicts(state.get_threat_scenarios())}
    numbers: dict[tuple[str | None, str | None], dict[str, str]] = {}
    for entry in state.get_audit_log():
        if entry.action != "write":
            continue
        scenario = known.get(entry.tid)
        if scenario is None:
            continue
        key = (scenario.get("project_id"), scenario.get("use_case_id"))
        group = numbers.setdefault(key, {})
        if entry.tid not in group:
            group[entry.tid] = f"T{len(group) + 1}"
    return numbers


def _asset_version(threats: list[dict[str, Any]]) -> int | None:
    versions = []
    for threat in threats:
        try:
            versions.append(int(float(str(threat.get("asset_version")))))
        except (TypeError, ValueError):
            continue
    return max(versions) if versions else None


def _event(entry_action: str) -> tuple[str, str]:
    kind = (
        "risk"
        if entry_action.startswith("risk_")
        else "compliance"
        if entry_action.startswith("compliance_")
        else "threat"
    )
    if entry_action in _APPROVALS:
        return "human_approval", kind
    if entry_action in _REJECTIONS:
        return "human_rejection", kind
    return "artefact_versioned", kind


def build_export(
    state: StateManager,
    use_case_id: str,
    *,
    project_id: str | None = None,
    session_id: str | None = None,
    upstream_versions: dict[str, int] | None = None,
) -> dict[str, Any]:
    """The five documents for one use case, plus ``problems`` (things a reader should know)."""
    threats = {
        tid: t
        for tid, t in _dicts(state.get_threat_scenarios()).items()
        if t.get("use_case_id") == use_case_id
        and (project_id is None or t.get("project_id") in (None, project_id))
    }
    project = project_id or next((t.get("project_id") for t in threats.values()), None)
    numbers = threat_numbers(state).get((project, use_case_id), {})
    log = state.get_audit_log()
    approvals = {e.tid: e for e in log if e.action in ("approve", "add")}
    problems: list[str] = []

    threat_rows = []
    for tid in sorted(threats, key=lambda t: int(numbers.get(t, "T999999")[1:])):
        threat = threats[tid]
        number = numbers.get(tid)
        if number is None:
            problems.append(f"{tid} has no approval record in the audit log and was left out")
            continue
        evidence = threat.get("evidence_chain") or {}
        approved = approvals.get(tid)
        threat_rows.append(
            {
                "id": number,
                "scenario": threat.get("attack_vector", ""),
                "asset_ids": [threat.get("asset_id")],
                "stride": [STRIDE_LETTER.get(str(threat.get("stride_category")), "?")],
                "attack_vector": evidence.get("exposure", ""),
                "references": [reference(str(threat.get("kb_reference", "")))],
                # our own detail, beyond the agreed fields
                "team2_tid": tid,
                "confidence": threat.get("confidence_score"),
                "validation_status": threat.get("validation_status"),
                "applicability_reason": evidence.get("applicability_reason"),
                "citation": evidence.get("citation"),
                "kb_snapshot_version": threat.get("kb_snapshot_version"),
                "approved_by": approved.actor if approved else None,
                "approved_at": approved.timestamp.isoformat() if approved else None,
            }
        )
    exported = {row["team2_tid"]: row["id"] for row in threat_rows}

    risks = _dicts(state.get_risk_assessments())
    risk_rows = []
    for tid, number in exported.items():
        risk = risks.get(tid)
        if risk is None:
            problems.append(f"{number} ({tid}) has no approved risk assessment yet")
            continue
        risk_rows.append(
            {
                "threat_id": number,
                "impact": risk.get("impact"),
                "overall_impact": risk.get("overall_impact"),
                "attack_feasibility": risk.get("attack_feasibility"),
                "risk_level": risk.get("effective_risk") or risk.get("risk"),
                "treatment": risk.get("treatment"),
                "treatment_source": (
                    f"Decided by {risk.get('approved_by')}: {risk.get('treatment_rationale')}"
                ),
                "risk_id": risk.get("risk_id"),
                "computed_risk_level": risk.get("risk"),
                "adjusted": bool(risk.get("adjusted_risk")),
                "adjustment_reason": risk.get("adjustment_reason"),
                "residual_risk": risk.get("residual_risk"),
                "rank_in_asset": risk.get("rank_in_asset"),
                "justification": risk.get("justification"),
                "feasibility_points": risk.get("feasibility_points"),
                "ratings_version": risk.get("ratings_version"),
                "approved_by": risk.get("approved_by"),
            }
        )
    for tid, risk in risks.items():
        if risk.get("use_case_id") == use_case_id and tid not in threats:
            problems.append(
                f"risk {risk.get('risk_id')} belongs to a threat that is no longer approved; left out"
            )

    records = _dicts(state.get_compliance_records())
    mapping_rows = []
    for tid, number in exported.items():
        record = records.get(tid)
        if record is None:
            continue
        mapping_rows.append(
            {
                "threat_id": number,
                "required_resistance": record.get("required_resistance"),
                "jil_attack_potential": record.get("jil_attack_potential"),
                "sesip_level": record.get("sesip_level"),
                "cc_eal": record.get("cc_eal"),
                "assurance_component": record.get("assurance_component"),
                "attacker_class": record.get("attacker_class"),
                "rule_id": record.get("rule_id"),
                "overridden": bool(record.get("overridden")),
                "override_reason": record.get("override_reason"),
                "asset_criticality": record.get("asset_criticality"),
                "justification": record.get("justification"),
                "citations": record.get("citations", []),
                "rules_version": record.get("rules_version"),
                "confirmed_by": record.get("confirmed_by"),
            }
        )
    reduce = {r["threat_id"] for r in risk_rows if r["treatment"] == "Reduce"}
    unmapped = sorted(reduce - {m["threat_id"] for m in mapping_rows}, key=lambda t: int(t[1:]))
    if unmapped:
        problems.append(f"no confirmed resistance level yet for: {', '.join(unmapped)}")

    every_tid = set(numbers)  # includes retired threats, so their history is exported too
    trail = []
    counts = {"threat": 0, "risk": 0, "compliance": 0}
    for seq, entry in enumerate(log, 1):
        if entry.tid not in every_tid:
            continue
        event, kind = _event(entry.action)
        if entry.action in _THREAT_CHANGES | _RISK_CHANGES | _COMPLIANCE_CHANGES:
            counts[kind] += 1
        trail.append(
            {
                "seq": seq,
                "event_type": event,
                "actor": entry.actor,
                "artefact_type": kind,
                "detail": {
                    "step": kind,
                    "action": entry.action,
                    "threat_id": numbers.get(entry.tid),
                    "team2_tid": entry.tid,
                    "reason": entry.reason,
                    "version": counts[kind],
                },
                "created_at": entry.timestamp.isoformat(),
                "entry_hash": entry.entry_hash,
            }
        )

    integrity = state.verify_integrity()
    chain = (
        f"chain intact across {integrity['chain']['entries']} entries"
        if integrity["ok"]
        else "CHAIN OR CONTENT CHECK FAILED: see /scrs/audit/verify"
    )
    versions = {
        **(upstream_versions or {}),
        "threat": max(counts["threat"], 1) if threat_rows else 0,
        "risk": max(counts["risk"], 1) if risk_rows else 0,
        "compliance": max(counts["compliance"], 1) if mapping_rows else 0,
    }
    asset_version = _asset_version(list(threats.values()))
    if asset_version is not None:
        versions.setdefault("asset", asset_version)

    head = {
        "session_id": session_id,
        "project_id": project,
        "usecase_id": use_case_id,
        "_source": "Team 2 (TRC engine)",
    }
    return {
        "threats": {**head, "asset_version": asset_version, "threats": threat_rows},
        "risks": {**head, "threat_version": versions["threat"], "risks": risk_rows},
        "compliance": {**head, "risk_version": versions["risk"], "mappings": mapping_rows},
        "versions": versions,
        "audit_trail": {"audit_chain": chain, "entries": trail},
        "problems": problems,
        "retired_threat_ids": sorted(
            (n for t, n in numbers.items() if t not in threats), key=lambda t: int(t[1:])
        ),
    }


def use_cases_in(state: StateManager) -> list[tuple[str | None, str]]:
    """Every (project, use case) that has approved threats."""
    seen = {
        (t.get("project_id"), str(t.get("use_case_id")))
        for t in _dicts(state.get_threat_scenarios()).values()
        if t.get("use_case_id")
    }
    return sorted(seen, key=lambda k: (k[0] or "", k[1]))


def write_export(bundle: dict[str, Any], folder: Path) -> list[Path]:
    """Write the five documents as the files Team 3's kit expects."""
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for name in ("threats", "risks", "compliance", "versions", "audit_trail"):
        path = folder / f"{name}.json"
        path.write_text(json.dumps(bundle[name], indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(path)
    notes = folder / "export_notes.json"
    notes.write_text(
        json.dumps(
            {"problems": bundle["problems"], "retired_threat_ids": bundle["retired_threat_ids"]},
            indent=2,
        ),
        encoding="utf-8",
    )
    return [*written, notes]
