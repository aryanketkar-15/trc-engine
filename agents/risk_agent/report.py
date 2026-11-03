"""Consolidated TARA report: per asset, ranked threats, risk, treatment, residual risk, resistance.

Reads only approved data from the SCRS. Threats that have no approved risk yet are listed as open.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from agents.risk_agent.engine import rank_per_asset
from agents.risk_agent.schemas import RiskAssessment
from agents.threat_agent.chains import propose_chains
from scrp.state_manager import StateManager

COLUMNS = [
    "asset_id",
    "rank",
    "tid",
    "stride",
    "attack",
    "kb_reference",
    "overall_impact",
    "attack_feasibility",
    "risk",
    "risk_adjusted",
    "treatment",
    "rationale",
    "residual_risk",
    "needs_requirement",
    "attacker_class",
    "jil_attack_potential",
    "assurance_component",
    "sesip_level",
    "cc_eal",
    "approved_by",
]


def _targets(resistance: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from agents.compliance_agent.engine import Rules, load_records, protection_targets

    return protection_targets(load_records(resistance), Rules.load())


def _match(item: dict[str, Any], project_id: str | None, use_case_id: str | None) -> bool:
    if project_id and item.get("project_id") not in (None, project_id):
        return False
    return not (use_case_id and item.get("use_case_id") not in (None, use_case_id))


def build_report(
    state: StateManager,
    project_id: str | None = None,
    use_case_id: str | None = None,
    assets: list[Any] | None = None,
) -> dict[str, Any]:
    threats = {
        str(t): v
        for t, v in state.get_threat_scenarios().items()
        if isinstance(v, dict) and _match(v, project_id, use_case_id)
    }
    risks = [
        RiskAssessment.model_validate(v)
        for v in state.get_risk_assessments().values()
        if isinstance(v, dict) and _match(v, project_id, use_case_id)
    ]
    resistance = {
        str(t): v for t, v in state.get_compliance_records().items() if isinstance(v, dict)
    }

    rows: list[dict[str, Any]] = []
    for r in rank_per_asset(risks):
        threat = threats.get(r.tid, {})
        res = resistance.get(r.tid, {})
        rows.append(
            {
                "asset_id": r.asset_id,
                "rank": r.rank_in_asset,
                "tid": r.tid,
                "stride": threat.get("stride_category", ""),
                "attack": threat.get("attack_vector", ""),
                "kb_reference": threat.get("kb_reference", ""),
                "overall_impact": r.overall_impact.value,
                "attack_feasibility": r.attack_feasibility.value,
                "risk": r.effective_risk.value,
                "risk_adjusted": r.adjusted_risk is not None,
                "treatment": r.treatment.value if r.treatment else "",
                "rationale": r.treatment_rationale or "",
                "residual_risk": r.residual_risk.value if r.residual_risk else "",
                "needs_requirement": bool(r.treatment and r.treatment.value == "Reduce"),
                "attacker_class": res.get("attacker_class", ""),
                "jil_attack_potential": res.get("jil_attack_potential", ""),
                "assurance_component": res.get("assurance_component", ""),
                "sesip_level": res.get("sesip_level", ""),
                "cc_eal": res.get("cc_eal", ""),
                "approved_by": r.approved_by or "",
            }
        )
    scored = {r.tid for r in risks}
    open_threats = [
        {"tid": t, "asset_id": v.get("asset_id"), "attack": v.get("attack_vector", "")}
        for t, v in threats.items()
        if t not in scored
    ]
    by_asset: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_asset.setdefault(row["asset_id"], []).append(row)
    levels = {"High": 0, "Medium": 0, "Low": 0}
    for row in rows:
        levels[row["risk"]] += 1
    reduce = [r for r in rows if r["needs_requirement"]]
    return {
        "project_id": project_id,
        "use_case_id": use_case_id,
        "summary": {
            "approved_threats": len(threats),
            "scored": len(rows),
            "not_yet_scored": len(open_threats),
            "risk_levels": levels,
            "to_reduce_requirements": len(reduce),
            "residual_items": len(rows) - len(reduce),
            "with_resistance_level": sum(1 for r in rows if r["attacker_class"]),
        },
        "by_asset": by_asset,
        "requirements_needed": [r["tid"] for r in reduce],
        "residual_risk": [
            {k: r[k] for k in ("asset_id", "tid", "treatment", "residual_risk", "rationale")}
            for r in rows
            if not r["needs_requirement"]
        ],
        "not_yet_scored": open_threats,
        "protection_targets": _targets(resistance),
        "attack_chains": propose_chains(list(threats.values()), assets or []),
        "versions": {
            "state_version": state.get_state_version(),
            "ratings_versions": sorted({r.ratings_version for r in risks}),
            "rules_versions": sorted({str(v.get("rules_version")) for v in resistance.values()}),
            "kb_snapshot_versions": sorted(
                {str(v.get("kb_snapshot_version")) for v in threats.values()}
            ),
        },
    }


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for rows in report["by_asset"].values():
        writer.writerows(rows)
    return buf.getvalue()


def to_markdown(report: dict[str, Any], title: str = "TARA report") -> str:
    s = report["summary"]
    lv = s["risk_levels"]
    out = [
        f"# {title}",
        "",
        f"Approved threats: {s['approved_threats']} | scored: {s['scored']} | not yet scored: "
        f"{s['not_yet_scored']}",
        f"Risk: High {lv['High']}, Medium {lv['Medium']}, Low {lv['Low']} | to reduce "
        f"(security requirements): {s['to_reduce_requirements']} | residual risk items: "
        f"{s['residual_items']}",
        "",
    ]
    for asset, rows in report["by_asset"].items():
        out += [
            f"## {asset}",
            "",
            "| # | Threat | STRIDE | Impact | Feasibility | Risk | Treatment | Residual "
            "| Resistance (JIL / SESIP / EAL) |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            res = (
                f"{r['attacker_class']}: {r['jil_attack_potential']} / {r['sesip_level']} / "
                f"{r['cc_eal']}"
                if r["attacker_class"]
                else "-"
            )
            star = "*" if r["risk_adjusted"] else ""
            out.append(
                f"| {r['rank']} | {r['tid']} | {r['stride']} | {r['overall_impact']} | "
                f"{r['attack_feasibility']} | {r['risk']}{star} | {r['treatment'] or '-'} | "
                f"{r['residual_risk'] or '-'} | {res} |"
            )
        out.append("")
    if any(r["risk_adjusted"] for rows in report["by_asset"].values() for r in rows):
        out += ["\\* risk adjusted by the expert (reason recorded in the audit log)", ""]
    out += ["## Security requirements needed (treatment: Reduce)", ""]
    out += [f"- {t}" for t in report["requirements_needed"]] or ["- none"]
    targets = report.get("protection_targets") or {}
    if targets.get("product"):
        out += ["", "## Required protection level", ""]
        out += [
            "| Scope | Attacker class | JIL | Assurance | SESIP | CC EAL |",
            "|---|---|---|---|---|---|",
        ]
        rows_t = [*targets["per_asset"].items(), ("Product", targets["product"])]
        for scope, t in rows_t:
            out.append(
                f"| {scope} | {t['attacker_class']} | {t['jil_attack_potential']} | "
                f"{t['assurance_component']} | {t['sesip_level']} | {t['cc_eal']} |"
            )
    out += ["", "## Residual risk (accepted, shared or avoided)", ""]
    for r in report["residual_risk"]:
        out.append(
            f"- {r['asset_id']} {r['tid']}: {r['treatment']}, residual {r['residual_risk']}. "
            f"{r['rationale']}"
        )
    if not report["residual_risk"]:
        out.append("- none")
    chains = report.get("attack_chains") or []
    if chains:
        out += ["", "## Possible attack chains (proposed, for expert review)", ""]
        for chain in chains[:10]:
            path = " -> ".join(f"{s['asset_id']} {s['stride']}" for s in chain["steps"])
            out.append(f"- {path} (evidence {chain['evidence_strength']})")
    versions = report.get("versions") or {}
    if versions:
        out += [
            "",
            "## Versions",
            "",
            f"State {versions['state_version']}; ratings "
            f"{', '.join(versions['ratings_versions']) or '-'}; rules "
            f"{', '.join(versions['rules_versions']) or '-'}; knowledge base "
            f"{', '.join(versions['kb_snapshot_versions']) or '-'}.",
        ]
    if report["not_yet_scored"]:
        out += ["", "## Approved threats without a risk assessment yet", ""]
        out += [f"- {t['asset_id']} {t['tid']}: {t['attack']}" for t in report["not_yet_scored"]]
    return "\n".join(out) + "\n"
