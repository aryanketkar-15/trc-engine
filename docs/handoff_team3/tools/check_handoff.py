"""Validate the Team 2 -> Team 3 handoff samples and show how to consume them.

Run from anywhere:   python tools/check_handoff.py
Needs Python 3.11+ and `pip install pydantic` (v2). Reads only files inside this package.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG / "schemas"))

from compliance_schemas import ComplianceRecord  # noqa: E402
from project_schema import ProjectInput, expand_project  # noqa: E402
from risk_schemas import RiskAssessment  # noqa: E402
from scrs_schemas import AuditLogEntry, SCRSState  # noqa: E402
from staleness import check_staleness  # noqa: E402
from threat_schemas import ThreatAgentInput, ThreatScenario, ThreatStatus  # noqa: E402


def load(name: str):
    return json.loads((PKG / "samples" / name).read_text(encoding="utf-8"))


def main() -> int:
    ok = True

    # 1. Inputs our agent consumes today
    for f in ("input_smart_door_lock.json", "input_infusion_pump.json"):
        inp = ThreatAgentInput.model_validate(load(f))
        print(f"[ok] {f}: {len(inp.assets)} assets ->", ", ".join(a.asset_id for a in inp.assets))

    # 2. Output scenarios
    scenarios = [ThreatScenario.model_validate(s) for s in load("output_threat_scenarios_sample.json")]
    print(f"[ok] output_threat_scenarios_sample.json: {len(scenarios)} scenarios validated")

    # 3. Shared state (SCRS)
    state = SCRSState.model_validate(load("output_scrs_state_sample.json"))
    print(
        f"[ok] SCRS state: {len(state.threat_scenarios)} approved scenarios, "
        f"{len(state.audit_log)} audit entries, {sum(len(v) for v in state.revision_history.values())} history rounds"
    )
    for entry in state.audit_log:
        AuditLogEntry.model_validate(entry.model_dump())
    print("     audit actions:", dict(Counter(e.action for e in state.audit_log)))

    # 4. The rule every consumer must follow: approved only
    approved = [s for s in scenarios if s.status == ThreatStatus.APPROVED]
    print(f"[rule] approved only: {len(approved)} of {len(scenarios)} usable")
    if len(approved) != len(scenarios):
        ok = False

    # 5. Quality flags to carry into reports
    flags = Counter(s.validation_status for s in approved)
    print("[flags] validation_status:", dict(flags))

    # 6. Trace matrix: Use case -> Asset -> Threat
    print("\nTrace matrix (Use case -> Asset -> Threat)")
    print(f"{'use_case_id':<13}{'asset':<7}{'ver':<5}{'threat id':<26}{'STRIDE':<23}{'KB reference':<18}{'conf':<6}check")
    for s in sorted(approved, key=lambda x: (x.asset_id, x.tid)):
        print(
            f"{(s.use_case_id or '-'):<13}{s.asset_id:<7}{(s.asset_version or '-'):<5}{s.tid:<26}"
            f"{s.stride_category.value:<23}{s.kb_reference:<18}{s.confidence_score:<6.2f}{s.validation_status}"
        )

    # 7. Consistency-style check: which assets of the input have no approved threat?
    inp = ThreatAgentInput.model_validate(load("input_smart_door_lock.json"))
    covered = {s.asset_id for s in approved}
    missing = [a.asset_id for a in inp.assets if a.asset_id not in covered]
    print("\nAssets without an approved threat:", missing or "none")

    # 8. Team 1 example: show the keys we rely on
    t1 = load("team1_asset_table_example.json")
    print(f"\nTeam 1 AssetTable example (illustrative): {len(t1['assets'])} assets; keys per asset:",
          ", ".join(sorted(t1["assets"][0])))

    # 9. A product with several use cases -> one run per use case
    proj = ProjectInput.model_validate(load("input_product_with_use_cases.json"))
    runs = expand_project(proj, "DEMO")
    print(f"\nProduct {proj.project_id}: {len(runs)} use cases, assets listed once ({len(proj.assets)})")
    for r in runs:
        print(f"  {r.use_case_id}  {len(r.assets)} assets  run_id={r.run_id}")

    # 10. "Go back one step": edit an asset upstream and see which approved threats are now stale
    edited = [
        a.model_copy(update={"device_config": {**a.device_config, "signature_check": "enforced"}})
        if a.asset_id == "AS-3"
        else a
        for a in inp.assets
    ]
    report = check_staleness(inp.model_copy(update={"assets": edited}), approved)
    print("\nStaleness demo (AS-3 edited upstream):")
    print("  stale threats:", [(s.tid, s.reason) for s in report.stale] or "none")
    print("  assets to re-analyse:", report.affected_assets)

    # 11. Risk and attack-resistance records (Risk Agent and Compliance mapping)
    risks = [RiskAssessment.model_validate(r) for r in load("output_risk_assessments_sample.json")]
    comps = [ComplianceRecord.model_validate(c) for c in load("output_compliance_records_sample.json")]
    print(f"\n[ok] {len(risks)} risk assessments, {len(comps)} resistance records validated")
    print("     rule for Requirements: Reduce -> requirement; Retain / Share -> residual risk")
    by_tid = {c.tid: c for c in comps}
    print(f"{'threat id':<26}{'asset':<7}{'risk':<8}{'treat':<8}{'residual':<10}{'class':<16}{'SESIP':<9}EAL")
    for r in sorted(risks, key=lambda x: (x.asset_id, x.rank_in_asset or 0)):
        c = by_tid.get(r.tid)
        print(
            f"{r.tid:<26}{r.asset_id:<7}{r.effective_risk.value:<8}"
            f"{(r.treatment.value if r.treatment else '-'):<8}"
            f"{(r.residual_risk.value if r.residual_risk else '-'):<10}"
            f"{(c.attacker_class if c else '-'):<16}{(c.sesip_level if c else '-'):<9}{(c.cc_eal if c else '-')}"
        )
        if r.approved_by is None or (c and c.confirmed_by is None):
            ok = False
    needs_req = [r.tid for r in risks if r.treatment and r.treatment.value == "Reduce"]
    print(f"  threats that need a security requirement: {len(needs_req)}")

    print("\nRESULT:", "all checks passed" if ok else "problems found")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
