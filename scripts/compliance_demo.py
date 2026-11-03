"""SCRP attack-resistance mapping (Phase 2, step 6) - interactive command line.

Takes the APPROVED risks that were treated with "Reduce", proposes the required attacker resistance
(JIL attack potential, SESIP level, CC EAL) from the rule base, and asks the expert to confirm it,
change it (with a reason) or reject it. Only confirmed records are stored.

    python scripts/scrp_demo.py --auto            # Phase 1: approved threats
    python scripts/risk_demo.py --auto            # Phase 2: risk, treatment, residual risk
    python scripts/compliance_demo.py             # Phase 2: required resistance, expert confirms
    python scripts/compliance_demo.py --auto --approver "Dr. Gaikwad"     # scripted rehearsal
    python scripts/compliance_demo.py --all       # also map risks that are not "Reduce"

The rule base is in agents/compliance_agent/rules.json and can be changed without touching code.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:  # noqa: S110
        pass

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from agents.compliance_agent import engine, explainer
from agents.compliance_agent.engine import ComplianceDecision, ComplianceRecord, Rules, RulesError
from agents.risk_agent.schemas import RiskAssessment
from agents.threat_agent.project import load_inputs
from agents.threat_agent.schemas import AssetModel
from scrp.state_manager import StateManager

console = Console(highlight=False)
DEFAULT_SCRS = _ROOT / "demo_output" / "SCRS_demo.json"


def ask(prompt: str, default: str | None = None) -> str:
    return (
        Prompt.ask(prompt, default=default, show_default=False)
        if default is not None
        else Prompt.ask(prompt)
    )


def cited(rec: ComplianceRecord) -> str:
    return "; ".join(f"{c['doc']} {c['locator']}" for c in rec.citations) or "-"


def ai_block(rec: ComplianceRecord) -> str:
    if not rec.ai_rationale:
        return ""
    sources = ", ".join(f"{e['doc']} {e['locator']}" for e in rec.ai_evidence)
    return (
        f"\n[cyan]AI rationale ({rec.ai_model}, evidence match {rec.ai_confidence}):[/cyan] "
        f"{rec.ai_rationale}\n[dim]evidence: {sources}[/dim]"
    )


def load_assets(path: str | None) -> dict[str, AssetModel]:
    if not path:
        return {}
    assets: dict[str, AssetModel] = {}
    for run in load_inputs(Path(path), "MAP"):
        assets.update({a.asset_id: a for a in run.assets})
    return assets


def show_targets(records: list[ComplianceRecord], rules: Rules) -> None:
    targets = engine.protection_targets(records, rules)
    if not targets["product"]:
        return
    table = Table(title="Required protection level", box=box.SIMPLE_HEAVY)
    for col in ("Scope", "Attacker class", "JIL", "Assurance", "SESIP", "EAL"):
        table.add_column(col)
    for scope, t in [*targets["per_asset"].items(), ("Product", targets["product"])]:
        table.add_row(
            scope,
            t["attacker_class"],
            t["jil_attack_potential"],
            t["assurance_component"],
            t["sesip_level"],
            t["cc_eal"],
        )
    console.print(table)


def show_proposal(risk: RiskAssessment, rec: ComplianceRecord, n: int, total: int) -> None:
    console.print(
        Panel(
            f"[bold]{risk.tid}[/bold]  asset {risk.asset_id}  risk {risk.effective_risk.value}  "
            f"treatment {risk.treatment.value if risk.treatment else '-'}\n"
            f"Asset criticality: {rec.asset_criticality}\n"
            f"Proposed attacker class: [bold]{rec.attacker_class}[/bold] (rule {rec.rule_id})\n"
            f"  required resistance : {rec.required_resistance}\n"
            f"  JIL attack potential: {rec.jil_attack_potential}\n"
            f"  assurance component : {rec.assurance_component}\n"
            f"  SESIP level         : {rec.sesip_level}\n"
            f"  CC EAL              : {rec.cc_eal}\n"
            f"[dim]why: {rec.justification}[/dim]\n"
            f"[dim]standards: {cited(rec)}[/dim]" + ai_block(rec),
            title=f"Mapping {n}/{total}",
            border_style="cyan",
        )
    )


def result_table(records: list[ComplianceRecord]) -> None:
    table = Table(title="Required attack resistance (expert-confirmed)", box=box.SIMPLE_HEAVY)
    for col in ("Threat", "Asset", "Risk", "Attacker class", "JIL", "SESIP", "EAL", "Changed?"):
        table.add_column(col)
    for r in records:
        table.add_row(
            r.tid,
            r.asset_id,
            r.effective_risk.value,
            r.attacker_class,
            r.jil_attack_potential,
            r.sesip_level,
            r.cc_eal,
            "yes" if r.overridden else "no",
        )
    console.print(table)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--scrs", default=str(DEFAULT_SCRS), help="SCRS file to read and write")
    parser.add_argument("--approver", help="name recorded as the confirming expert")
    parser.add_argument("--all", action="store_true", help="also map risks not treated with Reduce")
    parser.add_argument("--auto", action="store_true", help="confirm the proposals (rehearsal)")
    parser.add_argument(
        "--rules", help="rule base JSON (default: agents/compliance_agent/rules.json)"
    )
    parser.add_argument("--input", help="project JSON (its assets set the asset criticality)")
    parser.add_argument("--no-ai", action="store_true", help="skip the LLM written rationale")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if not args.verbose:
        logging.disable(logging.CRITICAL)

    rules = Rules.load(Path(args.rules) if args.rules else None)
    sm = StateManager(Path(args.scrs))
    console.print("[bold cyan]SCRP Attack-resistance mapping[/bold cyan]  Phase 3\n")
    stale, _ = engine.check_compliance_staleness(
        sm.get_compliance_records(), sm.get_risk_assessments()
    )
    if stale:
        console.print(
            f"[yellow]{len(stale)} earlier mapping(s) no longer match their risk:[/yellow]"
        )
        for tid, why in stale:
            console.print(f"  {tid}: {why}")
        if args.auto or ask("Retire them so they can be mapped again? (y/n)", "y").lower() == "y":
            sm.retire_compliance_records(
                [t for t, _ in stale], "; ".join(sorted({w for _, w in stale}))
            )

    have = sm.get_compliance_records()
    risks = [RiskAssessment.model_validate(r) for r in sm.get_risk_assessments().values()]
    todo = [r for r in risks if r.tid not in have and engine.applies(r, include_all=args.all)]
    console.print(
        f"{len(risks)} approved risks, {len(have)} already mapped, {len(todo)} to map"
        f"{'' if args.all else ' (only treatment Reduce; use --all for the rest)'}.\n"
    )
    if not todo:
        return 0 if risks else 1

    approver = args.approver or (
        "Demo expert" if args.auto else ask("Your name (recorded as the confirming expert)")
    )
    sm.set_actor(f"{approver} (command line, unverified)")
    assets = load_assets(args.input)
    threats = sm.get_threat_scenarios()
    confirmed: list[ComplianceRecord] = []
    rejected = 0
    for n, risk in enumerate(todo, 1):
        level = engine.asset_criticality(assets.get(risk.asset_id), rules)
        proposal = engine.propose(risk, rules, criticality=level)
        ai = None
        if not args.no_ai:
            threat = threats.get(risk.tid)
            text = str(threat.get("attack_vector", "")) if isinstance(threat, dict) else ""
            ai = explainer.explain(proposal, text)
        proposal = explainer.attach(proposal, ai)
        show_proposal(risk, proposal, n, len(todo))
        if args.auto:
            confirmed.append(
                explainer.attach(
                    engine.confirm(
                        risk, rules, ComplianceDecision(approver=approver), criticality=level
                    ),
                    ai,
                )
            )
            continue
        while True:
            choice = ask("  (c)onfirm  (o)verride class  (r)eject  (s)kip", "c").strip().lower()
            if choice == "c":
                confirmed.append(
                    explainer.attach(
                        engine.confirm(
                            risk, rules, ComplianceDecision(approver=approver), criticality=level
                        ),
                        ai,
                    )
                )
            elif choice == "o":
                cls = ask(f"  Attacker class ({', '.join(rules.classes)})").strip()
                reason = ask("  Why a different class?").strip()
                try:
                    confirmed.append(
                        engine.confirm(
                            risk,
                            rules,
                            ComplianceDecision(
                                approver=approver,
                                attacker_class=cls,
                                override_reason=reason,
                                notes=ask("  Note (optional, e.g. side-channel)", "").strip()
                                or None,
                            ),
                            criticality=level,
                        )
                    )
                except (RulesError, ValueError) as exc:
                    console.print(f"  [red]{exc}[/red]")
                    continue
            elif choice == "r":
                reason = ""
                while len(reason) < 5:
                    reason = ask("  Why do you reject this mapping?").strip()
                sm.log_compliance_rejection(risk.tid, risk.run_id or "unknown", reason, approver)
                rejected += 1
            break

    result_table(confirmed)
    show_targets([*engine.load_records(sm.get_compliance_records()), *confirmed], rules)
    stored = sm.commit_compliance_records([r.model_dump(mode="json") for r in confirmed])
    console.print(
        f"\nStored {stored} confirmed mapping(s) in {args.scrs} (confirmed by {approver}); "
        f"{rejected} rejected and left unmapped."
    )
    report = Path(args.scrs).with_name("compliance_report.json")
    report.write_text(
        json.dumps(
            {
                "rules_version": rules.version,
                "confirmed_by": approver,
                "records": [r.model_dump(mode="json") for r in confirmed],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    console.print(f"Report: {report}")
    return 0


if __name__ == "__main__":
    code = 0
    try:
        code = main()
    except KeyboardInterrupt:
        console.print("\nInterrupted.")
        code = 130
    sys.stdout.flush()
    os._exit(code)
