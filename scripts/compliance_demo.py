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

from agents.compliance_agent import engine
from agents.compliance_agent.engine import ComplianceDecision, ComplianceRecord, Rules, RulesError
from agents.risk_agent.schemas import RiskAssessment
from scrp.state_manager import StateManager

console = Console(highlight=False)
DEFAULT_SCRS = _ROOT / "demo_output" / "SCRS_demo.json"


def ask(prompt: str, default: str | None = None) -> str:
    return (
        Prompt.ask(prompt, default=default, show_default=False)
        if default is not None
        else Prompt.ask(prompt)
    )


def show_proposal(risk: RiskAssessment, rec: ComplianceRecord, n: int, total: int) -> None:
    console.print(
        Panel(
            f"[bold]{risk.tid}[/bold]  asset {risk.asset_id}  risk {risk.effective_risk.value}  "
            f"treatment {risk.treatment.value if risk.treatment else '-'}\n"
            f"Proposed attacker class: [bold]{rec.attacker_class}[/bold] (rule {rec.rule_id})\n"
            f"  required resistance : {rec.required_resistance}\n"
            f"  JIL attack potential: {rec.jil_attack_potential}\n"
            f"  assurance component : {rec.assurance_component}\n"
            f"  SESIP level         : {rec.sesip_level}\n"
            f"  CC EAL              : {rec.cc_eal}\n"
            f"[dim]why: {rec.justification}[/dim]",
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
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if not args.verbose:
        logging.disable(logging.CRITICAL)

    rules = Rules.load(Path(args.rules) if args.rules else None)
    sm = StateManager(Path(args.scrs))
    console.print("[bold cyan]SCRP Attack-resistance mapping[/bold cyan]  Phase 2\n")
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
    confirmed: list[ComplianceRecord] = []
    rejected = 0
    for n, risk in enumerate(todo, 1):
        proposal = engine.propose(risk, rules)
        show_proposal(risk, proposal, n, len(todo))
        if args.auto:
            confirmed.append(engine.confirm(risk, rules, ComplianceDecision(approver=approver)))
            continue
        while True:
            choice = ask("  (c)onfirm  (o)verride class  (r)eject  (s)kip", "c").strip().lower()
            if choice == "c":
                confirmed.append(engine.confirm(risk, rules, ComplianceDecision(approver=approver)))
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
