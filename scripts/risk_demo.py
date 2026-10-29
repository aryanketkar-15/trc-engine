# ruff: noqa: E501
"""SCRP Risk Agent (Phase 2) - interactive command line.

Reads the APPROVED threats from the shared state (SCRS), proposes impact and attack-feasibility
ratings, lets you accept or edit them, computes the risk by fixed rules, ranks the threats per
asset and records your treatment decision (Reduce / Share / Retain / Avoid) and residual risk.

    python scripts/scrp_demo.py --auto                 # Phase 1 first: creates demo_output/SCRS_demo.json
    python scripts/risk_demo.py                        # Phase 2 on those approved threats
    python scripts/risk_demo.py --use-case UC-02
    python scripts/risk_demo.py --input projects/smart_door_lock_multi_use_case.json
    python scripts/risk_demo.py --auto --approver "Dr. Gaikwad"     # scripted run for rehearsal

The rating tables are PLACEHOLDERS until the company confirms theirs; every result says so.
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

from agents.risk_agent import engine, suggester
from agents.risk_agent.engine import Ratings, RatingsError
from agents.risk_agent.schemas import (
    FeasibilityFactors,
    ImpactLevel,
    ImpactRatings,
    RiskAssessment,
    RiskInput,
    RiskLevel,
    Treatment,
    TreatmentDecision,
)
from agents.threat_agent.project import load_inputs
from agents.threat_agent.schemas import AssetModel, ThreatScenario
from scrp.state_manager import StateManager

console = Console(highlight=False)
DEFAULT_SCRS = _ROOT / "demo_output" / "SCRS_demo.json"
MAX_REJECTIONS = 3
AXES = ("safety", "financial", "operational", "privacy")
LEVEL_KEYS = {
    "n": ImpactLevel.NEGLIGIBLE,
    "m": ImpactLevel.MODERATE,
    "j": ImpactLevel.MAJOR,
    "s": ImpactLevel.SEVERE,
}
RISK_STYLE = {"High": "bold red", "Medium": "yellow", "Low": "green"}
TREATMENT_KEYS = {
    "r": Treatment.REDUCE,
    "s": Treatment.SHARE,
    "t": Treatment.RETAIN,
    "a": Treatment.AVOID,
}


def short(text: str, n: int = 70) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def ask(prompt: str, default: str | None = None) -> str:
    return (
        Prompt.ask(prompt, default=default, show_default=False)
        if default is not None
        else Prompt.ask(prompt)
    )


def impact_text(impact: ImpactRatings) -> str:
    parts = []
    for label, value in zip(
        "SFOP", (impact.safety, impact.financial, impact.operational, impact.privacy), strict=True
    ):
        parts.append(f"{label}:{value.value[:3] if value else '-'}")
    return "  ".join(parts)


def load_assets(path: str | None, use_case: str | None) -> dict[str, AssetModel]:
    if not path:
        return {}
    assets: dict[str, AssetModel] = {}
    for run in load_inputs(Path(path), "RISK"):
        if use_case and run.use_case_id != use_case:
            continue
        assets.update({a.asset_id: a for a in run.assets})
    return assets


def approved_threats(sm: StateManager, use_case: str | None) -> list[ThreatScenario]:
    out = [ThreatScenario.model_validate(r) for r in sm.get_threat_scenarios().values()]
    if use_case:
        out = [t for t in out if t.use_case_id == use_case]
    return sorted(out, key=lambda t: (t.asset_id, t.tid))


def show_threat(t: ThreatScenario, n: int, total: int) -> None:
    body = (
        f"[bold]{t.tid}[/bold]  asset {t.asset_id}  STRIDE {t.stride_category.value}  "
        f"ref {t.kb_reference}\n{short(t.attack_vector, 180)}"
    )
    console.print(Panel(body, title=f"Threat {n}/{total}", border_style="cyan"))


def show_input(ri: RiskInput) -> None:
    console.print(f"  impact   {impact_text(ri.impact)}")
    if ri.feasibility_factors:
        f = ri.feasibility_factors
        console.print(
            f"  factors  time={f.elapsed_time}  expertise={f.expertise}  knowledge={f.knowledge}  "
            f"window={f.window}  equipment={f.equipment}"
        )
    else:
        console.print(
            f"  feasibility (direct) {ri.attack_feasibility.value if ri.attack_feasibility else '-'}"
        )
    if ri.suggestion_basis:
        console.print(f"  [dim]basis: {short(ri.suggestion_basis, 150)}[/dim]")


def edit_input(tid: str, ratings: Ratings, current: RiskInput) -> RiskInput:
    console.print("  Impact per axis: n=Negligible m=Moderate j=Major s=Severe, - = not applicable")
    levels: dict[str, ImpactLevel | None] = {}
    for axis in AXES:
        was = getattr(current.impact, axis)
        default = {v: k for k, v in LEVEL_KEYS.items()}.get(was, "-") if was else "-"
        while True:
            key = ask(f"    {axis}", default).strip().lower()
            if key == "-" or key in LEVEL_KEYS:
                levels[axis] = LEVEL_KEYS.get(key)
                break
            console.print("    [red]use n, m, j, s or -[/red]")
    factors: dict[str, str] = {}
    base = current.feasibility_factors
    for name, table in ratings.points.items():
        options = list(table)
        was = getattr(base, name) if base else options[0]
        menu = "  ".join(f"{i}={o}({table[o]})" for i, o in enumerate(options, 1))
        console.print(f"    {name}: {menu}")
        while True:
            key = ask(f"    {name} number", str(options.index(was) + 1)).strip()
            if key.isdigit() and 1 <= int(key) <= len(options):
                factors[name] = options[int(key) - 1]
                break
            console.print(f"    [red]enter a number from 1 to {len(options)}[/red]")
    return RiskInput(
        tid=tid,
        impact=ImpactRatings(**levels),
        feasibility_factors=FeasibilityFactors(**factors),
        ai_suggested=False,
        suggestion_basis=f"edited by the expert (started from: {short(current.suggestion_basis or 'none', 80)})",
    )


def show_score(a: RiskAssessment) -> None:
    pts = f" ({a.feasibility_points} points)" if a.feasibility_points is not None else ""
    note = "" if a.risk_basis == "company" else f"  [dim]matrix cell is {a.risk_basis}[/dim]"
    style = RISK_STYLE[a.risk.value]
    console.print(
        f"  => overall impact [bold]{a.overall_impact.value}[/bold], feasibility "
        f"[bold]{a.attack_feasibility.value}[/bold]{pts}, risk [{style}]{a.risk.value}[/{style}]{note}"
    )
    console.print(f"  [dim]why: {short(a.justification, 600)}[/dim]")


def treatment_for(a: RiskAssessment, approver: str, auto: bool) -> TreatmentDecision:
    adjusted: RiskLevel | None = None
    adj_reason: str | None = None
    if not auto and ask("  Change the computed risk? (y/n)", "n").strip().lower() == "y":
        adjusted = RiskLevel(ask("  New risk (Low/Medium/High)", a.risk.value).strip().title())
        while len((adj_reason or "").strip()) < 5:
            adj_reason = ask("  Reason for the change").strip()
    current = adjusted or a.risk
    if auto:
        if a.risk == RiskLevel.LOW:
            return TreatmentDecision(
                treatment=Treatment.RETAIN,
                rationale="Low risk accepted by the owner.",
                residual_risk=a.risk,
                approver=approver,
            )
        return TreatmentDecision(
            treatment=Treatment.REDUCE,
            rationale="Add a control that removes the attack path.",
            residual_risk=RiskLevel.LOW if a.risk == RiskLevel.MEDIUM else RiskLevel.MEDIUM,
            residual_reason="The control reduces, but does not remove, the exposure.",
            approver=approver,
        )
    while True:
        key = ask("  Treatment: (r)educe  (s)hare  re(t)ain  (a)void", "r").strip().lower()
        if key in TREATMENT_KEYS:
            break
    treatment = TREATMENT_KEYS[key]
    rationale = ""
    while len(rationale) < 5:
        rationale = ask("  Rationale (why this decision)").strip()
    if treatment == Treatment.RETAIN:
        residual = current
        reason = None
        console.print(f"  Retain keeps the risk as it is: residual risk = {residual.value}")
    else:
        residual = RiskLevel(
            ask("  Residual risk after treatment (Low/Medium/High)", "Low").strip().title()
        )
        reason = ask("  Why does this risk remain (or why is it gone)?").strip() or None
    return TreatmentDecision(
        treatment=treatment,
        rationale=rationale,
        residual_risk=residual,
        residual_reason=reason or ("treated" if treatment == Treatment.AVOID else None),
        approver=approver,
        adjusted_risk=adjusted,
        adjustment_reason=adj_reason,
    )


def ranked_table(items: list[RiskAssessment], title: str) -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY)
    for col in ("Asset", "#", "Threat", "Impact", "Feasibility", "Risk", "Treatment", "Residual"):
        table.add_column(col)
    for a in items:
        shown = a.effective_risk
        style = RISK_STYLE[shown.value]
        table.add_row(
            a.asset_id,
            str(a.rank_in_asset),
            a.tid,
            a.overall_impact.value,
            a.attack_feasibility.value,
            f"[{style}]{shown.value}[/{style}]" + ("*" if a.adjusted_risk else ""),
            a.treatment.value if a.treatment else "-",
            a.residual_risk.value if a.residual_risk else "-",
        )
    console.print(table)
    if any(a.adjusted_risk for a in items):
        console.print("  * risk adjusted by the expert (reason recorded)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--scrs", default=str(DEFAULT_SCRS), help="SCRS file to read and write")
    parser.add_argument("--input", help="project JSON (gives the suggester the asset facts)")
    parser.add_argument("--use-case", help="only the threats of this use case, e.g. UC-02")
    parser.add_argument("--approver", help="name recorded as the approver")
    parser.add_argument("--auto", action="store_true", help="accept suggestions (rehearsal)")
    parser.add_argument("--ratings", help="rating tables JSON (default: placeholder tables)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if not args.verbose:
        logging.disable(logging.CRITICAL)

    ratings = Ratings.load(Path(args.ratings) if args.ratings else None)
    sm = StateManager(Path(args.scrs))
    console.print("[bold cyan]SCRP Risk Agent[/bold cyan]  Phase 2\n")
    if ratings.version.startswith("placeholder"):
        console.print(
            "[yellow]Rating tables are PLACEHOLDERS (4 matrix cells from the company document, "
            "2 derived, 6 provisional). Results are labelled accordingly.[/yellow]\n"
        )

    threats = approved_threats(sm, args.use_case)
    if not threats:
        console.print(f"No approved threats in {args.scrs}. Run scripts/scrp_demo.py first.")
        return 1
    done = sm.get_risk_assessments()
    todo = [t for t in threats if t.tid not in done]
    console.print(
        f"{len(threats)} approved threats, {len(threats) - len(todo)} already have a risk, {len(todo)} to assess.\n"
    )
    if not todo:
        return 0

    approver = args.approver or (
        "Demo expert" if args.auto else ask("Your name (recorded as approver)")
    )
    assets = load_assets(args.input, args.use_case)
    valid = {k: list(v) for k, v in ratings.points.items()}

    scored: list[RiskAssessment] = []
    skipped = 0
    for n, threat in enumerate(todo, 1):
        show_threat(threat, n, len(todo))
        ri = suggester.suggest(threat, assets.get(threat.asset_id), valid)
        show_input(ri)
        while True:
            try:
                assessment = engine.score(threat, ri, ratings)
            except RatingsError as exc:
                console.print(f"[red]{exc}[/red]")
                ri = edit_input(threat.tid, ratings, ri)
                continue
            show_score(assessment)
            if args.auto:
                break
            choice = (
                ask("  (a)ccept  (e)dit ratings  (r)eject suggestion  (s)kip", "a").strip().lower()
            )
            if choice == "e":
                ri = edit_input(threat.tid, ratings, ri)
                continue
            if choice == "r":
                reason = ""
                while len(reason) < 5:
                    reason = ask("  Why do you reject this suggestion?").strip()
                used = sm.log_risk_rejection(threat.tid, threat.run_id, reason, approver)
                if used >= MAX_REJECTIONS:
                    console.print(
                        f"  [yellow]Rejected {used} times: the agent stops suggesting. "
                        "Please enter the ratings yourself.[/yellow]"
                    )
                    ri = edit_input(threat.tid, ratings, ri)
                    continue
                new = suggester.suggest(
                    threat, assets.get(threat.asset_id), valid, feedback=reason, previous=ri
                )
                console.print(
                    f"  [cyan]New suggestion ({used}/{MAX_REJECTIONS} rejections used):[/cyan]"
                )
                show_input(new)
                if (new.suggestion_basis or "").startswith("could not produce"):
                    ri = edit_input(threat.tid, ratings, new)
                else:
                    ri = new
                continue
            if choice == "s":
                assessment = None  # type: ignore[assignment]
            break
        if assessment is None:
            skipped += 1
            continue
        scored.append(assessment)

    ranked = engine.rank_per_asset(scored)
    ranked_table(ranked, "Risk per asset (ranked, before treatment)")

    final: list[RiskAssessment] = []
    for a in ranked:
        console.print(f"\n[bold]{a.tid}[/bold] ({a.asset_id}, risk {a.effective_risk.value})")
        while True:
            try:
                final.append(
                    engine.apply_treatment(
                        a,
                        treatment_for(a, approver, args.auto),
                        rejections=sm.risk_rejection_count(a.tid),
                    )
                )
                break
            except (RatingsError, ValueError) as exc:
                console.print(f"  [red]{exc}[/red]")
                if args.auto:
                    raise
    ranked_table(final, "Result: risk, treatment and residual risk")

    stored = sm.commit_risk_assessments([a.model_dump(mode="json") for a in final])
    reduce = [a.tid for a in final if engine.requires_requirement(a)]
    residual = [a for a in final if a.treatment and a.treatment != Treatment.REDUCE]
    console.print(
        f"\nStored {stored} risk assessment(s) in {args.scrs} (approver: {approver}); "
        f"{skipped} skipped.\n"
        f"[bold]For Team 3 (security requirements):[/bold] {len(reduce)} threat(s) to Reduce: {', '.join(reduce) or '-'}\n"
        f"[bold]Residual risk accepted or moved:[/bold] {len(residual)} "
        f"({', '.join(f'{a.tid}={a.residual_risk.value}' for a in residual if a.residual_risk) or '-'})"
    )
    report = Path(args.scrs).with_name("risk_report.json")
    report.write_text(
        json.dumps(
            {
                "ratings_version": ratings.version,
                "approver": approver,
                "assessments": [a.model_dump(mode="json") for a in final],
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
