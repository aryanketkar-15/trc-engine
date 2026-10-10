# ruff: noqa: ANN401
"""SCRP Threat Agent - interactive command line.

Pick a project, generate threat scenarios, then approve or reject each one.
A rejected scenario asks for your reason and is regenerated; this repeats until
you approve it or the rejection limit is reached. Approved scenarios are written
to the shared state (SCRS) together with an audit trail.

    python scripts/scrp_demo.py                       # choose a project from the menu
    python scripts/scrp_demo.py --project 1           # skip the menu
    python scripts/scrp_demo.py --input my_project.json
    python scripts/scrp_demo.py --mode live           # always call the language model
    python scripts/scrp_demo.py --auto                # scripted run for rehearsal

Output goes to ./demo_output (the real SCRS_state.json is never touched).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

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

console = Console(highlight=False)

FIXTURE_DIR = _ROOT / "tests" / "threat_agent" / "e2e" / "fixtures"
PROJECT_DIR = _ROOT / "projects"
REPLAY_FILE = _ROOT / "docs" / "research" / "final_fullkb_scenarios_raw_live.json"
REPLAY_PROJECTS = {"smart_door_lock"}
OUT_DIR = _ROOT / "demo_output"
MAX_REJECTIONS = 3
STRIDE_SHORT = {
    "Spoofing": "S",
    "Tampering": "T",
    "Repudiation": "R",
    "InformationDisclosure": "I",
    "DenialOfService": "D",
    "ElevationOfPrivilege": "E",
}


# ------------------------------------------------------------------ small helpers


def ok(msg: str) -> None:
    console.print(f"[green]ok[/green]  {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]!![/yellow]  {msg}")


def err(msg: str) -> None:
    console.print(f"[red]error[/red]  {msg}")


def short(text: str, n: int = 70) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def stride_name(value: Any) -> str:
    return str(getattr(value, "value", value))


def ask(prompt: str, default: str | None = None) -> str:
    return (
        Prompt.ask(prompt, default=default, show_default=False)
        if default is not None
        else Prompt.ask(prompt)
    )


# --------------------------------------------------------------------- projects


def discover_projects() -> list[tuple[str, Path]]:
    """Every project JSON we can offer: bundled fixtures plus anything in ./projects."""
    found: list[tuple[str, Path]] = []
    if FIXTURE_DIR.is_dir():
        for folder in sorted(FIXTURE_DIR.iterdir()):
            f = folder / "input.json"
            if f.is_file():
                found.append((folder.name.replace("_", " ").title(), f))
    if PROJECT_DIR.is_dir():
        for f in sorted(PROJECT_DIR.glob("*.json")):
            found.append((f.stem.replace("_", " ").title(), f))
    found.sort(key=lambda item: (item[1].parent.name != "smart_door_lock", item[0]))
    return found


def load_project(path: Path) -> Any:
    from agents.threat_agent.schemas import ThreatAgentInput

    data = json.loads(path.read_text(encoding="utf-8"))
    agent_input = ThreatAgentInput.model_validate(data)
    return agent_input.model_copy(update={"run_id": f"RUN-{uuid.uuid4().hex[:6].upper()}"})


def choose_project(args: argparse.Namespace) -> tuple[str, Path]:
    if args.input:
        p = Path(args.input).expanduser().resolve()
        if not p.is_file():
            sys.exit(f"Input file not found: {p}")
        return p.stem.replace("_", " ").title(), p
    projects = discover_projects()
    if not projects:
        sys.exit("No project JSON files found.")
    table = Table(box=box.SIMPLE_HEAD, header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Project")
    table.add_column("Assets", justify="right")
    table.add_column("File")
    rows = []
    for i, (name, path) in enumerate(projects, 1):
        try:
            n_assets = len(json.loads(path.read_text(encoding="utf-8")).get("assets", []))
        except (OSError, ValueError):
            n_assets = 0
        rel = path.relative_to(_ROOT) if path.is_relative_to(_ROOT) else path
        table.add_row(str(i), name, str(n_assets), str(rel))
        rows.append((name, path))
    console.print("Available projects:")
    console.print(table)
    choice = args.project or ask(f"Select a project (1-{len(rows)}, default 1)", "1")
    if not choice.isdigit() or not 1 <= int(choice) <= len(rows):
        sys.exit(f"Invalid selection '{choice}'.")
    return rows[int(choice) - 1]


# ----------------------------------------------------------------------- replay


class Replay:
    """Stands in for the language model by replaying recorded real model output."""

    def __init__(self) -> None:
        from agents.threat_agent.schemas import ThreatScenario

        self.saved = [
            ThreatScenario.model_validate(x) for x in json.loads(REPLAY_FILE.read_text("utf-8"))
        ]
        self.used: set[str] = set()

    def generate(
        self,
        paths: list[Any],
        context: Any,
        *,
        validation_failure_context: Any = None,
    ) -> list[Any]:
        out = []
        for seq, path in enumerate(paths):
            ref = path.steps[0].pattern_id
            asset = path.target_asset_ids[0] if path.target_asset_ids else ""
            for s in self.saved:
                if s.tid not in self.used and s.asset_id == asset and s.kb_reference == ref:
                    self.used.add(s.tid)
                    out.append(
                        s.model_copy(
                            update={
                                "tid": f"THR-{path.path_id}-{seq + 1:03d}",
                                "run_id": context.run_id,
                            }
                        )
                    )
                    break
        return out

    def has_unused(self, asset_id: str, ref: str) -> bool:
        return any(
            s.tid not in self.used and s.asset_id == asset_id and s.kb_reference == ref
            for s in self.saved
        )


# ---------------------------------------------------------------------- session


class Session:
    def __init__(self, agent_input: Any, mode: str, scrs_path: Path, max_paths: int) -> None:
        from scrp.state_manager import StateManager

        self.agent_input = agent_input
        self.mode = mode
        self.max_paths = max_paths
        self.replay = Replay() if mode == "replay" else None
        self.sm = StateManager(scrs_path)
        self.candidates: list[Any] = []
        self.paths: dict[str, Any] = {}
        self.scenarios: list[Any] = []

    # -- generation -------------------------------------------------------
    def _generate(self, paths: list[Any], feedback: list[str] | None = None) -> list[Any]:
        from unittest.mock import patch

        from agents.threat_agent import orchestrator

        target = self.replay.generate if self.replay else orchestrator.generate_scenarios
        with patch.object(orchestrator, "generate_scenarios", target):
            scenarios, _retries, _status = orchestrator.generate_and_validate_with_retry(
                self.agent_input, paths=paths, initial_failure_details=feedback
            )
        return list(scenarios)

    def run_pipeline(self) -> None:
        from agents.threat_agent.attack_chain import build_paths, build_single_step_path
        from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates

        t0 = time.time()
        plan = build_retrieval_plan(self.agent_input)
        with console.status("Searching the knowledge base..."):
            self.candidates = fetch_candidates(plan)
        ok(f"Retrieved {len(self.candidates)} candidate patterns ({time.time() - t0:.0f}s)")

        try:
            paths = build_paths(self.candidates, self.agent_input)
        except NotImplementedError:
            paths = [build_single_step_path(c) for c in self.candidates]
        per_asset: dict[str, list[Any]] = {}
        for p in sorted(paths, key=lambda x: -x.chain_confidence):
            per_asset.setdefault(p.target_asset_ids[0] if p.target_asset_ids else "?", []).append(p)
        chosen: list[Any] = []
        while len(chosen) < self.max_paths and any(per_asset.values()):
            for lst in per_asset.values():
                if lst and len(chosen) < self.max_paths:
                    chosen.append(lst.pop(0))
        self.paths = {p.path_id: p for p in chosen}
        ok(f"Built {len(chosen)} attack paths")

        t0 = time.time()
        with console.status("Generating and validating threat scenarios..."):
            self.scenarios = self._generate(chosen)
        flagged = sum(1 for s in self.scenarios if s.validation_status != "passed")
        ok(
            f"Generated {len(self.scenarios)} scenarios ({time.time() - t0:.0f}s): "
            f"{len(self.scenarios) - flagged} passed validation, {flagged} flagged for review"
        )

    # -- regeneration after a rejection --------------------------------------
    def regenerate(self, old: Any, feedback: str) -> Any | None:
        from agents.threat_agent.attack_chain import build_single_step_path
        from agents.threat_agent.grounding import path_id_from_tid

        if self.replay is None:
            path = self.paths.get(path_id_from_tid(old.tid) or "")
            if path is None:
                return None
            with console.status("Regenerating with your feedback..."):
                new = self._generate([path], [feedback])
        else:
            # Recorded mode cannot use the feedback; show the next recorded alternative
            # for the same asset (its pattern was retrieved, so it is still grounded).
            alt = next(
                (
                    c
                    for c in sorted(self.candidates, key=lambda x: -x.retrieval_score)
                    if c.asset_id == old.asset_id
                    and c.pattern_id != old.kb_reference
                    and self.replay.has_unused(old.asset_id, c.pattern_id)
                ),
                None,
            )
            if alt is None:
                return None
            path = build_single_step_path(alt)
            self.paths[path.path_id] = path
            new = self._generate([path])
        return new[0].model_copy(update={"tid": old.tid}) if new else None


# --------------------------------------------------------------------- display


def show_card(s: Any, index: int, total: int, title: str | None = None) -> None:
    e = s.evidence_chain
    flagged = (s.validation_status or "") != "passed"
    status = (
        "[yellow]flagged: needs careful review[/yellow]" if flagged else "[green]passed[/green]"
    )
    lines = [
        f"[bold]Asset[/bold]       {s.asset_id}",
        f"[bold]STRIDE[/bold]      {stride_name(s.stride_category)}"
        f"      [bold]Confidence[/bold] {s.confidence_score:.2f}"
        f"      [bold]Validation[/bold] {status}",
        f"[bold]Pattern[/bold]     {s.kb_reference}",
        f"[bold]Attack[/bold]      {s.attack_vector}",
        f"[bold]Exposure[/bold]    {e.exposure}",
        f"[bold]Why[/bold]         {e.applicability_reason}",
        f"[bold]Citation[/bold]    {e.citation}",
    ]
    console.print(
        Panel(
            "\n".join(lines),
            title=title or f"Scenario {index} of {total}   {s.tid}",
            title_align="left",
            border_style="yellow" if flagged else "cyan",
            padding=(0, 1),
        )
    )


def show_summary_table(scenarios: list[Any]) -> None:
    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    t.add_column("#", justify="right")
    t.add_column("Asset")
    t.add_column("STRIDE")
    t.add_column("Pattern")
    t.add_column("Conf", justify="right")
    t.add_column("Validation")
    t.add_column("Attack", no_wrap=True, overflow="ellipsis", max_width=44)
    for i, s in enumerate(scenarios, 1):
        passed = s.validation_status == "passed"
        t.add_row(
            str(i),
            s.asset_id,
            stride_name(s.stride_category),
            s.kb_reference,
            f"{s.confidence_score:.2f}",
            "[green]passed[/green]" if passed else "[yellow]flagged[/yellow]",
            s.attack_vector,
        )
    console.print(t)


# ----------------------------------------------------------------------- review


def add_expert_scenario(session: Session) -> Any | None:
    from agents.threat_agent.retrieval import kb_reference_exists
    from agents.threat_agent.schemas import (
        EvidenceChain,
        STRIDECategory,
        ThreatScenario,
        ThreatStatus,
    )
    from agents.threat_agent.validator import Validator

    ai = session.agent_input
    ids = ", ".join(a.asset_id for a in ai.assets)
    asset_id = ask(f"Asset ({ids})")
    if asset_id not in {a.asset_id for a in ai.assets}:
        err(f"Unknown asset '{asset_id}'")
        return None
    try:
        stride = STRIDECategory(
            ask("STRIDE category (e.g. Spoofing, Tampering, InformationDisclosure)")
        )
    except ValueError:
        err("Not a valid STRIDE category")
        return None
    ref = ask("Pattern id (e.g. CAPEC-94, CWE-306)")
    if kb_reference_exists(ref) is False:
        err(f"'{ref}' does not exist in the knowledge base")
        return None
    vector = ask("Attack description")
    exposure = ask("What is exposed on the asset")
    why = ask("Why it applies")
    citation = ask("Citation text (must name the pattern id)", ref)
    justification = ask("Why are you adding it", "Expert knowledge")
    try:
        sc = ThreatScenario(
            tid=f"THR-EXP-{uuid.uuid4().hex[:8].upper()}",
            run_id=ai.run_id,
            asset_id=asset_id,
            stride_category=stride,
            attack_vector=vector,
            kb_reference=ref,
            evidence_chain=EvidenceChain(
                exposure=exposure, matched_pattern=ref, applicability_reason=why, citation=citation
            ),
            confidence_score=1.0,
            status=ThreatStatus.PENDING_TEST,
            validation_status="passed",
            use_case_id=session.scenarios[0].use_case_id if session.scenarios else None,
            asset_version=next((a.version for a in ai.assets if a.asset_id == asset_id), None),
            kb_snapshot_version=ai.kb_snapshot_version,
        )
    except Exception as exc:
        err(short(str(exc), 160))
        return None
    result = Validator().validate(sc)
    if not result.passed:
        for fc in result.failed_checks:
            err(f"{fc.check_id}: {short(fc.detail, 200)}")
        return None
    session.sm.log_edit(ai.run_id, sc.tid, "add", justification, sc.model_dump(mode="json"))
    ok(f"Added {sc.tid}")
    return sc


def review_one(session: Session, idx: int, total: int, auto: bool) -> tuple[str, Any]:
    """Review one scenario; returns (decision, scenario)."""
    s = session.scenarios[idx]
    rejections = 0
    first = True
    while True:
        show_card(s, idx + 1, total, None if first else f"Revised scenario {idx + 1} of {total}")
        first = False
        if auto:
            answer = "n" if (idx == 0 and rejections == 0) else "y"
            console.print(f"Approve this scenario? (y/n): [bold]{answer}[/bold]  (scripted)")
        else:
            answer = ask(
                "Approve this scenario? (y=yes, n=no, x=discard, a=all, q=quit; default y)",
                "y",
            )
        answer = answer.strip().lower()

        if answer in {"y", "yes"}:
            return "approved", s
        if answer in {"a", "all"}:
            return "all", s
        if answer in {"q", "quit"}:
            return "quit", s
        if answer in {"x", "discard"}:
            reason = "Out of scope (scripted)." if auto else ask("Reason for discarding")
            session.sm.log_edit(
                session.agent_input.run_id,
                s.tid,
                "prune",
                reason or "Discarded",
                s.model_dump(mode="json"),
            )
            ok("Discarded and logged")
            return "discarded", s
        if answer in {"n", "no"}:
            rejections += 1
            if auto:
                reason = "Be specific to this asset's interface and say why existing controls fail."
                console.print(f"Reason for rejection: [bold]{reason}[/bold] (scripted)")
            else:
                reason = ask("Reason for rejection") or "No reason given"
            session.sm.log_rejection(session.agent_input.run_id, reason, [s])
            if rejections >= MAX_REJECTIONS:
                warn(f"Rejected {MAX_REJECTIONS} times; marked rejected, not written.")
                return "rejected", s
            if session.replay is not None:
                warn(
                    "Recorded mode: showing the next recorded alternative for this asset "
                    "(use --mode live to regenerate from your reason)."
                )
            new = session.regenerate(s, reason)
            if new is None:
                warn("No new version could be produced.")
                return "rejected", s
            ok(f"Regenerated (attempt {rejections + 1} of {MAX_REJECTIONS})")
            s = new
            session.scenarios[idx] = new
            continue
        err("Please answer y, n, x, a or q")


def review_all(session: Session, auto: bool) -> tuple[list[Any], dict[str, int]]:
    approved: list[Any] = []
    counts: Counter[str] = Counter()
    total = len(session.scenarios)
    approve_rest = False
    i = 0
    while i < len(session.scenarios):
        if approve_rest:
            approved.append(session.scenarios[i])
            counts["approved"] += 1
            i += 1
            continue
        decision, s = review_one(session, i, total, auto)
        if decision in {"approved", "all"}:
            approved.append(s)
            counts["approved"] += 1
            approve_rest = decision == "all"
        elif decision == "quit":
            warn("Review stopped; unreviewed scenarios are not written.")
            break
        else:
            counts[decision] += 1
        i += 1
    if (
        not auto
        and counts
        and Prompt.ask("\nAdd a scenario of your own? (y/n)", default="n", show_default=False)
        == "y"
    ):
        sc = add_expert_scenario(session)
        if sc is not None:
            show_card(sc, 0, 0, f"Expert scenario {sc.tid}")
            approved.append(sc)
            counts["added"] += 1
    return approved, dict(counts)


# ------------------------------------------------------------------------ finish


def write_results(
    session: Session, approved: list[Any], scrs_path: Path, report_path: Path
) -> None:
    from agents.threat_agent.schemas import ThreatStatus

    if not approved:
        warn("Nothing approved, so nothing was written to the shared state.")
        return
    final = [s.model_copy(update={"status": ThreatStatus.APPROVED}) for s in approved]
    n = session.sm.commit_approved_run(session.agent_input.run_id, final)
    log = session.sm.get_audit_log()
    actions = Counter(e.action for e in log)
    ok(f"{n} approved scenarios written to {scrs_path.relative_to(_ROOT)}")
    console.print(
        "    audit log: "
        + ", ".join(
            f"{actions[a]} {a}"
            for a in ("write", "approve", "reject", "prune", "add")
            if actions[a]
        )
    )
    report_path.write_text(
        json.dumps(
            {
                "run_id": session.agent_input.run_id,
                "mode": session.mode,
                "approved": [s.model_dump(mode="json") for s in approved],
                "audit_counts": dict(actions),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    ok(f"Report saved to {report_path.relative_to(_ROOT)}")


def run_once(args: argparse.Namespace, settings: Any) -> bool:
    name, path = choose_project(args)
    args.project = None
    args.input = None
    agent_input = load_project(path)
    folder = path.parent.name
    mode = args.mode
    if mode == "auto":
        mode = "replay" if folder in REPLAY_PROJECTS else "live"
    if mode == "replay" and folder not in REPLAY_PROJECTS:
        sys.exit("No recorded output for this project; use --mode live.")

    shutil.rmtree(OUT_DIR, ignore_errors=True)
    OUT_DIR.mkdir(parents=True)
    scrs_path, report_path = OUT_DIR / "SCRS_demo.json", OUT_DIR / "run_report.json"

    db = settings.DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
    source = "recorded model output" if mode == "replay" else f"model {settings.OPENAI_MODEL}"
    console.print(
        f"\nProject [bold]{name}[/bold]   {len(agent_input.assets)} assets   "
        f"knowledge base {db}   {source}\n"
    )

    session = Session(agent_input, mode, scrs_path, args.max_paths)
    session.run_pipeline()
    if not session.scenarios:
        err("No scenarios were produced.")
        return False

    console.print()
    show_summary_table(session.scenarios)
    console.print("Review each scenario. Nothing is saved until you approve it.\n")
    approved, counts = review_all(session, args.auto)

    console.print()
    parts = [f"{v} {k}" for k, v in counts.items()]
    console.print("[bold]Review finished:[/bold] " + (", ".join(parts) or "nothing reviewed"))
    write_results(session, approved, scrs_path, report_path)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--project", help="project number from the menu")
    parser.add_argument("--input", help="path to a project JSON file")
    parser.add_argument(
        "--mode",
        choices=["auto", "replay", "live"],
        default="auto",
        help="auto: recorded output when available, else the model; live: always the model",
    )
    parser.add_argument("--auto", action="store_true", help="scripted answers for rehearsal")
    parser.add_argument(
        "--max-paths", type=int, default=6, help="scenarios to generate (default 6)"
    )
    parser.add_argument("--verbose", action="store_true", help="show internal JSON logs")
    args = parser.parse_args()
    if not args.verbose:
        logging.disable(logging.CRITICAL)

    from config.settings import get_settings

    settings = get_settings()
    console.print("[bold cyan]SCRP Threat Agent[/bold cyan]  Phase 1\n")
    while True:
        if not run_once(args, settings) or args.auto:
            break
        if (
            Prompt.ask("\nRun another project? (y/n)", default="n", show_default=False).lower()
            != "y"
        ):
            break


if __name__ == "__main__":
    code = 0
    try:
        main()
    except KeyboardInterrupt:
        console.print("\nInterrupted.")
        code = 130
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (1 if exc.code else 0)
        if isinstance(exc.code, str):
            console.print(exc.code)
    sys.stdout.flush()
    # Skip waiting for the database pool's background threads (untidy shutdown traceback).
    os._exit(code)
