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


def info(msg: str) -> None:
    console.print(f"[cyan]..[/cyan]  {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]!![/yellow]  {msg}")


def err(msg: str) -> None:
    console.print(f"[red]error[/red]  {msg}")


def short(text: str, n: int = 70) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def step(number: int, title: str, does: str) -> None:
    console.print(f"\n[bold cyan]Step {number}/7  {title}[/bold cyan]")
    console.print(f"[dim]{does}[/dim]")


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


def load_runs(path: Path) -> list[Any]:
    """One input per use case (a single-run file gives one), each with a fresh run id."""
    from agents.threat_agent.project import load_inputs

    return [
        i.model_copy(
            update={"run_id": f"{i.run_id.rsplit('-', 1)[0]}-{uuid.uuid4().hex[:6].upper()}"}
        )
        if i.project_id
        else i.model_copy(update={"run_id": f"RUN-{uuid.uuid4().hex[:6].upper()}"})
        for i in load_inputs(path)
    ]


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
    def __init__(
        self, agent_input: Any, mode: str, scrs_path: Path, max_paths: int, explain: bool = True
    ) -> None:
        from scrp.state_manager import StateManager

        self.agent_input = agent_input
        self.mode = mode
        self.max_paths = max_paths
        self.explain = explain
        self.replay = Replay() if mode == "replay" else None
        self.sm = StateManager(scrs_path)
        self.candidates: list[Any] = []
        self.paths: dict[str, Any] = {}
        self.scenarios: list[Any] = []
        self.previous: list[Any] = []
        self.skip: set[tuple[str, str]] = set()
        self.load_previous()

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

    def load_previous(self) -> None:
        """Approved scenarios of this project saved by earlier runs (kept, never re-reviewed)."""
        from agents.threat_agent.schemas import ThreatScenario
        from agents.threat_agent.staleness import use_case_key

        key = use_case_key(self.agent_input)
        found = []
        for raw in self.sm.get_threat_scenarios().values():
            try:
                sc = ThreatScenario.model_validate(raw)
            except Exception:  # noqa: S112
                continue
            if (
                sc.use_case_id == key
                and sc.project_id == self.agent_input.project_id
                and str(sc.status) in {"approved", "ThreatStatus.APPROVED"}
            ):
                found.append(sc)
        found.sort(key=lambda x: x.created_at)
        self.previous = found
        self.skip = {(x.asset_id, x.kb_reference) for x in found}

    # -- helpers used to explain what the agent did ---------------------------------
    def score_of(self, s: Any) -> float | None:
        for c in self.candidates:
            if c.asset_id == s.asset_id and c.pattern_id == s.kb_reference:
                return float(c.retrieval_score)
        return None

    def check_flags(self, s: Any) -> dict[str, bool]:
        """Which of the five automatic checks this scenario passes (True = pass)."""
        from agents.threat_agent.grounding import check_grounding, path_id_from_tid
        from agents.threat_agent.validator import Validator

        failed = {fc.check_id for fc in Validator().validate(s).failed_checks}
        grounded = not check_grounding(
            s, self.paths.get(path_id_from_tid(s.tid) or ""), self.agent_input.assets
        )
        return {
            "Citation": "CITATION_MISSING" not in failed,
            "Schema": "SCHEMA_INCOMPLETE" not in failed,
            "STRIDE fit": "CONSISTENCY_MISMATCH" not in failed,
            "Evidence": "EVIDENCE_GENERIC" not in failed,
            "Grounded": grounded,
        }

    def run_pipeline(self) -> None:
        from agents.threat_agent.attack_chain import build_paths, build_single_step_path
        from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
        from common.pii_redaction import redact_pii_with_count

        ai = self.agent_input
        ex = self.explain

        # Step 1 - understand the system
        if ex:
            step(
                1,
                "Understanding the system",
                "The agent reads every asset: what it is, which interfaces it exposes and which "
                "security properties it must keep. For each property the answer is simply "
                "yes or no: "
                "is it required for this asset?",
            )
            console.print(f"  Use case: {short(ai.use_case, 110)}")
            t = Table(box=box.SIMPLE_HEAD, header_style="bold")
            for col in ("Asset", "Name"):
                t.add_column(col)
            for col in ("Conf.", "Integ.", "Avail.", "Auth."):
                t.add_column(col, justify="center")
            t.add_column("Interfaces")
            for a in ai.assets:
                yn = [
                    "[green]yes[/green]"
                    if getattr(a.security_attributes, k, False)
                    else "[dim]no[/dim]"
                    for k in ("confidentiality", "integrity", "availability", "authenticity")
                ]
                t.add_row(
                    a.asset_id,
                    a.name,
                    *yn,
                    short(", ".join(a.dfd_context.interfaces), 40),
                )
            console.print(t)
            _, masked = redact_pii_with_count(ai.use_case + " " + ai.system_model)
            console.print(
                f"  Privacy: {masked} credential / personal item(s) masked before anything is "
                "sent to the model."
            )

        # Step 2 - plan the search
        t0 = time.time()
        plan = build_retrieval_plan(ai)
        if ex:
            step(
                2,
                "Planning the search",
                "For each asset the agent writes a search text and works out which STRIDE threat "
                "types apply (integrity -> Tampering, authenticity -> Spoofing, confidentiality "
                "-> Information Disclosure, availability -> Denial of Service).",
            )
            t = Table(box=box.SIMPLE_HEAD, header_style="bold")
            for col in ("Asset", "Search text", "Topic tags", "STRIDE to look for"):
                t.add_column(col)
            for q in plan.queries:
                t.add_row(
                    str(q["asset_id"]),
                    short(str(q["query_text"]), 46),
                    ", ".join(q.get("asset_tags", [])[:4]) or "-",  # type: ignore[arg-type]
                    ", ".join(q.get("asset_stride", [])) or "-",  # type: ignore[arg-type]
                )
            console.print(t)

        # Step 3 - search the knowledge base
        if ex:
            step(
                3,
                "Searching the knowledge base",
                "Each search text becomes a 384-number vector and is compared (cosine similarity) "
                "with every CAPEC / ATT&CK / CWE / STRIDE pattern. Patterns whose topic tags match "
                "the asset get a small boost.",
            )
        with console.status("Searching the knowledge base..."):
            self.candidates = fetch_candidates(plan)
        by_src = Counter(c.source.value for c in self.candidates)
        ok(
            f"{len(self.candidates)} patterns retrieved in {time.time() - t0:.0f}s "
            f"({', '.join(f'{k} {v}' for k, v in by_src.most_common())})"
        )
        if ex:
            t = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Best matches per asset")
            for col in ("Asset", "Pattern", "Source", "Similarity", "Title"):
                t.add_column(col)
            for a in ai.assets:
                mine = [c for c in self.candidates if c.asset_id == a.asset_id]
                for c in sorted(mine, key=lambda x: -x.retrieval_score)[:2]:
                    t.add_row(
                        a.asset_id,
                        c.pattern_id,
                        c.source.value,
                        f"{c.retrieval_score:.2f}",
                        short(c.title, 40),
                    )
            console.print(t)

        # Step 4 - attack paths
        try:
            paths = build_paths(self.candidates, ai)
        except NotImplementedError:
            paths = [build_single_step_path(c) for c in self.candidates]
        if self.skip:
            before = len(paths)
            paths = [
                p
                for p in paths
                if (p.target_asset_ids[0] if p.target_asset_ids else "?", p.steps[0].pattern_id)
                not in self.skip
            ]
            if before != len(paths):
                info(
                    f"{before - len(paths)} patterns already approved in earlier runs are skipped, "
                    "so you only review new proposals"
                )
        per_asset: dict[str, list[Any]] = {}
        for p in sorted(paths, key=lambda x: -x.chain_confidence):
            per_asset.setdefault(p.target_asset_ids[0] if p.target_asset_ids else "?", []).append(p)
        chosen: list[Any] = []
        while len(chosen) < self.max_paths and any(per_asset.values()):
            for lst in per_asset.values():
                if lst and len(chosen) < self.max_paths:
                    chosen.append(lst.pop(0))
        self.paths = {p.path_id: p for p in chosen}
        if ex:
            step(
                4,
                "Building attack paths",
                "Each retrieved pattern is paired with the asset it was found for. The best "
                f"{len(chosen)} (spread across the assets) are taken forward. Linking patterns "
                "into multi-step chains is not implemented yet.",
            )
            t = Table(box=box.SIMPLE_HEAD, header_style="bold")
            for col in ("Path", "Asset", "Pattern", "Confidence"):
                t.add_column(col)
            for p in chosen:
                t.add_row(
                    p.path_id,
                    ",".join(p.target_asset_ids),
                    " -> ".join(x.pattern_id for x in p.steps),
                    f"{p.chain_confidence:.2f}",
                )
            console.print(t)
        else:
            ok(f"Built {len(chosen)} attack paths")

        # Step 5 - generate
        if ex:
            step(
                5,
                "Generating threat scenarios",
                "For every path the model receives the asset facts and the pattern text, and must "
                "return the attack, what is exposed, why it applies and a citation of the pattern.",
            )
        t0 = time.time()
        with console.status("Generating and validating threat scenarios..."):
            self.scenarios = self._generate(chosen)
        src = " (recorded model output)" if self.replay else ""
        ok(f"{len(self.scenarios)} scenarios generated{src}")

        # Step 6 - validate
        if ex:
            step(
                6,
                "Checking the output",
                "Every scenario must pass 5 automatic checks. Scenarios that fail are regenerated "
                "(only those, up to 3 times); if they still fail they are flagged for you.",
            )
            t = Table(box=box.SIMPLE_HEAD, header_style="bold")
            t.add_column("#", justify="right")
            t.add_column("Asset")
            t.add_column("Pattern")
            for col in ("Citation", "Schema", "STRIDE fit", "Evidence", "Grounded"):
                t.add_column(col, justify="center")
            t.add_column("Result")
            for i, sc in enumerate(self.scenarios, 1):
                flags = self.check_flags(sc)
                cells = ["[green]ok[/green]" if v else "[red]FAIL[/red]" for v in flags.values()]
                result = (
                    "[green]passed[/green]"
                    if sc.validation_status == "passed"
                    else "[yellow]flagged[/yellow]"
                )
                t.add_row(str(i), sc.asset_id, sc.kb_reference, *cells, result)
            console.print(t)
            console.print(
                "  Grounded = cites only a pattern that was really retrieved, targets a real "
                "asset, and describes an exposure that belongs to that asset."
            )
        flagged = sum(1 for sc in self.scenarios if sc.validation_status != "passed")
        ok(f"{len(self.scenarios) - flagged} passed all checks, {flagged} flagged for your review")

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
            # the scenario keeps its tid, so its tid must now resolve to the new path
            self.paths[path_id_from_tid(old.tid) or ""] = path
            new = self._generate([path])
        return new[0].model_copy(update={"tid": old.tid}) if new else None


# --------------------------------------------------------------------- display


def show_card(
    s: Any, index: int, total: int, title: str | None = None, session: Session | None = None
) -> None:
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
    if session is not None:
        score = session.score_of(s)
        origin = f"{s.asset_id} -> {s.kb_reference}" + (
            f" (similarity {score:.2f})" if score else ""
        )
        flags = session.check_flags(s)
        checks = "  ".join(f"{k} {'ok' if v else 'FAIL'}" for k, v in flags.items())
        lines.append(f"[bold]Derived[/bold]     {origin}")
        lines.append(f"[bold]Checks[/bold]      {checks}")
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


def approved_table(rows: list[tuple[Any, str]], title: str) -> None:
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", title=title)
    t.add_column("#", justify="right")
    t.add_column("Asset")
    t.add_column("STRIDE")
    t.add_column("Pattern")
    t.add_column("From", no_wrap=True)
    t.add_column("Attack", no_wrap=True, overflow="ellipsis", max_width=44)
    for i, (sc, origin) in enumerate(rows, 1):
        t.add_row(
            str(i),
            sc.asset_id,
            stride_name(sc.stride_category),
            sc.kb_reference,
            origin,
            sc.attack_vector,
        )
    console.print(t)


def origin_of(sc: Any, current_run: str) -> str:
    who = "expert" if sc.tid.startswith("THR-EXP") else "AI"
    when = "new" if sc.run_id == current_run else "earlier"
    return f"{who} ({when})"


def show_previous(session: Session) -> None:
    if not session.previous:
        return
    run = session.agent_input.run_id
    console.print()
    approved_table(
        [(sc, origin_of(sc, run)) for sc in session.previous],
        f"Already approved for this project ({len(session.previous)}), kept from earlier runs",
    )
    console.print("These stay in the shared state. New proposals below are in addition to them.\n")


# ----------------------------------------------------------------------- review


def add_expert_scenario(session: Session) -> Any | None:
    from agents.threat_agent.retrieval import kb_reference_exists
    from agents.threat_agent.schemas import (
        EvidenceChain,
        STRIDECategory,
        ThreatScenario,
        ThreatStatus,
    )
    from agents.threat_agent.staleness import traceability_stamp
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
            **traceability_stamp(ai, asset_id),
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
        show_card(
            s, idx + 1, total, None if first else f"Revised scenario {idx + 1} of {total}", session
        )
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
        and (counts or session.previous)
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
        warn("Nothing new was approved, so nothing was added to the shared state.")
        if session.previous:
            ok(f"{len(session.previous)} earlier approved scenarios are still saved")
        return
    final = [s.model_copy(update={"status": ThreatStatus.APPROVED}) for s in approved]
    n = session.sm.commit_approved_run(session.agent_input.run_id, final)
    log = session.sm.get_audit_log()
    actions = Counter(e.action for e in log)
    ok(f"{n} newly approved scenarios written to {scrs_path.relative_to(_ROOT)}")
    run = session.agent_input.run_id
    everything = [(sc, origin_of(sc, run)) for sc in session.previous] + [
        (sc, origin_of(sc, run)) for sc in approved
    ]
    console.print()
    approved_table(
        everything,
        f"All approved scenarios for this project now saved ({len(everything)})",
    )
    console.print("Run the project again to continue from here; use --fresh to start clean.")
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
                "approved_this_run": [s.model_dump(mode="json") for s in approved],
                "approved_total": len(session.previous) + len(approved),
                "audit_counts": dict(actions),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    ok(f"Report saved to {report_path.relative_to(_ROOT)}")


def approved_for(scrs_path: Path, agent_input: Any) -> list[Any]:
    """Approved scenarios saved for this use case (project + use case id)."""
    from agents.threat_agent.schemas import ThreatScenario
    from agents.threat_agent.staleness import use_case_key
    from scrp.state_manager import StateManager

    key = use_case_key(agent_input)
    out = []
    for raw in StateManager(scrs_path).get_threat_scenarios().values():
        try:
            sc = ThreatScenario.model_validate(raw)
        except Exception:  # noqa: S112
            continue
        if sc.use_case_id == key and sc.project_id == agent_input.project_id:
            out.append(sc)
    return out


def choose_use_cases(runs: list[Any], scrs_path: Path, args: argparse.Namespace) -> list[Any]:
    """A product with several use cases: show them and let the user pick one (or all)."""
    if len(runs) == 1:
        return runs
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Use cases of this product")
    table.add_column("#", justify="right")
    table.add_column("Use case")
    table.add_column("Title")
    table.add_column("Assets", justify="right")
    table.add_column("Approved so far", justify="right")
    for i, r in enumerate(runs, 1):
        title = r.use_case.split(".")[0]
        table.add_row(
            str(i),
            str(r.use_case_id),
            title,
            str(len(r.assets)),
            str(len(approved_for(scrs_path, r))),
        )
    console.print(table)
    choice = args.use_case or (
        "1" if args.auto else ask("Select a use case (number, id or 'all')", "1")
    )
    choice = choice.strip()
    if choice.lower() == "all":
        return runs
    for i, r in enumerate(runs, 1):
        if choice == str(i) or choice.upper() == str(r.use_case_id).upper():
            return [r]
    sys.exit(f"Unknown use case '{choice}'.")


def handle_staleness(agent_input: Any, scrs_path: Path, args: argparse.Namespace) -> Any:
    """Go back one step: if approved threats no longer match their upstream data, offer to retire
    them and re-run only the affected assets. Returns the input to analyse."""
    from agents.threat_agent.staleness import check_staleness
    from scrp.state_manager import StateManager

    previous = approved_for(scrs_path, agent_input)
    if not previous:
        return agent_input
    report = check_staleness(agent_input, previous)
    if not report.has_changes:
        return agent_input
    console.print()
    t = Table(
        box=box.SIMPLE_HEAD, header_style="bold", title="Upstream data changed since you approved"
    )
    t.add_column("Scenario")
    t.add_column("Asset")
    t.add_column("Why it is out of date")
    for item in report.stale:
        t.add_row(short(item.tid, 28), item.asset_id, item.reason)
    console.print(t)
    warn(
        f"{len(report.stale)} approved scenario(s) no longer match the current assets "
        "or system model."
    )
    answer = "y" if args.auto else ask("Retire them and re-run the affected assets? (y/n)", "y")
    if answer.strip().lower() not in {"y", "yes"}:
        warn("Kept as they are. They stay in the shared state and are marked here as out of date.")
        return agent_input
    sm = StateManager(scrs_path)
    by_reason: dict[str, list[str]] = {}
    for item in report.stale:
        by_reason.setdefault(item.reason, []).append(item.tid)
    for reason, tids in by_reason.items():
        sm.retire_scenarios(tids, f"Upstream data changed: {reason}")
    ok(f"Retired {len(report.stale)} scenario(s) into the history. New proposals follow.")
    affected = set(report.affected_assets)
    only = [a for a in agent_input.assets if a.asset_id in affected]
    if only and len(only) < len(agent_input.assets):
        info("Re-running only the affected assets: " + ", ".join(sorted(affected)))
        return agent_input.model_copy(update={"assets": only})
    return agent_input


def replay_available(path: Path, agent_input: Any) -> bool:
    return path.parent.name in REPLAY_PROJECTS or agent_input.project_id == "CSDL-100"


def run_use_case(
    agent_input: Any,
    name: str,
    path: Path,
    args: argparse.Namespace,
    settings: Any,
    scrs_path: Path,
    report_path: Path,
) -> bool:
    mode = args.mode
    if mode == "auto":
        mode = "replay" if replay_available(path, agent_input) else "live"
    if mode == "replay" and not replay_available(path, agent_input):
        sys.exit("No recorded output for this project; use --mode live.")

    db = settings.DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
    source = "recorded model output" if mode == "replay" else f"model {settings.OPENAI_MODEL}"
    uc = f"   use case [bold]{agent_input.use_case_id}[/bold]" if agent_input.use_case_id else ""
    console.print(
        f"\nProject [bold]{name}[/bold]{uc}   {len(agent_input.assets)} assets   "
        f"knowledge base {db}   {source}\n"
    )

    agent_input = handle_staleness(agent_input, scrs_path, args)
    session = Session(agent_input, mode, scrs_path, args.max_paths, not args.quiet)
    show_previous(session)
    session.run_pipeline()
    if not session.scenarios and not session.previous:
        err("No scenarios were produced.")
        return False
    if not session.scenarios:
        warn("No new proposals: every retrieved pattern is already approved for this use case.")

    console.print()
    if session.scenarios:
        show_summary_table(session.scenarios)
    if args.quiet:
        console.print("Review each scenario. Nothing is saved until you approve it.\n")
    else:
        step(
            7,
            "Your review",
            "You decide on every scenario; nothing is saved until you approve it. If you reject "
            "one, give a reason: the agent feeds it back to the model, regenerates that scenario, "
            "re-checks it and shows it again (at most 3 rejections per scenario). Approved "
            "scenarios are written to the shared state with an audit log.",
        )
    approved, counts = review_all(session, args.auto)

    console.print()
    parts = [f"{v} {k}" for k, v in counts.items()]
    console.print("[bold]Review finished:[/bold] " + (", ".join(parts) or "nothing reviewed"))
    write_results(session, approved, scrs_path, report_path)
    return True


def run_once(args: argparse.Namespace, settings: Any) -> bool:
    name, path = choose_project(args)
    args.project = None
    args.input = None
    runs = load_runs(path)

    if args.fresh or args.auto:
        shutil.rmtree(OUT_DIR, ignore_errors=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    scrs_path = OUT_DIR / "SCRS_demo.json"

    chosen = choose_use_cases(runs, scrs_path, args)
    args.use_case = None
    result = True
    for run in chosen:
        report = OUT_DIR / (
            f"run_report_{run.use_case_id}.json" if len(runs) > 1 else "run_report.json"
        )
        result = run_use_case(run, name, path, args, settings, scrs_path, report) and result
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--project", help="project number from the menu")
    parser.add_argument("--input", help="path to a project JSON file")
    parser.add_argument(
        "--use-case", help="for a product with several use cases: id (UC-02), number or 'all'"
    )
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
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="start clean: forget scenarios approved in earlier runs",
    )
    parser.add_argument("--quiet", action="store_true", help="short output without explanations")
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
