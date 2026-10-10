# ruff: noqa: ANN401
"""SCRP Phase 1 - Threat Agent demonstration (company walkthrough).

Runs the real Phase 1 pipeline end to end and shows each stage:

    1 Perceive      input model, assets, secret / PII redaction
    2 Knowledge     the knowledge base in use, retrieval plan, retrieved patterns
    3 Attack paths  one path per retrieved pattern (multi-step chaining is planned)
    4 Generation    threat scenarios (live model or recorded real model output)
    5 Validation    4 protocol invariants + grounding rules, retry-only-failed
    6 Review        STRIDE coverage, scenario details, traceability fields
    7 Human gate    approve / reject-with-feedback / prune / add expert scenario
    8 SCRS + audit  approved scenarios written to the shared state, full audit trail

Examples
--------
    python scripts/scrp_demo.py                 # recorded model output, no network needed
    python scripts/scrp_demo.py --mode live     # calls the model configured in .env
    python scripts/scrp_demo.py --auto          # scripted walkthrough, no typing
    python scripts/scrp_demo.py --fixture pump --mode live

Everything the demo writes goes to ./demo_output (never to the real SCRS file).
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
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)

FIXTURES = {
    "lock": ("Smart Door Lock (BLE + cloud + OTA)", "smart_door_lock"),
    "pump": ("Medical Infusion Pump", "infusion_pump"),
}
REPLAY_FILE = _ROOT / "docs" / "research" / "final_fullkb_scenarios_raw_live.json"
OUT_DIR = _ROOT / "demo_output"
STRIDE_SHORT = {
    "Spoofing": "S",
    "Tampering": "T",
    "Repudiation": "R",
    "InformationDisclosure": "I",
    "DenialOfService": "D",
    "ElevationOfPrivilege": "E",
}


# --------------------------------------------------------------------------- helpers


def stage(number: int, title: str, subtitle: str = "") -> None:
    console.print()
    console.print(Rule(f"[bold cyan]STAGE {number}  |  {title}[/bold cyan]", style="cyan"))
    if subtitle:
        console.print(f"[dim]{subtitle}[/dim]")


def ok(msg: str) -> None:
    console.print(f"  [bold green]OK[/bold green]  {msg}")


def info(msg: str) -> None:
    console.print(f"  [cyan]..[/cyan]  {msg}")


def warn(msg: str) -> None:
    console.print(f"  [bold yellow]!![/bold yellow]  {msg}")


def fail(msg: str) -> None:
    console.print(f"  [bold red]XX[/bold red]  {msg}")


class Pacer:
    """Pauses between stages so a presenter can talk; disabled with --no-pause / --auto."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wait(self, text: str = "Press Enter to continue") -> None:
        if self.enabled:
            Prompt.ask(f"\n[dim]{text}[/dim]", default="", show_default=False)


def short(text: str, n: int = 70) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "..."


def stride_letter(value: Any) -> str:
    return STRIDE_SHORT.get(getattr(value, "value", str(value)), "?")


# --------------------------------------------------------------------------- stages


def load_input(fixture: str) -> Any:
    from agents.threat_agent.schemas import ThreatAgentInput

    folder = FIXTURES[fixture][1]
    path = _ROOT / "tests" / "threat_agent" / "e2e" / "fixtures" / folder / "input.json"
    return ThreatAgentInput.model_validate_json(path.read_text(encoding="utf-8"))


def banner(args: argparse.Namespace, settings: Any) -> None:
    db = settings.DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
    body = Text()
    body.append("SCRP - State-Aware Cybersecurity Reasoning Protocol\n", style="bold white")
    body.append("Phase 1: Threat Agent  |  Group TY-A9, VIT Pune\n", style="cyan")
    body.append("Industry partner: Infineon  |  Guide: Dr. Vidya Gaikwad\n\n", style="dim")
    body.append(f"Mode            {args.mode.upper()}", style="white")
    body.append(
        "  (recorded real model output; no network)\n"
        if args.mode == "replay"
        else f"  (model: {settings.OPENAI_MODEL})\n",
        style="dim",
    )
    body.append(f"Knowledge base  {db}\n", style="white")
    body.append(f"Fixture         {FIXTURES[args.fixture][0]}\n", style="white")
    body.append(
        "AI output is a recommendation only: a human approves every scenario.",
        style="italic yellow",
    )
    console.print(
        Panel(body, title="[bold]Demonstration[/bold]", border_style="cyan", padding=(1, 2))
    )


def stage_perceive(agent_input: Any) -> None:
    from common.pii_redaction import redact_pii_with_count

    stage(1, "PERCEIVE", "Validated input model, assets and outbound redaction (company 3.4)")
    console.print(f"  Run id        [bold]{agent_input.run_id}[/bold]")
    console.print(f"  Use case      {short(agent_input.use_case, 100)}")
    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for col in ("Asset", "Name", "Type", "Location", "Security attributes (C/I/A)"):
        t.add_column(col)
    for a in agent_input.assets:
        sa = a.security_attributes
        attrs = " ".join(
            f"{k[0].upper()}:{v}" for k, v in sa.model_dump().items() if isinstance(v, str)
        )
        t.add_row(a.asset_id, a.name, a.asset_type, short(a.location, 28), attrs or "-")
    console.print(t)

    sample = (
        "Debug build uses api_key=sk-demo-1234567890abcdef, admin password: Hunter22, "
        "contact ops@example.com from 192.168.10.4."
    )
    masked, count = redact_pii_with_count(sample)
    console.print("  [bold]Redaction before anything is sent to the model[/bold]")
    console.print(f"    before  [red]{sample}[/red]")
    console.print(f"    after   [green]{masked}[/green]   ({count} item(s) masked)")


def stage_knowledge(agent_input: Any, settings: Any) -> list[Any]:
    from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
    from common.db import get_db_connection

    stage(
        2,
        "KNOWLEDGE BASE AND RETRIEVAL",
        "Semantic search (pgvector, all-MiniLM-L6-v2) with domain-tag rerank",
    )
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT source, COUNT(*) FROM threat_patterns GROUP BY source ORDER BY 2 DESC"
            )
            rows = cur.fetchall()
            try:
                cur.execute("SELECT COUNT(*) FROM standards_chunks")
                chunks = cur.fetchone()[0]  # type: ignore[index]
            except Exception:
                chunks = None
    except Exception as exc:
        fail(f"Knowledge base unreachable: {exc}. Start it with `docker compose up -d`.")
        sys.exit(1)

    kb = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Knowledge base content")
    kb.add_column("Source")
    kb.add_column("Entries", justify="right")
    total = 0
    for src, n in rows:
        kb.add_row(str(src), f"{n:,}")
        total += n
    kb.add_row("[bold]Total patterns[/bold]", f"[bold]{total:,}[/bold]")
    if chunks is not None:
        kb.add_row("Standards chunks (CC/CEM/JIL/CRA)", f"{chunks:,}")
    console.print(kb)

    plan = build_retrieval_plan(agent_input)
    info(f"Retrieval plan: {len(plan.queries)} queries, one per asset attribute")
    t0 = time.time()
    with console.status(
        "[cyan]Loading the embedding model and searching the knowledge base...[/cyan]"
    ):
        candidates = fetch_candidates(plan)
    ok(f"{len(candidates)} candidate patterns retrieved in {time.time() - t0:.1f}s")

    by_asset: dict[str, list[Any]] = {}
    for c in candidates:
        by_asset.setdefault(c.asset_id, []).append(c)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Top retrieved patterns per asset")
    for col in ("Asset", "Pattern", "Source", "Score", "Title"):
        t.add_column(col)
    for asset in agent_input.assets:
        for c in sorted(by_asset.get(asset.asset_id, []), key=lambda x: -x.retrieval_score)[:3]:
            t.add_row(
                asset.asset_id,
                c.pattern_id,
                c.source.value,
                f"{c.retrieval_score:.3f}",
                short(c.title, 46),
            )
    console.print(t)
    return candidates


def stage_chaining(candidates: list[Any], agent_input: Any, max_paths: int) -> list[Any]:
    from agents.threat_agent.attack_chain import build_paths, build_single_step_path

    stage(
        3,
        "ATTACK PATHS",
        "Each retrieved pattern becomes an attack path to be turned into a scenario",
    )
    try:
        paths = build_paths(candidates, agent_input)
        ok(f"{len(paths)} attack paths built by kill-chain ordering")
    except NotImplementedError:
        paths = [build_single_step_path(c) for c in candidates]
        ok(f"{len(paths)} single-step attack paths (one per retrieved pattern)")
        warn(
            "Multi-step kill-chain ordering (linking patterns into longer chains) is a "
            "planned extension and is not part of this demonstration."
        )

    # Take a balanced sample across assets so the demo stays short but representative.
    per_asset: dict[str, list[Any]] = {}
    for p in sorted(paths, key=lambda x: -x.chain_confidence):
        per_asset.setdefault(p.target_asset_ids[0] if p.target_asset_ids else "?", []).append(p)
    chosen: list[Any] = []
    while len(chosen) < max_paths and any(per_asset.values()):
        for lst in per_asset.values():
            if lst and len(chosen) < max_paths:
                chosen.append(lst.pop(0))
    info(f"Demonstrating {len(chosen)} paths (balanced across assets; use --max-paths to change)")
    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for col in ("Path", "Asset", "Chain", "Confidence"):
        t.add_column(col)
    for p in chosen:
        t.add_row(
            p.path_id,
            ",".join(p.target_asset_ids),
            " -> ".join(s.pattern_id for s in p.steps),
            f"{p.chain_confidence:.2f}",
        )
    console.print(t)
    return chosen


def _replay_generator(agent_input: Any) -> Any:
    """Return a generate_scenarios() stand-in that replays recorded REAL model output."""
    from agents.threat_agent.schemas import ThreatScenario

    saved = [ThreatScenario.model_validate(x) for x in json.loads(REPLAY_FILE.read_text("utf-8"))]
    used: set[str] = set()

    def replay(
        paths: list[Any], context: Any, *, validation_failure_context: Any = None
    ) -> list[Any]:
        out = []
        for seq, path in enumerate(paths):
            ref = path.steps[0].pattern_id
            asset = path.target_asset_ids[0] if path.target_asset_ids else ""
            for s in saved:
                if s.tid not in used and s.asset_id == asset and s.kb_reference == ref:
                    used.add(s.tid)
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

    return replay


def stage_generation_and_validation(
    agent_input: Any, paths: list[Any], mode: str
) -> tuple[list[Any], int, str]:
    from unittest.mock import patch

    from agents.threat_agent import orchestrator
    from agents.threat_agent.orchestrator import generate_and_validate_with_retry

    stage(4, "GENERATION", "One scenario per attack path, each citing a retrieved KB pattern")
    if mode == "replay":
        info("Replay mode: using recorded output of a real model run (no network needed)")
        gen_patch = patch.object(orchestrator, "generate_scenarios", _replay_generator(agent_input))
    else:
        info("Live mode: calling the configured language model")
        gen_patch = patch.object(
            orchestrator, "generate_scenarios", orchestrator.generate_scenarios
        )

    t0 = time.time()
    with gen_patch, console.status("[cyan]Generating, validating and grounding...[/cyan]"):
        scenarios, retries, status = generate_and_validate_with_retry(agent_input, paths=paths)
    retry_note = "n/a for recorded output" if mode == "replay" else str(retries)
    ok(
        f"{len(scenarios)} scenarios produced in {time.time() - t0:.1f}s "
        f"(automatic retries used: {retry_note})"
    )
    return scenarios, retries, status


def stage_validation(agent_input: Any, scenarios: list[Any], paths: list[Any]) -> None:
    from agents.threat_agent.grounding import check_grounding, path_id_from_tid
    from agents.threat_agent.validator import Validator

    stage(
        5,
        "VALIDATION",
        "4 frozen protocol invariants (FAR 15.38%, FRR 8.33%) + deterministic grounding rules",
    )
    by_path = {p.path_id: p for p in paths}
    val = Validator()
    rows = []
    passed = 0
    for s in scenarios:
        v = val.validate(s)
        pid = path_id_from_tid(s.tid)
        g = check_grounding(s, by_path.get(pid or ""), agent_input.assets)
        failed = [fc.check_id for fc in v.failed_checks] + [x.check_id for x in g]
        passed += not failed
        rows.append((s, failed))

    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for col in ("#", "Scenario", "Asset", "KB ref", "Invariants+grounding", "Final status"):
        t.add_column(col)
    for i, (s, failed) in enumerate(rows, 1):
        mark = (
            "[green]all pass[/green]"
            if not failed
            else f"[red]{', '.join(sorted(set(failed)))}[/red]"
        )
        status = s.validation_status or "-"
        style = "green" if status == "passed" else "yellow"
        t.add_row(
            str(i),
            short(s.tid, 24),
            s.asset_id,
            s.kb_reference,
            mark,
            f"[{style}]{status}[/{style}]",
        )
    console.print(t)
    ok(f"{passed}/{len(scenarios)} scenarios satisfy every check")
    info(
        "Scenarios that exhaust automatic retries are flagged 'escalated_after_retries' "
        "for the human reviewer. Only failing paths are regenerated."
    )
    info("Citations are verified in code: a scenario can only cite a pattern retrieval gave it.")


def stage_review(scenarios: list[Any], agent_input: Any, detail: int) -> None:
    stage(6, "SCENARIO REVIEW", "Coverage, evidence and traceability for the human reviewer")
    letters = list(STRIDE_SHORT.values())
    t = Table(
        box=box.SIMPLE_HEAD, header_style="bold", title="STRIDE coverage (scenarios per asset)"
    )
    t.add_column("Asset")
    for letter in letters:
        t.add_column(letter, justify="center")
    t.add_column("Total", justify="right")
    for a in agent_input.assets:
        cnt = Counter(
            stride_letter(s.stride_category) for s in scenarios if s.asset_id == a.asset_id
        )
        t.add_row(
            f"{a.asset_id} {short(a.name, 20)}",
            *[str(cnt[x]) if cnt[x] else "[dim].[/dim]" for x in letters],
            str(sum(cnt.values())),
        )
    console.print(t)
    src = Counter(s.kb_reference.split("-")[0] for s in scenarios)
    info("Evidence sources cited: " + ", ".join(f"{k} x{v}" for k, v in src.most_common()))
    for s in scenarios[:detail]:
        show_scenario(s)


def show_scenario(s: Any, title: str | None = None) -> None:
    e = s.evidence_chain
    body = (
        f"[bold]Asset[/bold] {s.asset_id}   [bold]STRIDE[/bold] {s.stride_category.value}   "
        f"[bold]Confidence[/bold] {s.confidence_score:.2f}   "
        f"[bold]Status[/bold] {s.validation_status}\n"
        f"[bold]Attack vector[/bold]  {s.attack_vector}\n"
        f"[bold]KB reference[/bold]   {s.kb_reference}\n\n"
        f"[bold]Evidence chain[/bold]\n"
        f"  exposure      {e.exposure}\n"
        f"  matched       {e.matched_pattern}\n"
        f"  why it applies {e.applicability_reason}\n"
        f"  citation      {e.citation}\n\n"
        f"[dim]Traceability: use case {s.use_case_id}  |  asset version {s.asset_version}  |  "
        f"KB snapshot {s.kb_snapshot_version}  |  run {s.run_id}[/dim]"
    )
    console.print(Panel(body, title=title or s.tid, border_style="green", padding=(0, 1)))


def scenario_table(scenarios: list[Any]) -> None:
    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for col in ("#", "Asset", "S", "KB ref", "Conf", "Status"):
        t.add_column(col, no_wrap=True)
    t.add_column("Attack vector", no_wrap=True, overflow="ellipsis", max_width=46)
    for i, s in enumerate(scenarios, 1):
        status = (
            "ESCALATED"
            if (s.validation_status or "").startswith("escalated")
            else (s.validation_status or "-")
        )
        t.add_row(
            str(i),
            s.asset_id,
            stride_letter(s.stride_category),
            s.kb_reference,
            f"{s.confidence_score:.2f}",
            status,
            s.attack_vector,
        )
    console.print(t)


# ------------------------------------------------------------------------ human gate


class Review:
    """State of the human review session (kept so the audit trail is complete)."""

    def __init__(
        self, agent_input: Any, scenarios: list[Any], paths: list[Any], mode: str, state_mgr: Any
    ) -> None:
        self.agent_input = agent_input
        self.scenarios = list(scenarios)
        self.paths = {p.path_id: p for p in paths}
        self.mode = mode
        self.sm = state_mgr
        self.events: list[str] = []

    def reject(self, idx: int, feedback: str) -> None:
        from agents.threat_agent.grounding import path_id_from_tid
        from agents.threat_agent.orchestrator import generate_and_validate_with_retry

        old = self.scenarios[idx]
        self.sm.log_rejection(self.agent_input.run_id, feedback, [old])
        self.events.append(f"rejected {old.tid}: {feedback}")
        warn(f"Rejected {old.tid} - feedback recorded in SCRS history")
        if self.mode == "replay":
            warn(
                "Replay mode cannot call the model, so the rejected scenario stays in the list. "
                "Run with --mode live to watch it regenerate from your feedback."
            )
            return
        pid = path_id_from_tid(old.tid)
        path = self.paths.get(pid or "")
        if path is None:
            warn("No attack path found for this scenario; cannot regenerate it.")
            return
        with console.status("[cyan]Regenerating this scenario with your feedback...[/cyan]"):
            new, retries, _ = generate_and_validate_with_retry(
                self.agent_input, paths=[path], initial_failure_details=[feedback]
            )
        if not new:
            warn("The model returned nothing; keeping the original.")
            return
        replacement = new[0].model_copy(update={"tid": old.tid})
        self.scenarios[idx] = replacement
        ok(f"Regenerated (retries: {retries}); revised scenario below")
        show_scenario(replacement, title="Revised scenario (after your feedback)")

    def prune(self, idx: int, reason: str) -> None:
        old = self.scenarios.pop(idx)
        self.sm.log_edit(
            self.agent_input.run_id, old.tid, "prune", reason, old.model_dump(mode="json")
        )
        self.events.append(f"pruned {old.tid}: {reason}")
        ok(f"Pruned {old.tid} (kept in the audit trail with your reason)")

    def add(self, fields: dict[str, str]) -> bool:
        from agents.threat_agent.retrieval import kb_reference_exists
        from agents.threat_agent.schemas import (
            EvidenceChain,
            STRIDECategory,
            ThreatScenario,
            ThreatStatus,
        )
        from agents.threat_agent.validator import Validator

        known = {a.asset_id for a in self.agent_input.assets}
        if fields["asset_id"] not in known:
            fail(f"Unknown asset '{fields['asset_id']}' (known: {', '.join(sorted(known))})")
            return False
        try:
            stride = STRIDECategory(fields["stride"])
        except ValueError:
            fail(f"'{fields['stride']}' is not a STRIDE category")
            return False
        if kb_reference_exists(fields["kb_ref"]) is False:
            fail(f"'{fields['kb_ref']}' does not exist in the knowledge base")
            return False
        try:
            sc = ThreatScenario(
                tid=f"THR-EXP-{uuid.uuid4().hex[:8].upper()}",
                run_id=self.agent_input.run_id,
                asset_id=fields["asset_id"],
                stride_category=stride,
                attack_vector=fields["vector"],
                kb_reference=fields["kb_ref"],
                evidence_chain=EvidenceChain(
                    exposure=fields["exposure"],
                    matched_pattern=fields["kb_ref"],
                    applicability_reason=fields["why"],
                    citation=fields["citation"],
                ),
                confidence_score=1.0,
                status=ThreatStatus.PENDING_TEST,
                validation_status="expert_added",
                use_case_id=self.scenarios[0].use_case_id if self.scenarios else None,
                asset_version=next(
                    (a.version for a in self.agent_input.assets
                     if a.asset_id == fields["asset_id"]),
                    None,
                ),
                kb_snapshot_version=self.agent_input.kb_snapshot_version,
            )
        except Exception as exc:
            fail(f"Invalid scenario: {short(str(exc), 120)}")
            return False
        result = Validator().validate(sc)
        if not result.passed:
            for fc in result.failed_checks:
                fail(f"Validator {fc.check_id}: {fc.detail}")
            return False
        self.sm.log_edit(
            self.agent_input.run_id,
            sc.tid,
            "add",
            fields["justification"],
            sc.model_dump(mode="json"),
        )
        self.scenarios.append(sc)
        self.events.append(f"added {sc.tid}: {fields['justification']}")
        ok(f"Expert scenario {sc.tid} added: validated, KB reference verified, audit-logged")
        show_scenario(sc, title="Expert-added scenario")
        return True

    def approve_all(self) -> int:
        from agents.threat_agent.schemas import ThreatStatus

        approved = [s.model_copy(update={"status": ThreatStatus.APPROVED}) for s in self.scenarios]
        return int(self.sm.commit_approved_run(self.agent_input.run_id, approved))


def _ask_add(agent_input: Any) -> dict[str, str]:
    known = ", ".join(a.asset_id for a in agent_input.assets)
    return {
        "asset_id": Prompt.ask(f"  Asset id ({known})"),
        "stride": Prompt.ask(
            "  STRIDE (Spoofing, Tampering, Repudiation, InformationDisclosure, "
            "DenialOfService, ElevationOfPrivilege)"
        ),
        "kb_ref": Prompt.ask("  KB reference (e.g. CAPEC-94, CWE-306)"),
        "vector": Prompt.ask("  Attack vector"),
        "exposure": Prompt.ask("  Exposure (the asset property that is exposed)"),
        "why": Prompt.ask("  Why it applies to this asset"),
        "citation": Prompt.ask("  Citation text (must name the KB reference)"),
        "justification": Prompt.ask("  Justification for adding", default="Expert knowledge"),
    }


def stage_human_gate(review: Review, auto: bool) -> bool:
    stage(
        7,
        "HUMAN-IN-THE-LOOP GATE",
        "Nothing reaches the shared state without a human decision (company 3.4)",
    )
    if auto:
        return _scripted_gate(review)
    help_text = (
        "  [bold]v N[/bold] view scenario N    "
        "[bold]r N[/bold] reject N with feedback (regenerates)\n"
        "  [bold]p N[/bold] prune N with reason  [bold]a[/bold] add an expert scenario\n"
        "  [bold]l[/bold] list scenarios         "
        "[bold]ok[/bold] approve all remaining and write to SCRS\n"
        "  [bold]q[/bold] quit without writing"
    )
    console.print(Panel(help_text, title="Reviewer commands", border_style="yellow"))
    scenario_table(review.scenarios)
    while True:
        raw = Prompt.ask("\n[bold yellow]review>[/bold yellow]", default="ok").strip().lower()
        cmd, _, arg = raw.partition(" ")
        idx = int(arg) - 1 if arg.strip().isdigit() else -1
        valid = 0 <= idx < len(review.scenarios)
        if cmd == "ok":
            return True
        if cmd == "q":
            return False
        if cmd == "l":
            scenario_table(review.scenarios)
        elif cmd == "v" and valid:
            show_scenario(review.scenarios[idx])
        elif cmd == "r" and valid:
            review.reject(idx, Prompt.ask("  Feedback for the model") or "Please revise.")
        elif cmd == "p" and valid:
            reason = Prompt.ask("  Reason for pruning (required)")
            if reason.strip():
                review.prune(idx, reason)
            else:
                fail("A reason is required")
        elif cmd == "a":
            review.add(_ask_add(review.agent_input))
        else:
            fail("Unknown command or number; type l to list scenarios")


def _scripted_gate(review: Review) -> bool:
    console.print("  [dim]Scripted walkthrough (--auto): the reviewer acts as follows.[/dim]")
    scenario_table(review.scenarios)
    review.reject(
        0,
        "Make the attack vector more specific to this asset's interface and "
        "explain why the existing countermeasures do not stop it.",
    )
    if len(review.scenarios) > 1:
        review.prune(
            len(review.scenarios) - 1,
            "Out of scope for the current product variant (reviewer judgement).",
        )
    asset = review.agent_input.assets[0]
    console.print(
        "  [dim]Reviewer first tries an inconsistent entry; the validator must stop it.[/dim]"
    )
    review.add(
        {
            "asset_id": asset.asset_id,
            "stride": "Spoofing",
            "kb_ref": "CWE-306",
            "vector": "Heavy rainfall damages the enclosure",
            "exposure": f"{asset.name} interface accepts requests without authentication",
            "why": "Placeholder reasoning that does not match the chosen STRIDE class at all.",
            "citation": "CWE-306: Missing Authentication for Critical Function",
            "justification": "Deliberately wrong example for the demonstration.",
        }
    )
    console.print("  [dim]Then enters a correct one.[/dim]")
    review.add(
        {
            "asset_id": asset.asset_id,
            "stride": "Spoofing",
            "kb_ref": "CWE-306",
            "vector": f"Impersonation of a legitimate caller to {asset.name} through an "
            "unauthenticated "
            "management interface (identity spoofing)",
            "exposure": f"{asset.name} interface accepts requests without caller authentication",
            "why": f"{asset.name} is reachable over its interface and no caller authentication is "
            "enforced before the critical function runs.",
            "citation": "CWE-306: Missing Authentication for Critical Function",
            "justification": "Known weakness class for this product family (expert experience).",
        }
    )
    return True


def stage_scrs(
    review: Review, approved_count: int, scrs_path: Path, report_path: Path, mode: str
) -> None:
    from scrp.state_manager import StateManager

    stage(
        8,
        "SHARED STATE (SCRS) AND AUDIT TRAIL",
        "Approved scenarios are persisted; every human decision is logged",
    )
    ok(f"{approved_count} approved scenarios written to {scrs_path.relative_to(_ROOT)}")
    sm = StateManager(scrs_path)
    log = sm.get_audit_log()
    counts = Counter(e.action for e in log)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", title="Audit log summary")
    t.add_column("Action")
    t.add_column("Entries", justify="right")
    for action in ("write", "approve", "reject", "revise", "prune", "add"):
        if counts[action]:
            t.add_row(action, str(counts[action]))
    console.print(t)
    hist = sm.get_revision_history(review.agent_input.run_id)
    info(
        f"Revision history rounds kept for this run: {len(hist)} "
        "(rejected and pruned content is never deleted)"
    )
    shown = [e for e in log if e.action in {"reject", "prune", "add"}]
    for e in shown[:6]:
        console.print(
            f"    [dim]{e.timestamp:%H:%M:%S}[/dim]  {e.action:<7} {e.tid}  "
            f"[dim]{short(e.reason or '', 70)}[/dim]"
        )

    report = {
        "run_id": review.agent_input.run_id,
        "mode": mode,
        "scenarios_approved": approved_count,
        "human_events": review.events,
        "audit_counts": dict(counts),
        "scenarios": [s.model_dump(mode="json") for s in review.scenarios],
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    ok(f"Run report saved to {report_path.relative_to(_ROOT)}")


def summary(args: argparse.Namespace) -> None:
    stage(9, "WHAT PHASE 1 DELIVERS")
    t = Table(box=box.SIMPLE_HEAD, header_style="bold")
    t.add_column("Capability")
    t.add_column("Status")
    done = [
        "Structured asset input, validated against a schema",
        "Outbound redaction of PII and secrets",
        "Retrieval over CAPEC, ATT&CK, CWE and STRIDE (2,300+ patterns, free sources)",
        "Per-pattern attack paths and scenario generation with cited evidence",
        "Protocol invariant validator plus grounding rules (no invented citations)",
        "Automatic retries on failed paths only (token-saving)",
        "Human gate: approve, reject-and-regenerate, prune, add expert scenario",
        "Shared state (SCRS) with audit log, non-overwrite history and traceability fields",
        "REST API with the same workflow, and 300+ automated tests",
    ]
    for d in done:
        t.add_row(d, "[green]complete[/green]")
    pending = [
        ("Team 1 asset-table adapter", "waiting for 4 fields from Team 1"),
        ("Expert relevance judgments / company internal patterns", "needs the company expert"),
        ("ISO/SAE 21434 and SESIP catalogues", "paid or unclear licence"),
        ("Multi-step attack chaining (kill-chain ordering)", "planned extension"),
        ("Phase 2: Risk Agent", "next phase"),
    ]
    for name, why in pending:
        t.add_row(name, f"[yellow]{why}[/yellow]")
    console.print(t)
    console.print("\n  Files written: [bold]demo_output/[/bold] (SCRS_demo.json, run_report.json)")
    console.print(
        "  [dim]Re-run with --mode live to use the model, --auto for a scripted run.[/dim]"
    )


# --------------------------------------------------------------------------------- main


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--mode",
        choices=["replay", "live"],
        default="replay",
        help="replay = recorded real model output (default); live = call the model",
    )
    parser.add_argument("--fixture", choices=list(FIXTURES), default="lock")
    parser.add_argument("--auto", action="store_true", help="scripted walkthrough, no typing")
    parser.add_argument("--no-pause", action="store_true", help="do not wait between stages")
    parser.add_argument(
        "--max-paths",
        type=int,
        default=12,
        help="attack paths to take through generation (default 12)",
    )
    parser.add_argument("--detail", type=int, default=2, help="scenarios shown in full (default 2)")
    parser.add_argument("--verbose", action="store_true", help="show internal JSON logs")
    args = parser.parse_args()

    if not args.verbose:
        logging.disable(logging.CRITICAL)
    if args.mode == "replay" and args.fixture != "lock":
        sys.exit("Replay data exists for the smart-door-lock fixture only; use --mode live.")

    from config.settings import get_settings

    settings = get_settings()
    if args.mode == "live" and not settings.OPENAI_API_KEY.get_secret_value():
        sys.exit("No OPENAI_API_KEY configured in .env; use the default --mode replay.")

    shutil.rmtree(OUT_DIR, ignore_errors=True)
    OUT_DIR.mkdir(parents=True)
    scrs_path = OUT_DIR / "SCRS_demo.json"
    report_path = OUT_DIR / "run_report.json"
    pacer = Pacer(enabled=not (args.no_pause or args.auto))

    banner(args, settings)
    agent_input = load_input(args.fixture)
    agent_input = agent_input.model_copy(update={"run_id": f"DEMO-{uuid.uuid4().hex[:6].upper()}"})
    pacer.wait("Press Enter to start")

    stage_perceive(agent_input)
    pacer.wait()
    candidates = stage_knowledge(agent_input, settings)
    pacer.wait()
    paths = stage_chaining(candidates, agent_input, args.max_paths)
    pacer.wait()
    scenarios, _retries, _status = stage_generation_and_validation(agent_input, paths, args.mode)
    if not scenarios:
        fail("No scenarios were produced; nothing to review.")
        sys.exit(1)
    pacer.wait()
    stage_validation(agent_input, scenarios, paths)
    pacer.wait()
    stage_review(scenarios, agent_input, args.detail)
    pacer.wait()

    from scrp.state_manager import StateManager

    review = Review(agent_input, scenarios, paths, args.mode, StateManager(scrs_path))
    if not stage_human_gate(review, args.auto):
        warn("Review ended without approval: nothing was written to the shared state.")
        return
    approved = review.approve_all()
    stage_scrs(review, approved, scrs_path, report_path, args.mode)
    summary(args)


if __name__ == "__main__":
    code = 0
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        code = 130
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (1 if exc.code else 0)
        if isinstance(exc.code, str):
            console.print(exc.code)
    sys.stdout.flush()
    # Exit without waiting for the database connection pool's background threads,
    # which otherwise print a harmless but untidy traceback on interpreter shutdown.
    os._exit(code)
