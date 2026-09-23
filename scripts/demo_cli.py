"""
scripts/demo_cli.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent Demonstration CLI
──────────────────────────────────────────────────────────────────────────────
Live pipeline demonstration script for HOD Progress Review (Group TY-A9).

Executes the deterministic SCRP Threat Agent pipeline against live code:
  1. Fixture Selection (Smart Door Lock vs. Infusion Pump)
  2. Retrieval Plan Generation (build_retrieval_plan)
  3. Vector DB Search (fetch_candidates via FAISS cosine similarity)
  4. Multi-Step Attack Chaining (attack_chain.build_paths)
  5. Threat Scenario Assembly (generate_scenarios via deterministic fixture)
  6. Protocol Invariant Validation (validator.validate)
  7. Human-in-the-Loop Approval Gate (StateManager.write_threat_scenario)
  8. Structured JSON Audit Log Inspection

Usage:
  python scripts/demo_cli.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure the project root is in sys.path so we can import 'agents', 'config', etc.
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception as _enc_err:
        # Non-fatal: fall back to the default console encoding
        import logging as _log

        _log.getLogger(__name__).debug("stdout reconfigure failed: %s", _enc_err)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from agents.threat_agent.attack_chain import build_paths, build_single_step_path
from agents.threat_agent.generator import generate_scenarios
from agents.threat_agent.orchestrator import (
    MAX_VALIDATION_ATTEMPTS,
    regenerate_after_human_rejection,
)
from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
from agents.threat_agent.router import MAX_HUMAN_REJECTIONS
from agents.threat_agent.schemas import (
    AssetModel,
    DFDContext,
    SecurityAttributes,
    ThreatAgentInput,
    ThreatStatus,
)
from agents.threat_agent.scorer import LOW_CONFIDENCE_THRESHOLD
from agents.threat_agent.validator import Validator
from common.logging import get_logger, log_step
from config.settings import get_settings
from scrp.state_manager import StateManager

logger = get_logger("demo_cli")
console = Console() if RICH_AVAILABLE else None


def print_banner() -> None:
    """Print the demonstration banner."""
    title = "TRC Engine — Phase 1 Threat Agent Demonstration"
    subtitle = "HOD Review Walkthrough | Group TY-A9 | SCRP Reasoning Loop"
    if console:
        console.print(
            Panel.fit(
                f"[bold cyan]{title}[/bold cyan]\n[dim]{subtitle}[/dim]",
                border_style="cyan",
            )
        )
    else:
        print("=" * 70)
        print(f"  {title}")
        print(f"  {subtitle}")
        print("=" * 70)


def load_smart_door_lock_input() -> ThreatAgentInput:
    """Return Fixture 1: Smart Door Lock ThreatAgentInput."""
    fixture_path = (
        Path(__file__).parent.parent
        / "tests"
        / "threat_agent"
        / "e2e"
        / "fixtures"
        / "smart_door_lock"
        / "input.json"
    )
    if fixture_path.exists():
        return ThreatAgentInput.model_validate_json(
            fixture_path.read_text(encoding="utf-8")
        )

    return ThreatAgentInput(
        run_id="DEMO-SDL-001",
        use_case=(
            "Consumer smart door lock with BLE unlock, cloud management, and OTA updates."
        ),
        system_model=(
            '{"trust_boundaries": ["phone-lock BLE", "lock-cloud TLS"], '
            '"data_flows": ["unlock_command", "ota_update", "e_key_sync"]}'
        ),
        assets=[
            AssetModel(
                asset_id="AS-1",
                name="BLE Controller",
                asset_type="embedded firmware",
                location="on-device",
                security_attributes=SecurityAttributes(
                    confidentiality=False, integrity=True,
                    availability=True, authenticity=True,
                ),
                damage_scenario=(
                    "Unauthorised physical entry to premises via BLE replay or spoofing."
                ),
                dfd_context=DFDContext(
                    interfaces=["BLE 5.0", "GATT"],
                    trust_zone="untrusted",
                    data_flows=["unlock_command"],
                ),
                device_config={
                    "auth": "PIN-only",
                    "encryption": "none",
                    "pairing": "unauthenticated",
                },
            ),
            AssetModel(
                asset_id="AS-2",
                name="Secure Element",
                asset_type="hardware security module",
                location="on-device",
                security_attributes=SecurityAttributes(
                    confidentiality=True, integrity=True,
                    availability=False, authenticity=True,
                ),
                damage_scenario=(
                    "Cryptographic key exfiltration enabling permanent device compromise."
                ),
                dfd_context=DFDContext(
                    interfaces=["I2C", "SPI"],
                    trust_zone="trusted",
                    data_flows=[],
                ),
                device_config={"key_storage": "persistent", "tamper": "physical"},
            ),
            AssetModel(
                asset_id="AS-3",
                name="Cloud Backend",
                asset_type="cloud api server",
                location="cloud-hosted",
                security_attributes=SecurityAttributes(
                    confidentiality=True, integrity=True,
                    availability=True, authenticity=True,
                ),
                damage_scenario="Mass compromise of all registered locks via cloud API takeover.",
                dfd_context=DFDContext(
                    interfaces=["HTTPS", "REST", "WebSocket"],
                    trust_zone="external",
                    data_flows=["ota_update", "e_key_sync"],
                ),
                device_config={"auth": "JWT", "rate_limiting": "none"},
            ),
        ],
    )


def load_infusion_pump_input() -> ThreatAgentInput:
    """Return Fixture 2: Medical Infusion Pump ThreatAgentInput."""
    fixture_path = (
        Path(__file__).parent.parent
        / "tests"
        / "threat_agent"
        / "e2e"
        / "fixtures"
        / "infusion_pump"
        / "input.json"
    )
    if fixture_path.exists():
        return ThreatAgentInput.model_validate_json(
            fixture_path.read_text(encoding="utf-8")
        )

    return ThreatAgentInput(
        run_id="DEMO-INF-001",
        use_case=(
            "Connected hospital infusion pump with remote dosage control and EMR integration."
        ),
        system_model=(
            '{"trust_boundaries": ["pump-nurse BLE", "pump-hospital VLAN"], '
            '"data_flows": ["dosage_command", "alarm_event", "firmware_update"]}'
        ),
        assets=[
            AssetModel(
                asset_id="AS-1",
                name="Dosage Control Firmware",
                asset_type="safety-critical embedded firmware",
                location="on-device",
                security_attributes=SecurityAttributes(
                    confidentiality=False, integrity=True,
                    availability=True, authenticity=True,
                ),
                damage_scenario=(
                    "Incorrect drug dosage delivered to patient due to firmware tampering."
                ),
                dfd_context=DFDContext(
                    interfaces=["UART", "CAN bus"],
                    trust_zone="trusted",
                    data_flows=["dosage_command", "firmware_update"],
                ),
                device_config={
                    "safety_level": "SIL-2",
                    "update_auth": "no-verify",
                },
            ),
            AssetModel(
                asset_id="AS-2",
                name="Hospital Network Interface",
                asset_type="network endpoint",
                location="internal VLAN",
                security_attributes=SecurityAttributes(
                    confidentiality=True, integrity=True,
                    availability=True, authenticity=False,
                ),
                damage_scenario=(
                    "Lateral movement through flat hospital network enabling attack "
                    "on life-critical systems."
                ),
                dfd_context=DFDContext(
                    interfaces=["Ethernet", "HL7 FHIR REST API"],
                    trust_zone="external",
                    data_flows=["alarm_event", "dosage_command"],
                ),
                device_config={"segmentation": "flat", "auth": "basic"},
            ),
        ],
    )


def display_assets(agent_input: ThreatAgentInput) -> None:
    """Display system model assets."""
    if console:
        title = f"System Model Assets ({agent_input.use_case[:45]}...)"
        table = Table(title=title, border_style="blue")
        table.add_column("Asset ID", style="bold yellow")
        table.add_column("Name", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Interfaces", style="magenta")
        table.add_column("Trust Zone", style="green")
        table.add_column("Device Config", style="dim")

        for asset in agent_input.assets:
            table.add_row(
                asset.asset_id,
                asset.name,
                asset.asset_type,
                ", ".join(asset.interfaces),
                asset.trust_zone,
                json.dumps(asset.device_config or {}),
            )
        console.print(table)
    else:
        print("\n--- System Model Assets ---")
        for asset in agent_input.assets:
            print(
                f"[{asset.asset_id}] {asset.name} ({asset.asset_type}) | Zone: {asset.trust_zone}"
            )


def _mock_llm_fallback(system_prompt: str, user_prompt: str, run_id: str) -> str:
    """Return a deterministic, schema-compliant JSON response for demo reproducibility."""
    return json.dumps(
        [
            {
                "asset_id": "ASSET-BLE-01",
                "stride_category": "Spoofing",
                "attack_vector": "Unauthenticated GATT pairing replay attack on BLE Controller",
                "kb_reference": "CAPEC-186",
                "title": "BLE GATT Pairing Replay Attack",
                "description": (
                    "An attacker within BLE radio range replays previously captured "
                    "pairing requests to compromise the controller."
                ),
                "exposure": "BLE 5.0 GATT interface with PIN-only unauthenticated pairing",
                "matched_pattern": "CAPEC-186 (Malicious Software Update / Replay)",
                "applicability_reason": (
                    "PIN-only unauthenticated pairing allows an attacker within radio range "
                    "to eavesdrop and replay GATT frames."
                ),
                "citation": "CAPEC-186",
            }
        ]
    )


def run_demo() -> None:
    """Execute the full interactive CLI demonstration."""
    print_banner()

    # Step 1: Fixture Selection
    if console:
        choice = Prompt.ask(
            "\n[bold yellow]Select Domain Fixture for Demonstration[/bold yellow]",
            choices=["1", "2"],
            default="1",
        )
    else:
        print("\nSelect Domain Fixture:")
        print(" 1. Smart Door Lock (BLE/Cloud IoT)")
        print(" 2. Infusion Pump (Medical Device)")
        choice = input("Enter choice [1/2] (default 1): ").strip() or "1"

    if choice == "2":
        agent_input = load_infusion_pump_input()
        fixture_name = "Medical Infusion Pump (Domain 2)"
    else:
        agent_input = load_smart_door_lock_input()
        fixture_name = "Smart Door Lock (Domain 1)"

    if console:
        console.print(f"\n[bold green][+] Loaded Fixture:[/bold green] {fixture_name}")
    else:
        print(f"\n[+] Loaded Fixture: {fixture_name}")

    display_assets(agent_input)

    # Step 2: Build Retrieval Plan
    if console:
        console.print("\n[bold cyan]Stage 1: Building Retrieval Plan...[/bold cyan]")
    else:
        print("\n--- Stage 1: Building Retrieval Plan ---")

    try:
        plan = build_retrieval_plan(agent_input, top_k=5)
        if console:
            p_table = Table(
                title="Generated Search Queries (build_retrieval_plan)",
                border_style="cyan",
            )
            p_table.add_column("Asset ID", style="bold yellow")
            p_table.add_column("Derived Search Query", style="white")
            p_table.add_column("Target KB Sources", style="magenta")
            for q in plan.queries:
                asset_id = str(q.get("asset_id", ""))
                query_text = str(q.get("query_text", ""))
                kb_sources = q.get("kb_sources", [])
                sources_str = ", ".join(str(s) for s in kb_sources)
                p_table.add_row(asset_id, query_text, sources_str)
            console.print(p_table)
        else:
            for q in plan.queries:
                asset_id = str(q.get("asset_id", ""))
                query_text = str(q.get("query_text", ""))
                kb_sources = q.get("kb_sources", [])
                print(f"Query for {asset_id}: '{query_text}' -> Sources: {kb_sources}")
    except Exception as exc:
        print(f"[ERROR] Failed to build retrieval plan: {exc}")
        sys.exit(1)

    # Step 3: Execute FAISS Retrieval
    if console:
        console.print("\n[bold cyan]Stage 2: Executing Live pgvector Search...[/bold cyan]")
    else:
        print("\n--- Stage 2: Executing Live pgvector Search ---")

    try:
        candidates = fetch_candidates(plan)
        if console:
            c_table = Table(
                title=f"Retrieved KB Candidates ({len(candidates)} candidates)",
                border_style="cyan",
            )
            c_table.add_column("Pattern ID", style="bold yellow")
            c_table.add_column("Source", style="magenta")
            c_table.add_column("Cosine Score", style="bold green")
            c_table.add_column("Pattern Title", style="white")
            for c in candidates[:8]:
                c_table.add_row(
                    c.pattern_id,
                    c.source,
                    f"{c.retrieval_score:.4f}",
                    c.title,
                )
            console.print(c_table)
        else:
            for c in candidates[:5]:
                print(
                    f"Matched {c.pattern_id} [{c.source}] "
                    f"(Score: {c.retrieval_score:.4f}): {c.title}"
                )
    except Exception as exc:
        print(f"[ERROR] FAISS Retrieval failed: {exc}")
        sys.exit(1)

    # Step 4: Attack Chain Analysis
    if console:
        console.print("\n[bold cyan]Stage 3: Building Attack Chains...[/bold cyan]")
    else:
        print("\n--- Stage 3: Building Attack Chains ---")

    try:
        try:
            paths = build_paths(candidates, agent_input)
        except NotImplementedError:
            paths = [build_single_step_path(c) for c in candidates]
        if console:
            path_table = Table(
                title=f"Generated Attack Paths ({len(paths)} paths)",
                border_style="cyan",
            )
            path_table.add_column("Path ID", style="bold yellow")
            path_table.add_column("Sequence", style="magenta")
            path_table.add_column("Chain Confidence", style="bold green")
            path_table.add_column("STRIDE Transitions", style="white")
            for p in paths[:5]:
                step_ids = " -> ".join([s.pattern_id for s in p.steps])
                strides = " -> ".join([str(s.stride_hint or "N/A") for s in p.steps])
                path_table.add_row(
                    p.path_id,
                    step_ids,
                    f"{p.chain_confidence:.4f}",
                    strides,
                )
            console.print(path_table)
        else:
            for p in paths[:3]:
                print(
                    f"Path {p.path_id} (Confidence: {p.chain_confidence:.4f}): "
                    f"{[s.pattern_id for s in p.steps]}"
                )
    except Exception as exc:
        print(f"[ERROR] Attack Chaining failed: {exc}")
        sys.exit(1)

    # Step 5: Threat Scenario Assembly
    use_live_llm = getattr(get_settings(), "USE_LIVE_LLM", True)
    if os.environ.get("USE_LIVE_LLM", "").lower() in ("false", "0", "no"):
        use_live_llm = False

    if not use_live_llm:
        disclosure_msg = (
            "[bold yellow][DISCLOSURE] Stage 4: Scenario Generation running in deterministic "
            "mode (USE_LIVE_LLM=false) for presentation stability.[/bold yellow]"
        )
        if console:
            console.print(f"\n{disclosure_msg}")
        else:
            print("\n[DISCLOSURE] Scenario generation running in deterministic mode.")

    if console:
        console.print("[bold cyan]Stage 4: Assembling Threat Scenarios...[/bold cyan]")
    else:
        print("--- Stage 4: Assembling Threat Scenarios ---")

    try:
        scenarios = generate_scenarios(paths, agent_input)
        if console:
            console.print(
                f"[bold green][+] Generated {len(scenarios)} ThreatScenarios.[/bold green]"
            )
            if scenarios:
                s = scenarios[0]
                console.print(
                    Panel(
                        f"[bold white]TID:[/bold white] {s.tid}\n"
                        f"[bold white]Asset:[/bold white] {s.asset_id}\n"
                        f"[bold white]STRIDE:[/bold white] {s.stride_category}\n"
                        f"[bold white]Attack Vector:[/bold white] {s.attack_vector}\n"
                        f"[bold white]KB Reference:[/bold white] {s.kb_reference}\n"
                        f"[bold white]Confidence Score:[/bold white] {s.confidence_score:.4f}",
                        title="Sample ThreatScenario (Top Candidate)",
                        border_style="green",
                    )
                )
    except Exception as exc:
        print(f"[ERROR] Scenario Generation failed: {exc}")
        sys.exit(1)

    if not scenarios:
        print("[WARNING] No scenarios generated.")
        return

    # Step 6: Protocol Invariant Validation
    if console:
        console.print("\n[bold cyan]Stage 5: Running Protocol Invariant Validator...[/bold cyan]")
    else:
        print("\n--- Stage 5: Running Protocol Invariant Validator ---")

    try:
        target_scenario = scenarios[0]
        v_result = Validator().validate(target_scenario)
        if console:
            status_str = "PASSED" if v_result.passed else "FAILED"
            color = "bold green" if v_result.passed else "bold red"
            console.print(f"Validation Status: [{color}]{status_str}[/{color}]")
            total_checks = 4  # Citation, Schema, Consistency, Evidence
            passed_count = total_checks - len(v_result.failed_checks)
            console.print(f"Checks Passed: [green]{passed_count}/{total_checks}[/green]")
            if v_result.failed_checks:
                for fc in v_result.failed_checks:
                    console.print(f"  [red][-] Check Failed ({fc.check_id}):[/red] {fc.detail}")
            else:
                console.print("  [bold green][+] Citation Presence Check: PASSED[/bold green]")
                console.print("  [bold green][+] Schema Completeness Check: PASSED[/bold green]")
                console.print("  [bold green][+] STRIDE Consistency Check: PASSED[/bold green]")
                console.print("  [bold green][+] Evidence Completeness Check: PASSED[/bold green]")
        else:
            print(
                f"Validation Result: Passed={v_result.passed}, "
                f"Failed Checks={len(v_result.failed_checks)}"
            )
    except Exception as exc:
        print(f"[ERROR] Validation failed: {exc}")
        sys.exit(1)

    # Step 7: Human-in-the-Loop Approval & SCRS Persistence
    # Mirrors the reject -> reason -> regenerate -> re-validate -> re-review
    # loop wired into router.reject_run() (MAX_HUMAN_REJECTIONS attempts before
    # escalating to a terminal rejection).
    rejection_count = 0
    approve = "n"

    while True:
        conf = target_scenario.confidence_score
        is_low_conf = conf < LOW_CONFIDENCE_THRESHOLD

        if console:
            console.print(
                "\n[bold cyan]Stage 6: Human-in-the-Loop Approval Gate[/bold cyan]"
            )
            if is_low_conf:
                console.print(
                    f"  [bold red]⚠ LOW CONFIDENCE: {conf:.4f} "
                    f"(below threshold {LOW_CONFIDENCE_THRESHOLD})[/bold red]"
                )
            else:
                console.print(f"  Confidence Score: [bold green]{conf:.4f}[/bold green]")

            prompt_text = (
                f"Approve ThreatScenario [bold yellow]{target_scenario.tid}[/bold yellow] "
                f"(Confidence: {conf:.4f}) for SCRS?"
            )
            approve = Prompt.ask(prompt_text, choices=["y", "n"], default="y")
        else:
            warn_text = (
                f" [⚠ LOW CONFIDENCE: {conf:.4f}]"
                if is_low_conf
                else f" [Confidence: {conf:.4f}]"
            )
            prompt_msg = (
                f"\nApprove ThreatScenario {target_scenario.tid}{warn_text} "
                f"for SCRS? [y/n] (default y): "
            )
            approve = input(prompt_msg).strip() or "y"

        if approve.lower() == "y":
            try:
                target_scenario = target_scenario.model_copy(
                    update={"status": ThreatStatus.APPROVED}
                )
                state_mgr = StateManager()
                state_mgr.write_threat_scenario(
                    target_scenario, run_id=agent_input.run_id
                )
                if console:
                    console.print(
                        f"[bold green][+] Scenario {target_scenario.tid} "
                        "written to SCRS![/bold green]"
                    )
                else:
                    print(f"[+] ThreatScenario {target_scenario.tid} written to SCRS!")
            except Exception as exc:
                print(f"[ERROR] Failed to write to SCRS: {exc}")
            break

        # Rejected — collect a reason, log it, and regenerate (bounded retry).
        rejection_count += 1
        reason_prompt = "Reason for rejection"
        reason = (
            Prompt.ask(f"[bold yellow]{reason_prompt}[/bold yellow]")
            if console
            else input(f"{reason_prompt}: ").strip()
        )
        reason = reason or "No reason provided."

        try:
            StateManager().log_rejection(
                run_id=agent_input.run_id,
                reason=reason,
                rejected_scenarios=[target_scenario],
            )
        except Exception as exc:
            logger.warning("Failed to log rejection to SCRS: %s", exc)

        if rejection_count >= MAX_HUMAN_REJECTIONS:
            target_scenario = target_scenario.model_copy(
                update={"status": ThreatStatus.REJECTED}
            )
            msg = (
                f"[-] Scenario {target_scenario.tid} rejected {rejection_count} "
                "time(s) — retry cap reached, escalating without further "
                "regeneration."
            )
            if console:
                console.print(f"[bold red]{msg}[/bold red]")
            else:
                print(msg)
            break

        regen_msg = (
            f"[cyan]Regenerating with reviewer feedback "
            f"(attempt {rejection_count + 1}/{MAX_HUMAN_REJECTIONS})...[/cyan]"
        )
        print(regen_msg) if not console else console.print(regen_msg)

        try:
            new_scenarios, _val_retries, batch_val_status = regenerate_after_human_rejection(
                agent_input=agent_input,
                human_feedback=reason,
                previous_scenarios=[target_scenario],
            )
        except Exception as exc:
            print(f"[ERROR] Regeneration after rejection failed: {exc}")
            break

        if not new_scenarios:
            print("[WARNING] Regeneration produced no scenarios; stopping.")
            break

        target_scenario = new_scenarios[0]

        # Show the reviewer what actually changed — without this, "PASSED"
        # is meaningless: they can't tell regeneration produced new content
        # (vs. re-showing the same rejected scenario) without seeing it.
        s = target_scenario
        if console:
            console.print(
                Panel(
                    f"[bold white]TID:[/bold white] {s.tid}\n"
                    f"[bold white]Asset:[/bold white] {s.asset_id}\n"
                    f"[bold white]STRIDE:[/bold white] {s.stride_category}\n"
                    f"[bold white]Attack Vector:[/bold white] {s.attack_vector}\n"
                    f"[bold white]KB Reference:[/bold white] {s.kb_reference}\n"
                    f"[bold white]Confidence Score:[/bold white] "
                    f"{s.confidence_score:.4f}",
                    title="Revised ThreatScenario (after your feedback)",
                    border_style="yellow",
                )
            )
        else:
            print(
                f"Revised ThreatScenario -> TID: {s.tid} | Asset: {s.asset_id} | "
                f"STRIDE: {s.stride_category} | Attack Vector: {s.attack_vector} | "
                f"KB Reference: {s.kb_reference} | "
                f"Confidence: {s.confidence_score:.4f}"
            )

        v_result = Validator().validate(target_scenario)
        revalidate_msg = (
            f"Revalidation Status: {'PASSED' if v_result.passed else 'FAILED'} "
            f"({4 - len(v_result.failed_checks)}/4 checks)"
        )
        if console:
            color = "bold green" if v_result.passed else "bold red"
            console.print(f"[{color}]{revalidate_msg}[/{color}]")
        else:
            print(revalidate_msg)

        # Surface the *batch's* validation_status too: the reviewed candidate
        # can individually pass while sibling candidates from the same
        # regeneration round were escalated after exhausting machine retries.
        #
        # NOTE: generate_and_validate_with_retry() stamps validation_status
        # onto every scenario in the batch uniformly when escalation occurs
        # (see orchestrator.py), so that field can't distinguish "this one
        # actually failed a check" from "this one shipped alongside a
        # failure." Re-validate each sibling individually instead of
        # trusting the coarse batch-wide label.
        if batch_val_status == "escalated_after_retries":
            actually_failed = sum(
                1
                for s in new_scenarios
                if s.tid != target_scenario.tid and not Validator().validate(s).passed
            )
            batch_msg = (
                "[!] Batch validation status: escalated_after_retries "
                f"({actually_failed} of {len(new_scenarios) - 1} other "
                "candidate(s) in this regeneration round failed an invariant "
                f"check after {MAX_VALIDATION_ATTEMPTS} attempts — reviewed "
                "here only, not shown to you)."
            )
            if console:
                console.print(f"[bold yellow]{batch_msg}[/bold yellow]")
            else:
                print(batch_msg)

    # Step 8: Tail Structured JSON Logs
    if console:
        console.print("\n[bold cyan]Stage 7: Structured JSON Audit Logs[/bold cyan]")
    else:
        print("\n--- Stage 7: Structured JSON Audit Logs ---")

    log_step(
        logger,
        "INFO",
        "demo_run_completed",
        agent_input.run_id,
        {
            "fixture": fixture_name,
            "approved": approve.lower() == "y",
            "tid": target_scenario.tid,
        },
    )

    log_file = Path("trc_engine.log")
    if log_file.exists():
        try:
            lines = log_file.read_text(encoding="utf-8").strip().splitlines()
            tail_lines = lines[-5:]
            if console:
                for line in tail_lines:
                    try:
                        parsed = json.loads(line)
                        console.print_json(data=parsed)
                    except json.JSONDecodeError:
                        console.print(f"[dim]{line}[/dim]")
            else:
                for line in tail_lines:
                    print(line)
        except Exception as exc:
            print(f"[NOTE] Could not read log tail: {exc}")

    if console:
        console.print("\n[bold green][*] Demonstration Completed Successfully![/bold green]\n")
    else:
        print("\nDemonstration Walkthrough Completed Successfully!\n")


if __name__ == "__main__":
    run_demo()
