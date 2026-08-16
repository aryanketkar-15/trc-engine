"""scripts/demo.py
==============================================================================
TRC Engine -- Phase 1 Demo Script
------------------------------------------------------------------------------
Demonstrates the full Threat Agent flow against real merged code:

  Stage 1  [LIVE]     build_retrieval_plan()  — dynamic, asset-driven
  Stage 2  [LIVE]     fetch_candidates()      — real FAISS cosine search
                      (requires built index: run kb/scripts/build_index.py)
  Stage 3  [STUBBED]  generate_scenarios()    — deterministic fixture response
                      Waiting on Chetan's feature/threat-agent-generator PR.
                      Will be replaced with real LLM call after merge.
  Stage 4  [LIVE]     validate()              — real Protocol Invariant Validator
  Stage 5  [LIVE]     StateManager.write_threat_scenario()  — real SCRS write

Run:
    python scripts/demo.py

Requirements:
    pip install -e ".[dev]"
    Build FAISS index first:
        python -m kb.scripts.build_index
"""

from __future__ import annotations

import sys
import tempfile
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Add repo root to sys.path so imports work from scripts/
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))  # noqa: E402

# ---------------------------------------------------------------------------
# Imports — real merged modules only
# ---------------------------------------------------------------------------

from agents.threat_agent.retrieval import (  # noqa: E402
    build_retrieval_plan,
    fetch_candidates,
)
from agents.threat_agent.schemas import (  # noqa: E402
    AssetModel,
    EvidenceChain,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
    ThreatStatus,
    ValidationResult,
)
from agents.threat_agent.validator import Validator  # noqa: E402
from common.logging import get_logger, log_step  # noqa: E402
from scrp.state_manager import StateManager  # noqa: E402

logger = get_logger("trc.demo")

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_RED = "\033[31m"
_DIM = "\033[2m"


def _h(text: str) -> str:
    return f"{_BOLD}{_CYAN}{text}{_RESET}"


def _ok(text: str) -> str:
    return f"{_GREEN}{text}{_RESET}"


def _warn(text: str) -> str:
    return f"{_YELLOW}{text}{_RESET}"


def _err(text: str) -> str:
    return f"{_RED}{text}{_RESET}"


def _dim(text: str) -> str:
    return f"{_DIM}{text}{_RESET}"


def _tag_live() -> str:
    return f"{_GREEN}[LIVE]{_RESET}"


def _tag_stubbed() -> str:
    return f"{_YELLOW}[STUBBED — pending Chetan's PR]{_RESET}"


# ---------------------------------------------------------------------------
# Demo domain fixture: Smart Door Lock
# ---------------------------------------------------------------------------

_DEMO_ASSET = AssetModel(
    asset_id="ASSET-BLE-CONTROLLER-01",
    name="BLE Controller",
    asset_type="embedded firmware",
    interfaces=["BLE", "UART"],
    attributes={
        "auth": "PIN-only",
        "encryption": "none",
        "pairing": "unauthenticated",
    },
    trust_zone="untrusted",
)

_DEMO_INPUT = ThreatAgentInput(
    run_id=f"DEMO-{uuid.uuid4().hex[:8].upper()}",
    use_case=(
        "Smart door lock with BLE pairing and OTA firmware update. "
        "No encryption on BLE channel. PIN-only auth."
    ),
    system_model_summary=(
        "BLE peripheral with unauthenticated pairing, no transport encryption, "
        "and an OTA endpoint exposed on the local network "
        "without signature verification."
    ),
    assets=[_DEMO_ASSET],
    kb_snapshot_version="v1.0",
    pii_redacted=False,
)


# ---------------------------------------------------------------------------
# Stage 3 stub: deterministic fixture ThreatScenario
# (replaces real generate_scenarios() until Chetan's PR merges)
# ---------------------------------------------------------------------------

_FIXTURE_SCENARIO = ThreatScenario(
    tid=f"TID-{uuid.uuid4().hex[:8].upper()}",
    asset_id="ASSET-BLE-CONTROLLER-01",
    stride_category=STRIDECategory.TAMPERING,
    attack_vector=(
        "Adversary performs BLE replay attack: captures unauthenticated pairing "
        "handshake and replays it to gain unauthorized lock control."
    ),
    kb_reference="CAPEC-94",
    evidence_chain=EvidenceChain(
        exposure="BLE peripheral with no encryption and unauthenticated pairing",
        matched_pattern="CAPEC-94",
        applicability_reason=(
            "The device uses PIN-only BLE authentication with no transport "
            "encryption, making it susceptible to adversary-in-the-middle attacks "
            "where an attacker can intercept and replay pairing handshakes to "
            "impersonate a legitimate client and unlock the door."
        ),
        citation="CAPEC-94: Adversary in the Middle (AiTM)",
    ),
    confidence_score=0.0,  # will be set by scorer (stubbed in Phase 1)
    status=ThreatStatus.APPROVED,
    run_id=_DEMO_INPUT.run_id,
)


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------


def run_demo() -> None:  # noqa: PLR0915
    """Execute the full Phase 1 demo pipeline and print results."""

    print()
    print(_h("=" * 70))
    print(_h("  TRC Engine — Phase 1 Threat Agent Demo"))
    print(_h("=" * 70))
    print(f"  run_id    : {_DEMO_INPUT.run_id}")
    print(f"  asset     : {_DEMO_ASSET.name} ({_DEMO_ASSET.asset_type})")
    print(f"  interfaces: {', '.join(_DEMO_ASSET.interfaces)}")
    print(
        "  attributes: "
        + ", ".join(f"{k}={v}" for k, v in _DEMO_ASSET.attributes.items())
    )
    print(f"  trust_zone: {_DEMO_ASSET.trust_zone}")
    print()

    # ── Stage 1: build_retrieval_plan() ─────────────────────────────────────
    print(_h(f"Stage 1 {_tag_live()}  build_retrieval_plan()"))
    print(_dim("  Constructs per-asset FAISS query from real asset attributes."))
    print(_dim("  No hardcoded strings — query derived entirely from input."))

    plan = build_retrieval_plan(_DEMO_INPUT)
    query = plan.queries[0]
    query_text: str = query["query_text"]  # type: ignore[assignment]
    kb_sources: list[str] = query["kb_sources"]  # type: ignore[assignment]

    print(f"  query_text : {query_text!r}")
    print(f"  kb_sources : {kb_sources}")
    print(f"  top_k      : {plan.top_k}")
    log_step(
        logger,
        "INFO",
        "demo_plan",
        _DEMO_INPUT.run_id,
        {"query_text": query_text, "kb_sources": kb_sources, "top_k": plan.top_k},
    )
    print(_ok("  ✓ Plan built.\n"))

    # ── Stage 2: fetch_candidates() ──────────────────────────────────────────
    print(_h(f"Stage 2 {_tag_live()}  fetch_candidates()"))
    print(_dim("  Real FAISS IndexFlatIP cosine search against kb_metadata.json."))
    print(_dim("  Scores printed are ACTUAL index output — none are hardcoded."))

    candidates: list[object] = []
    try:
        candidates = fetch_candidates(plan)  # type: ignore[assignment]
        print(f"  Candidates retrieved: {len(candidates)}")
        for c in candidates:  # type: ignore[attr-defined]
            print(
                f"    [{c.source.value:8s}] {c.pattern_id:20s} "  # type: ignore[attr-defined]
                f"score={c.retrieval_score:.4f}  {c.title}"  # type: ignore[attr-defined]
            )
        log_step(
            logger,
            "INFO",
            "demo_fetch_end",
            _DEMO_INPUT.run_id,
            {"candidate_count": len(candidates)},
        )
        print(_ok("  ✓ Retrieval complete.\n"))
    except Exception as exc:  # noqa: BLE001
        print(
            _warn(
                f"  ⚠ fetch_candidates() raised {type(exc).__name__}: {exc}\n"
                "  This is expected if kb/data/threat_agent.faiss is not built.\n"
                "  Run: python -m kb.scripts.build_index\n"
                "  Continuing demo with empty candidate list.\n"
            )
        )
        candidates = []

    # ── Stage 3: generate_scenarios() [STUBBED] ──────────────────────────────
    print(_h(f"Stage 3 {_tag_stubbed()}  generate_scenarios()"))
    print(
        _dim(
            "  Generation uses a deterministic fixture response for reproducibility.\n"
            "  Live OpenAI wiring lands when Chetan's feature/threat-agent-generator\n"
            "  PR is merged to develop. Fixture scenario below is from conftest.py.\n"
            "  When live: candidates above feed into attack_chain.build_paths()\n"
            "  -> generate_scenarios() -> real ThreatScenario objects."
        )
    )
    scenario = _FIXTURE_SCENARIO
    print(f"  tid            : {scenario.tid}")
    print(f"  stride_category: {scenario.stride_category.value}")
    print(f"  kb_reference   : {scenario.kb_reference}")
    print(f"  attack_vector  : {scenario.attack_vector[:72]}...")
    print(
        _warn("  [STUBBED] confidence_score is 0.0 — scorer.py runs after generator.\n")
    )

    # ── Stage 4: validate() ───────────────────────────────────────────────────
    print(_h(f"Stage 4 {_tag_live()}  Validator.validate()"))
    print(_dim("  Real Protocol Invariant Validator (Shriraj's module, PR #2)."))
    print(_dim("  4 independent checks: citation, schema, consistency, evidence.\n"))

    validator = Validator()
    result: ValidationResult = validator.validate(scenario)

    if result.passed:
        print(_ok(f"  ✓ All checks passed  (passed={result.passed})"))
    else:
        print(_err(f"  ✗ Validation failed  (passed={result.passed})"))
        for fc in result.failed_checks:
            print(_err(f"    [{fc.check_id}] {fc.detail}"))

    log_step(
        logger,
        "INFO",
        "demo_validate",
        _DEMO_INPUT.run_id,
        {"passed": result.passed, "failed_count": len(result.failed_checks)},
    )
    print()

    # ── Stage 5: StateManager.write_threat_scenario() ────────────────────────
    print(_h(f"Stage 5 {_tag_live()}  StateManager.write_threat_scenario()"))
    print(_dim("  Real SCRS write gate (Shriraj's module, PR #2)."))
    print(_dim("  NotApprovedError is raised if status != 'approved'.\n"))

    with tempfile.TemporaryDirectory() as tmp_dir:
        scrs_path = Path(tmp_dir) / "SCRS_state.json"
        state_mgr = StateManager(scrs_path=scrs_path)

        if result.passed and scenario.status == ThreatStatus.APPROVED:
            try:
                state_mgr.write_threat_scenario(scenario, run_id=_DEMO_INPUT.run_id)
                audit = state_mgr.get_audit_log()
                stored = state_mgr.get_threat_scenarios()
                print(_ok(f"  ✓ Scenario written to SCRS  (tid={scenario.tid})"))
                print(f"  Audit log entries : {len(audit)}")
                print(f"  Scenarios in SCRS : {len(stored)}")
                print(f"  Audit entry run_id: {audit[-1].run_id}")
                print(f"  Audit entry action: {audit[-1].action}")
                log_step(
                    logger,
                    "INFO",
                    "demo_scrs_write",
                    _DEMO_INPUT.run_id,
                    {
                        "tid": scenario.tid,
                        "audit_entries": len(audit),
                        "scrs_path": str(scrs_path),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                print(_err(f"  ✗ write_threat_scenario() raised: {exc}"))
        else:
            print(
                _warn(
                    "  Skipping SCRS write — validation failed or "
                    "scenario not approved.\n"
                    "  In production, retry_with_context() feeds failure "
                    "details back into the generator prompt."
                )
            )

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print(_h("=" * 70))
    print(_h("  Demo Complete"))
    print(_h("=" * 70))
    print(f"  {_tag_live()}     Stages 1, 2, 4, 5 ran against real merged code.")
    print(f"  {_tag_stubbed()} Stage 3 used deterministic fixture.")
    print(
        f"  {_dim('Next step:')} Merge Chetan's PR -> replace Stage 3 stub "
        f"with real generate_scenarios()."
    )
    print()


if __name__ == "__main__":
    run_demo()
