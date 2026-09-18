"""tests/threat_agent/e2e/test_infusion_pump_e2e.py
==============================================================================
TRC Engine — Phase 2  |  Infusion Pump Fixture: Permanent E2E Test
------------------------------------------------------------------------------
Gated E2E test for the Infusion Pump system model fixture.

This test exercises the full SCRP Threat Agent pipeline:
    build_retrieval_plan → fetch_candidates → build_paths
    → generate_scenarios → Validator (with retry loop)

Gate: TRC_INTEGRATION_TESTS=1  (requires live PostgreSQL via docker-compose)

Live LLM mode: set USE_LIVE_LLM=true for a full LLM-backed run.
Default (no flag or USE_LIVE_LLM=false): uses the deterministic fallback,
which guarantees validator-passing output without API cost.

Fixture location:
    tests/threat_agent/e2e/fixtures/infusion_pump/input.json

Bugs found and fixed during initial live run (2026-09-18):
  1. json.loads(strict=False) — handles LLM responses containing literal
     control characters (\\n, \\t) inside JSON string values.
  2. 'fabricat'/'fabricated' added to STRIDE_VECTOR_VOCABULARY[SPOOFING]
     so LLM phrase 'fabricated session credentials' passes CONSISTENCY_MISMATCH.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agents.threat_agent.orchestrator import generate_and_validate_with_retry
from agents.threat_agent.schemas import STRIDECategory, ThreatAgentInput

# ── Skip gate ────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.skipif(
    not os.getenv("TRC_INTEGRATION_TESTS"),
    reason="Requires live PostgreSQL container (set TRC_INTEGRATION_TESTS=1)",
)

# ── Fixture loading ───────────────────────────────────────────────────────────

_FIXTURE_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "infusion_pump"
    / "input.json"
)

_VALID_STRIDE_VALUES = {cat.value for cat in STRIDECategory}
_VALID_VALIDATION_STATUSES = {"passed", "escalated_after_retries"}

# ── Tests ─────────────────────────────────────────────────────────────────────


class TestInfusionPumpE2E:
    """End-to-end pipeline tests for the Infusion Pump fixture."""

    @pytest.fixture(scope="class")
    def infusion_pump_input(self) -> ThreatAgentInput:
        """Load and parse the Infusion Pump fixture."""
        raw = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
        return ThreatAgentInput(**raw)

    @pytest.fixture(scope="class")
    def pipeline_result(
        self, infusion_pump_input: ThreatAgentInput
    ) -> tuple:
        """Run the full pipeline once per class (cached) using deterministic mode.

        Using deterministic fallback (no live LLM call) so this test can
        run in CI without API cost or credit dependency.
        For a live-LLM run, set USE_LIVE_LLM=true before running pytest.
        """
        original_env = os.environ.get("USE_LIVE_LLM")
        # Default to deterministic for CI-stable test
        if os.environ.get("USE_LIVE_LLM", "").lower() not in ("true", "1", "yes"):
            os.environ["USE_LIVE_LLM"] = "false"
        try:
            return generate_and_validate_with_retry(infusion_pump_input)
        finally:
            if original_env is None:
                os.environ.pop("USE_LIVE_LLM", None)
            else:
                os.environ["USE_LIVE_LLM"] = original_env

    def test_pipeline_produces_scenarios(self, pipeline_result: tuple) -> None:
        """Pipeline must produce at least one ThreatScenario."""
        scenarios, _retries, _status = pipeline_result
        assert len(scenarios) > 0, "Expected at least one scenario from Infusion Pump fixture"

    def test_validation_status_is_terminal(self, pipeline_result: tuple) -> None:
        """validation_status must be 'passed' or 'escalated_after_retries'."""
        _scenarios, _retries, val_status = pipeline_result
        assert val_status in _VALID_VALIDATION_STATUSES, (
            f"Unexpected validation_status: {val_status!r}. "
            f"Expected one of {_VALID_VALIDATION_STATUSES}"
        )

    def test_all_scenarios_have_valid_asset_id(
        self, infusion_pump_input: ThreatAgentInput, pipeline_result: tuple
    ) -> None:
        """All generated scenarios must reference an asset_id from the input."""
        scenarios, _retries, _status = pipeline_result
        valid_asset_ids = {a.asset_id for a in infusion_pump_input.assets}
        for scenario in scenarios:
            assert scenario.asset_id in valid_asset_ids, (
                f"Scenario {scenario.tid} has unknown asset_id {scenario.asset_id!r}. "
                f"Valid IDs: {valid_asset_ids}"
            )

    def test_all_scenarios_have_valid_stride_category(
        self, pipeline_result: tuple
    ) -> None:
        """All generated scenarios must have a valid STRIDE category value."""
        scenarios, _retries, _status = pipeline_result
        for scenario in scenarios:
            assert scenario.stride_category.value in _VALID_STRIDE_VALUES, (
                f"Scenario {scenario.tid} has invalid STRIDE: "
                f"{scenario.stride_category!r}"
            )

    def test_all_scenarios_have_validation_status_field(
        self, pipeline_result: tuple
    ) -> None:
        """All scenario objects must carry validation_status from the orchestrator."""
        scenarios, _retries, _status = pipeline_result
        for scenario in scenarios:
            assert scenario.validation_status in _VALID_VALIDATION_STATUSES, (
                f"Scenario {scenario.tid} has validation_status "
                f"{scenario.validation_status!r}, expected one of "
                f"{_VALID_VALIDATION_STATUSES}"
            )

    def test_all_scenarios_have_kb_reference(self, pipeline_result: tuple) -> None:
        """All scenarios must have a non-empty kb_reference."""
        scenarios, _retries, _status = pipeline_result
        for scenario in scenarios:
            assert scenario.kb_reference and scenario.kb_reference.strip(), (
                f"Scenario {scenario.tid} has empty kb_reference"
            )

    def test_all_scenarios_have_non_empty_attack_vector(
        self, pipeline_result: tuple
    ) -> None:
        """All scenarios must have a non-empty attack_vector string."""
        scenarios, _retries, _status = pipeline_result
        for scenario in scenarios:
            assert scenario.attack_vector and scenario.attack_vector.strip(), (
                f"Scenario {scenario.tid} has empty attack_vector"
            )

    def test_all_scenarios_have_non_empty_citation(
        self, pipeline_result: tuple
    ) -> None:
        """All scenarios must have a non-empty evidence citation (CITATION_MISSING guard)."""
        scenarios, _retries, _status = pipeline_result
        for scenario in scenarios:
            citation = scenario.evidence_chain.citation.strip()
            assert citation, (
                f"Scenario {scenario.tid} has empty citation in evidence chain"
            )

    def test_confidence_scores_are_in_range(self, pipeline_result: tuple) -> None:
        """All confidence scores must be within [0.0, 1.0]."""
        scenarios, _retries, _status = pipeline_result
        for scenario in scenarios:
            assert 0.0 <= scenario.confidence_score <= 1.0, (
                f"Scenario {scenario.tid} confidence_score "
                f"{scenario.confidence_score} is out of range [0, 1]"
            )

    def test_both_assets_are_represented(
        self, infusion_pump_input: ThreatAgentInput, pipeline_result: tuple
    ) -> None:
        """Both AS-1 (Dosage Control) and AS-2 (Hospital Network) must appear."""
        scenarios, _retries, _status = pipeline_result
        expected_assets = {a.asset_id for a in infusion_pump_input.assets}
        covered_assets = {s.asset_id for s in scenarios}
        assert expected_assets <= covered_assets, (
            f"Not all assets covered. Missing: {expected_assets - covered_assets}"
        )

    def test_retry_count_within_bounds(self, pipeline_result: tuple) -> None:
        """validator_retry_count must be between 0 and 3 (MAX_VALIDATION_ATTEMPTS)."""
        _scenarios, retries, _status = pipeline_result
        assert 0 <= retries <= 3, (
            f"validator_retry_count {retries} is outside expected [0, 3] range"
        )
