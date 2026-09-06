"""
tests/threat_agent/unit/test_scorer.py
───────────────────────────────────────
Unit tests for agents/threat_agent/scorer.py.

Verifies:
  1. Output is strictly clamped within [0.0, 1.0].
  2. Low-similarity/low-evidence input produces low confidence scores,
     not arbitrary or default values.
  3. Malformed, missing, or empty inputs do not crash and fall back safely.
  4. score_scenario applies confidence correctly to immutable ThreatScenario.
"""

from __future__ import annotations

from typing import Any

import pytest

from agents.threat_agent.schemas import (
    AttackPath,
    EvidenceChain,
    KBCandidate,
    KBSource,
    STRIDECategory,
    ThreatScenario,
    ThreatStatus,
)
from agents.threat_agent.scorer import (
    DEFAULT_FALLBACK_CONFIDENCE,
    LOW_CONFIDENCE_THRESHOLD,
    compute_confidence_score,
    score_scenario,
)


def _make_candidate(score: float, pattern_id: str = "CAPEC-94") -> KBCandidate:
    return KBCandidate(
        pattern_id=pattern_id,
        source=KBSource.CAPEC,
        title="Test Threat Pattern",
        description="Test pattern description for scorer unit test.",
        retrieval_score=score,
        asset_id="ASSET-001",
        stride_hint=STRIDECategory.SPOOFING,
        mitre_tactics=["TA0001"],
    )


def _make_path(candidates: list[KBCandidate]) -> AttackPath:
    chain_conf = candidates[0].retrieval_score if candidates else 0.0
    return AttackPath(
        path_id="PATH-TEST001",
        steps=candidates,
        target_asset_ids=["ASSET-001"],
        is_forced=False,
        chain_confidence=chain_conf,
        reasoning="Test path for confidence scorer unit test.",
    )


def _make_scenario(confidence_score: float = 0.5) -> ThreatScenario:
    return ThreatScenario(
        tid="THR-PATH-TEST001-001",
        asset_id="ASSET-001",
        stride_category=STRIDECategory.SPOOFING,
        attack_vector="BLE advertisement spoofing with forged packets.",
        kb_reference="CAPEC-94",
        evidence_chain=EvidenceChain(
            exposure="BLE advertising daemon exposed on external radio interface.",
            matched_pattern="CAPEC-94 Adversary in the Middle via unauthenticated BLE.",
            applicability_reason="The lock accepts unauthenticated BLE packets allowing spoofing.",
            citation="CAPEC-94: Adversary in the Middle",
        ),
        confidence_score=confidence_score,
        status=ThreatStatus.PENDING_TEST,
        run_id="run-test-scorer-001",
    )


class TestConfidenceScoreRange:
    """Test 1: Output is always in the valid range [0.0, 1.0]."""

    def test_single_candidate_in_range(self):
        candidate = _make_candidate(score=0.75)
        path = _make_path([candidate])
        score = compute_confidence_score(path)
        assert 0.0 <= score <= 1.0
        assert abs(score - 0.75) < 1e-9

    def test_multi_step_arithmetic_mean_in_range(self):
        c1 = _make_candidate(score=0.8, pattern_id="CAPEC-1")
        c2 = _make_candidate(score=0.6, pattern_id="CAPEC-2")
        path = _make_path([c1, c2])
        score = compute_confidence_score(path)
        assert 0.0 <= score <= 1.0
        assert abs(score - 0.7) < 1e-9

    def test_boundary_values(self):
        assert compute_confidence_score(_make_path([_make_candidate(0.0)])) == 0.0
        assert compute_confidence_score(_make_path([_make_candidate(1.0)])) == 1.0

    def test_raw_values_above_one_clamped_to_one(self):
        # Even if an un-normalized score > 1.0 is passed via a raw step, it is clamped
        score = compute_confidence_score(steps=[1.25])
        assert score == 1.0

    def test_raw_values_below_zero_clamped_to_zero(self):
        score = compute_confidence_score(steps=[-0.5])
        assert score == 0.0


class TestLowEvidenceConfidenceScoring:
    """Test 2: Low-similarity retrieval produces low confidence, not an arbitrary default."""

    @pytest.mark.parametrize("low_score", [0.05, 0.12, 0.25, 0.35])
    def test_low_similarity_yields_exact_low_confidence(self, low_score: float):
        candidate = _make_candidate(score=low_score)
        path = _make_path([candidate])
        score = compute_confidence_score(path)

        # Must reflect the low retrieval score accurately
        assert abs(score - low_score) < 1e-9
        # Must be below low-confidence threshold
        assert score < LOW_CONFIDENCE_THRESHOLD

    def test_multi_step_low_evidence_chain(self):
        c1 = _make_candidate(score=0.10, pattern_id="CAPEC-10")
        c2 = _make_candidate(score=0.20, pattern_id="CAPEC-20")
        path = _make_path([c1, c2])
        score = compute_confidence_score(path)

        assert abs(score - 0.15) < 1e-9
        assert score < LOW_CONFIDENCE_THRESHOLD


class TestMalformedAndMissingInputs:
    """Test 3: Malformed or missing inputs do not crash; return sensible fallback."""

    def test_none_path_returns_fallback(self):
        score = compute_confidence_score(None)
        assert score == DEFAULT_FALLBACK_CONFIDENCE
        assert score == 0.0

    def test_empty_steps_list_returns_fallback(self):
        score = compute_confidence_score(steps=[])
        assert score == DEFAULT_FALLBACK_CONFIDENCE

    def test_empty_path_steps_returns_fallback(self):
        class DummyEmptyPath:
            def __init__(self) -> None:
                self.steps: list[Any] = []

        score = compute_confidence_score(DummyEmptyPath())  # type: ignore[arg-type]
        assert score == DEFAULT_FALLBACK_CONFIDENCE

    def test_non_path_object_returns_fallback(self):
        score = compute_confidence_score("not_a_path")  # type: ignore[arg-type]
        assert score == DEFAULT_FALLBACK_CONFIDENCE

    def test_step_missing_retrieval_score_handled_gracefully(self):
        class DummyStepWithoutScore:
            pass

        score = compute_confidence_score(steps=[DummyStepWithoutScore()])
        assert score == DEFAULT_FALLBACK_CONFIDENCE

    def test_step_with_invalid_non_numeric_score(self):
        class DummyStepWithBadScore:
            retrieval_score = "not_a_number"

        score = compute_confidence_score(steps=[DummyStepWithBadScore()])
        assert score == DEFAULT_FALLBACK_CONFIDENCE

    def test_partial_valid_scores_computes_mean_of_valid(self):
        class DummyStepBad:
            retrieval_score = None

        c_valid = _make_candidate(score=0.6)
        score = compute_confidence_score(steps=[DummyStepBad(), c_valid])
        assert abs(score - 0.6) < 1e-9


class TestScoreScenarioHelper:
    """Test score_scenario helper for ThreatScenario model."""

    def test_score_scenario_updates_confidence(self):
        scenario = _make_scenario(confidence_score=0.1)
        candidate = _make_candidate(score=0.88)
        path = _make_path([candidate])

        updated = score_scenario(scenario, path)
        assert abs(updated.confidence_score - 0.88) < 1e-9
        # Original frozen instance must remain untouched
        assert abs(scenario.confidence_score - 0.1) < 1e-9

    def test_score_scenario_with_none_path_falls_back(self):
        scenario = _make_scenario(confidence_score=0.9)
        updated = score_scenario(scenario, None)
        assert updated.confidence_score == DEFAULT_FALLBACK_CONFIDENCE
