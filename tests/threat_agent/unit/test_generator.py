"""
tests/threat_agent/unit/test_generator.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Generator unit tests  (Chetan)
──────────────────────────────────────────────────────────────────────────────
Test scope:
    agents/threat_agent/generator.py

Coverage plan (keyed to build plan §6 acceptance criteria):
  ✅  generate_scenarios() raises EmptyAttackPathError on empty paths
  ✅  generate_from_candidates() raises EmptyAttackPathError on empty list
  ✅  _parse_llm_response() raises LLMResponseError on malformed JSON
  ✅  _parse_llm_response() raises LLMResponseError on non-array JSON
  ✅  _parse_llm_response() raises LLMResponseError on missing required keys
  ✅  _make_scenario() produces a valid ThreatScenario with correct tid format
  ✅  _make_scenario() confidence_score is clamped to [0, 1] by schema
  ✅  generate_scenarios() with mocked _call_llm produces valid ThreatScenarios
  ✅  generate_scenarios() passes failure context to user prompt on retry
  ✅  generate_from_candidates() wraps candidates into single-step AttackPaths
  ⬜  generate_scenarios() handles LLM timeout (TODO: needs LLM client types)
  ⬜  Scenarios validated against both domain fixtures (Smart Door Lock +
       infusion pump) — TODO: add e2e fixture calls once retrieval.py lands
  ⬜  self_consistency sampling (N=3) tested via scorer.py integration

All tests are unit-level: the LLM client is mocked, no network calls made.
Shriraj's validator tests are in tests/threat_agent/unit/test_validator.py.

Ruff compliance: ANN and S101 suppressed for test files per pyproject.toml.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import pytest

from agents.threat_agent.generator import (
    EmptyAttackPathError,
    LLMResponseError,
    _make_scenario,
    _parse_llm_response,
    generate_from_candidates,
    generate_scenarios,
)
from agents.threat_agent.schemas import (
    AssetModel,
    AttackPath,
    KBCandidate,
    KBSource,
    NormalizedInput,
    STRIDECategory,
    ThreatScenario,
    ThreatStatus,
)

# ─── Shared test fixtures ─────────────────────────────────────────────────────


def _make_asset(asset_id: str = "ASSET-001") -> AssetModel:
    """Minimal domain-neutral AssetModel for unit tests."""
    return AssetModel(
        asset_id=asset_id,
        name="Test Asset",
        asset_type="firmware",
        interfaces=["BLE 5.0", "UART"],
        trust_zone="untrusted",
        attributes={"auth_mechanism": "PIN-only", "encryption": "none"},
    )


def _make_kb_candidate(
    pattern_id: str = "CAPEC-94",
    asset_id: str = "ASSET-001",
    retrieval_score: float = 0.85,
) -> KBCandidate:
    """Minimal KBCandidate for unit tests."""
    return KBCandidate(
        pattern_id=pattern_id,
        source=KBSource.CAPEC,
        title="Adversary in the Middle",
        description="An attacker positions themselves between two communicating "
        "parties to intercept or modify traffic.",
        retrieval_score=retrieval_score,
        asset_id=asset_id,
        stride_hint=STRIDECategory.SPOOFING,
        mitre_tactics=["TA0001"],
    )


def _make_attack_path(
    candidate: KBCandidate | None = None,
    target_asset_ids: list[str] | None = None,
) -> AttackPath:
    """Minimal single-step AttackPath for unit tests."""
    c = candidate or _make_kb_candidate()
    return AttackPath(
        path_id="PATH-TESTPATH1",
        steps=[c],
        target_asset_ids=target_asset_ids or [c.asset_id],
        is_forced=False,
        chain_confidence=c.retrieval_score,
        reasoning="Unit test path — single step.",
    )


def _make_context(
    run_id: str = "run-test-001",
    assets: list[AssetModel] | None = None,
) -> NormalizedInput:
    """Minimal NormalizedInput for unit tests."""
    return NormalizedInput(
        run_id=run_id,
        use_case=(
            "Smart electronic door lock with BLE unlock, PIN fallback, "
            "and cloud-managed access control."
        ),
        assets=assets or [_make_asset()],
        kb_snapshot_version="test-snapshot-v1",
        system_model_summary=(
            "BLE controller exposes unauthenticated advertisement channel. "
            "PIN pad communicates via UART to MCU. "
            "MCU connects to cloud backend over TLS."
        ),
        pii_redacted=False,
    )


def _make_valid_llm_item(
    asset_id: str = "ASSET-001",
    pattern_id: str = "CAPEC-94",
) -> dict:
    """Return a dict matching the LLM response schema for one scenario."""
    return {
        "asset_id": asset_id,
        "stride_category": "Spoofing",
        "attack_vector": (
            "Unauthenticated BLE advertisement replay allows an attacker "
            "to unlock the door without valid credentials."
        ),
        "kb_reference": pattern_id,
        "exposure": "Unauthenticated BLE 5.0 advertisement channel",
        "matched_pattern": pattern_id,
        "applicability_reason": (
            "The BLE controller exposes an unauthenticated advertisement "
            "channel (trust_zone=untrusted, no pairing required), which "
            "CAPEC-94 Adversary-in-the-Middle directly exploits to intercept "
            "and replay unlock commands without needing valid credentials."
        ),
        "citation": "CAPEC-94: Adversary in the Middle (CAPEC v3.9)",
    }


# ─── EmptyAttackPathError tests ───────────────────────────────────────────────


class TestEmptyAttackPathError(unittest.TestCase):
    def test_generate_scenarios_raises_on_empty_paths(self):
        context = _make_context()
        with pytest.raises(EmptyAttackPathError, match="empty attack-path list"):
            generate_scenarios([], context)

    def test_generate_from_candidates_raises_on_empty_candidates(self):
        context = _make_context()
        with pytest.raises(EmptyAttackPathError, match="empty candidate list"):
            generate_from_candidates([], context)


# ─── _parse_llm_response tests ────────────────────────────────────────────────


class TestParseLlmResponse(unittest.TestCase):
    def setUp(self):
        self.path = _make_attack_path()
        self.run_id = "run-parse-test"

    def test_valid_response_returns_list_of_dicts(self):
        raw = json.dumps([_make_valid_llm_item()])
        result = _parse_llm_response(raw, self.path, self.run_id)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["asset_id"] == "ASSET-001"

    def test_raises_on_invalid_json(self):
        with pytest.raises(LLMResponseError, match="non-JSON response"):
            _parse_llm_response("not json at all {{{", self.path, self.run_id)

    def test_raises_on_non_array_json(self):
        raw = json.dumps({"asset_id": "ASSET-001"})  # object, not array
        with pytest.raises(LLMResponseError, match="Expected JSON array"):
            _parse_llm_response(raw, self.path, self.run_id)

    def test_raises_on_missing_required_key(self):
        item = _make_valid_llm_item()
        del item["applicability_reason"]
        raw = json.dumps([item])
        with pytest.raises(LLMResponseError, match="missing required keys"):
            _parse_llm_response(raw, self.path, self.run_id)

    def test_raises_on_non_dict_item(self):
        raw = json.dumps(["not a dict"])
        with pytest.raises(LLMResponseError, match="not a JSON object"):
            _parse_llm_response(raw, self.path, self.run_id)

    def test_multiple_valid_items(self):
        items = [_make_valid_llm_item("ASSET-001"), _make_valid_llm_item("ASSET-002")]
        raw = json.dumps(items)
        result = _parse_llm_response(raw, self.path, self.run_id)
        assert len(result) == 2


# ─── _make_scenario tests ─────────────────────────────────────────────────────


class TestMakeScenario(unittest.TestCase):
    def setUp(self):
        self.path = _make_attack_path()
        self.run_id = "run-make-test"

    def test_returns_threat_scenario_instance(self):
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        assert isinstance(result, ThreatScenario)

    def test_tid_format_is_correct(self):
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        # Expected: THR-PATH-TESTPATH1-001
        assert result.tid == "THR-PATH-TESTPATH1-001"

    def test_tid_seq_increments(self):
        item = _make_valid_llm_item()
        s0 = _make_scenario(item, self.path, self.run_id, seq=0)
        s2 = _make_scenario(item, self.path, self.run_id, seq=2)
        assert s0.tid.endswith("-001")
        assert s2.tid.endswith("-003")

    def test_status_is_pending_test(self):
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        assert result.status == ThreatStatus.PENDING_TEST

    def test_confidence_score_in_range(self):
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        assert 0.0 <= result.confidence_score <= 1.0

    def test_evidence_chain_populated(self):
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        ec = result.evidence_chain
        assert ec.exposure == item["exposure"]
        assert ec.matched_pattern == item["matched_pattern"]
        assert ec.citation == item["citation"]
        assert len(ec.applicability_reason) >= 20

    def test_stride_category_is_enum(self):
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        assert isinstance(result.stride_category, STRIDECategory)
        assert result.stride_category == STRIDECategory.SPOOFING

    def test_confidence_score_is_mean_of_step_retrieval_scores(self):
        """Preliminary score should be the mean retrieval_score of path steps."""
        candidate = _make_kb_candidate(retrieval_score=0.6)
        path = _make_attack_path(candidate=candidate)
        item = _make_valid_llm_item()
        result = _make_scenario(item, path, self.run_id, seq=0)
        assert abs(result.confidence_score - 0.6) < 1e-9

    def test_frozen_model_immutability(self):
        """ThreatScenario must be immutable — mutation must raise."""
        item = _make_valid_llm_item()
        result = _make_scenario(item, self.path, self.run_id, seq=0)
        # Frozen Pydantic v2 models raise ValidationError or TypeError on mutation.
        with pytest.raises((TypeError, ValueError)):
            result.status = ThreatStatus.APPROVED  # type: ignore[misc]


# ─── generate_scenarios (with mocked LLM) ────────────────────────────────────


class TestGenerateScenariosWithMock(unittest.TestCase):
    """Integration-style unit tests: _call_llm is mocked, rest runs real."""

    def _mock_llm_response(self, items: list[dict]) -> str:
        return json.dumps(items)

    def test_produces_one_scenario_per_step(self):
        candidate = _make_kb_candidate()
        path = _make_attack_path(candidate=candidate)
        context = _make_context()
        expected_item = _make_valid_llm_item()

        with patch(
            "agents.threat_agent.generator._call_llm",
            return_value=self._mock_llm_response([expected_item]),
        ):
            results = generate_scenarios([path], context)

        assert len(results) == 1
        assert isinstance(results[0], ThreatScenario)
        assert results[0].kb_reference == "CAPEC-94"

    def test_multiple_paths_produce_correct_count(self):
        c1 = _make_kb_candidate("CAPEC-94", "ASSET-001")
        c2 = _make_kb_candidate("ATT&CK T1190", "ASSET-001")
        path1 = _make_attack_path(c1, ["ASSET-001"])
        path2 = _make_attack_path(c2, ["ASSET-001"])
        context = _make_context()

        with patch(
            "agents.threat_agent.generator._call_llm",
            return_value=self._mock_llm_response([_make_valid_llm_item()]),
        ):
            results = generate_scenarios([path1, path2], context)

        assert len(results) == 2

    def test_retry_preamble_in_prompt_when_failure_context_provided(self):
        """When validation_failure_context is given, the user prompt must
        contain the failure details so the LLM can fix them."""
        candidate = _make_kb_candidate()
        path = _make_attack_path(candidate=candidate)
        context = _make_context()
        failure_details = ["EVIDENCE_GENERIC: applicability_reason is too vague."]

        captured_user_prompt: list[str] = []

        def mock_llm(system_prompt: str, user_prompt: str, run_id: str) -> str:
            captured_user_prompt.append(user_prompt)
            return self._mock_llm_response([_make_valid_llm_item()])

        with patch("agents.threat_agent.generator._call_llm", side_effect=mock_llm):
            generate_scenarios(
                [path], context, validation_failure_context=failure_details
            )

        assert "THIS IS A RETRY" in captured_user_prompt[0]
        assert "EVIDENCE_GENERIC" in captured_user_prompt[0]

    def test_llm_response_error_propagates(self):
        """Malformed LLM response must raise LLMResponseError, not be silently
        swallowed."""
        candidate = _make_kb_candidate()
        path = _make_attack_path(candidate=candidate)
        context = _make_context()

        with (
            patch(
                "agents.threat_agent.generator._call_llm",
                return_value="TOTALLY NOT JSON",
            ),
            pytest.raises(LLMResponseError, match="non-JSON response"),
        ):
            generate_scenarios([path], context)


# ─── generate_from_candidates tests ──────────────────────────────────────────


class TestGenerateFromCandidates(unittest.TestCase):
    def test_wraps_each_candidate_in_single_step_path(self):
        """Each KBCandidate should produce exactly one AttackPath with one step."""
        c1 = _make_kb_candidate("CAPEC-94", "ASSET-001")
        c2 = _make_kb_candidate("CWE-306", "ASSET-001")
        context = _make_context()

        captured_paths: list[list] = []

        def mock_generate(
            paths,
            ctx,
            *,
            validation_failure_context=None,
        ):
            captured_paths.append(paths)
            return []  # no scenarios needed for this assertion

        with patch(
            "agents.threat_agent.generator.generate_scenarios",
            side_effect=mock_generate,
        ):
            generate_from_candidates([c1, c2], context)

        assert len(captured_paths) == 1  # called once
        paths = captured_paths[0]
        assert len(paths) == 2  # two candidates → two single-step paths
        for p in paths:
            assert len(p.steps) == 1

    def test_empty_candidates_raises(self):
        context = _make_context()
        with pytest.raises(EmptyAttackPathError):
            generate_from_candidates([], context)


# ─── TODO placeholder stubs ───────────────────────────────────────────────────


class TestGeneratorTODO(unittest.TestCase):
    """Placeholder tests that will be filled in as dependencies land."""

    @pytest.mark.skip(reason="TODO: needs common.llm_client types (Manthan's module)")
    def test_llm_timeout_raises_typed_exception(self):
        """generate_scenarios() must propagate LLMTimeoutError from llm_client."""

    @pytest.mark.skip(reason="TODO: infusion-pump e2e fixture (Week 3)")
    def test_infusion_pump_fixture_produces_valid_scenarios(self):
        """generate_scenarios() must produce valid ThreatScenarios on the
        infusion pump domain fixture, not just Smart Door Lock."""

    @pytest.mark.skip(reason="TODO: self_consistency sampling via scorer.py (Week 2)")
    def test_self_consistency_sampling_calls_generate_n_times(self):
        """scorer.py's self_consistency component calls generate_scenarios N=3
        times; each must return the same stride_category + kb_reference pair."""


if __name__ == "__main__":
    unittest.main()
