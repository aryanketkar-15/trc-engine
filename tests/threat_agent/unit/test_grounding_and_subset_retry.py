"""Grounding rules, and retrying only the scenarios that failed."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agents.threat_agent.grounding import check_grounding, path_id_from_tid
from agents.threat_agent.orchestrator import generate_and_validate_with_retry
from agents.threat_agent.schemas import (
    AttackPath,
    EvidenceChain,
    FailedCheck,
    KBCandidate,
    KBSource,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
    ValidationResult,
)
from agents.threat_agent.validator import Validator

_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "e2e" / "fixtures" / "smart_door_lock" / "input.json"
)


@pytest.fixture()
def agent_input() -> ThreatAgentInput:
    return ThreatAgentInput(**json.loads(_FIXTURE.read_text(encoding="utf-8")))


def _path(hexid: str, pattern: str = "CWE-306") -> AttackPath:
    step = KBCandidate(
        pattern_id=pattern, source=KBSource.CWE, title="t", description="d",
        retrieval_score=0.8, asset_id="AS-1", stride_hint=STRIDECategory.SPOOFING,
        mitre_tactics=[],
    )
    return AttackPath(path_id=f"PATH-{hexid}", steps=[step], target_asset_ids=["AS-1"],
                      is_forced=False, chain_confidence=0.8, reasoning="r")


def _sc(hexid: str, vector: str = "ok vector", ref: str = "CWE-306", asset: str = "AS-1",
        citation: str | None = None, exposure: str = "BLE GATT characteristic accepts writes",
        matched: str | None = None) -> ThreatScenario:
    return ThreatScenario(
        tid=f"THR-PATH-{hexid}-001", run_id="RUN-G", asset_id=asset,
        stride_category=STRIDECategory.SPOOFING, attack_vector=vector, kb_reference=ref,
        evidence_chain=EvidenceChain(
            exposure=exposure, matched_pattern=matched or ref,
            applicability_reason="The unlock command is accepted without authentication.",
            citation=citation or f"{ref}: some pattern title",
        ),
        confidence_score=0.8,
    )


class TestGroundingRules:
    def test_grounded_scenario_has_no_failures(self, agent_input: ThreatAgentInput) -> None:
        assert check_grounding(_sc("AAAA1111"), _path("AAAA1111"), agent_input.assets) == []

    def test_citing_a_pattern_not_on_the_path_fails(self, agent_input: ThreatAgentInput) -> None:
        sc = _sc("AAAA1111", ref="CAPEC-999")
        ids = [f.check_id for f in check_grounding(sc, _path("AAAA1111"), agent_input.assets)]
        assert "CITATION_NOT_RETRIEVED" in ids

    def test_unknown_asset_fails(self, agent_input: ThreatAgentInput) -> None:
        sc = _sc("AAAA1111", asset="AS-99")
        ids = [f.check_id for f in check_grounding(sc, _path("AAAA1111"), agent_input.assets)]
        assert "ASSET_NOT_IN_INPUT" in ids

    def test_citation_must_name_the_same_pattern(self, agent_input: ThreatAgentInput) -> None:
        sc = _sc("AAAA1111", citation="CAPEC-94: something else entirely")
        ids = [f.check_id for f in check_grounding(sc, _path("AAAA1111"), agent_input.assets)]
        assert "CITATION_MISMATCH" in ids
        bad_matched = _sc("AAAA1111", matched="CWE-798")
        ids = [f.check_id for f in check_grounding(bad_matched, _path("AAAA1111"), agent_input.assets)]
        assert "CITATION_MISMATCH" in ids

    def test_url_citation_with_the_same_id_is_accepted(self, agent_input: ThreatAgentInput) -> None:
        sc = _sc("AAAA1111", citation="https://cwe.mitre.org/data/definitions/306.html")
        assert check_grounding(sc, _path("AAAA1111"), agent_input.assets) == []

    def test_attack_prefix_differences_are_tolerated(self, agent_input: ThreatAgentInput) -> None:
        sc = _sc("AAAA1111", ref="T1078", citation="MITRE ATT&CK T1078: Valid Accounts")
        assert check_grounding(sc, _path("AAAA1111", "ATT&CK-T1078"), agent_input.assets) == []

    def test_exposure_unrelated_to_the_asset_fails(self, agent_input: ThreatAgentInput) -> None:
        sc = _sc("AAAA1111", exposure="Quantum entanglement relay misconfiguration")
        ids = [f.check_id for f in check_grounding(sc, _path("AAAA1111"), agent_input.assets)]
        assert "EXPOSURE_NOT_GROUNDED" in ids

    def test_path_id_parsing(self) -> None:
        assert path_id_from_tid("THR-PATH-AAAA1111-001") == "PATH-AAAA1111"
        assert path_id_from_tid("TID-001") is None


def _ok() -> ValidationResult:
    return ValidationResult(passed=True, failed_checks=[], confidence_penalty=0.0)


def _bad(tid: str) -> ValidationResult:
    return ValidationResult(
        passed=False,
        failed_checks=[FailedCheck(check_id="EVIDENCE_GENERIC", affected_tid=tid,
                                   detail="applicability_reason is too generic")],
        confidence_penalty=0.1,
    )


def _validator(bad_vector: str = "BAD") -> MagicMock:
    v = MagicMock(spec=Validator)
    v.validate.side_effect = lambda s: _bad(s.tid) if s.attack_vector == bad_vector else _ok()
    v.retry_with_context.return_value = ("retry", {})
    return v


class TestRetryOnlyFailed:
    def test_only_the_failing_path_is_regenerated(self, agent_input: ThreatAgentInput) -> None:
        paths = [_path("AAAA1111"), _path("BBBB2222"), _path("CCCC3333")]
        first = [_sc("AAAA1111"), _sc("BBBB2222", vector="BAD"), _sc("CCCC3333")]
        fixed = [_sc("BBBB2222", vector="fixed vector")]
        gen = MagicMock(side_effect=[first, fixed])
        retrieval = MagicMock()
        with (
            patch("agents.threat_agent.orchestrator.generate_scenarios", gen),
            patch("agents.threat_agent.orchestrator._execute_retrieval_and_chaining", retrieval),
            patch("agents.threat_agent.orchestrator.log_step"),
        ):
            scenarios, retries, status = generate_and_validate_with_retry(
                agent_input, paths=paths, validator=_validator()
            )
        assert status == "passed" and retries == 1
        assert gen.call_count == 2
        assert [p.path_id for p in gen.call_args_list[1].args[0]] == ["PATH-BBBB2222"]
        retrieval.assert_not_called()  # no new retrieval for a path-level retry
        assert [s.tid for s in scenarios] == [
            "THR-PATH-AAAA1111-001", "THR-PATH-BBBB2222-001", "THR-PATH-CCCC3333-001"
        ]
        assert scenarios[1].attack_vector == "fixed vector"
        assert all(s.validation_status == "passed" for s in scenarios)
        context = gen.call_args_list[1].kwargs["validation_failure_context"]
        assert context and "THR-PATH-BBBB2222-001" in context[0]

    def test_exhaustion_flags_only_the_scenario_that_still_fails(
        self, agent_input: ThreatAgentInput
    ) -> None:
        paths = [_path("AAAA1111"), _path("BBBB2222"), _path("CCCC3333")]
        first = [_sc("AAAA1111"), _sc("BBBB2222", vector="BAD"), _sc("CCCC3333")]
        again = [_sc("BBBB2222", vector="BAD")]
        gen = MagicMock(side_effect=[first, again, again])
        with (
            patch("agents.threat_agent.orchestrator.generate_scenarios", gen),
            patch("agents.threat_agent.orchestrator.log_step"),
        ):
            scenarios, retries, status = generate_and_validate_with_retry(
                agent_input, paths=paths, validator=_validator()
            )
        assert status == "escalated_after_retries" and retries == 3
        assert {s.tid: s.validation_status for s in scenarios} == {
            "THR-PATH-AAAA1111-001": "passed",
            "THR-PATH-BBBB2222-001": "escalated_after_retries",
            "THR-PATH-CCCC3333-001": "passed",
        }
        # 3 + 1 + 1 generated scenarios, instead of 3 x 3 = 9 with a full retry
        assert sum(len(c.args[0]) for c in gen.call_args_list) == 5

    def test_grounding_failure_triggers_a_retry_with_the_reason(
        self, agent_input: ThreatAgentInput
    ) -> None:
        paths = [_path("AAAA1111")]
        invented = _sc("AAAA1111", ref="CAPEC-999")  # not a pattern on the path
        gen = MagicMock(side_effect=[[invented], [_sc("AAAA1111")]])
        with (
            patch("agents.threat_agent.orchestrator.generate_scenarios", gen),
            patch("agents.threat_agent.orchestrator.log_step"),
        ):
            scenarios, retries, status = generate_and_validate_with_retry(
                agent_input, paths=paths, validator=_validator()
            )
        assert status == "passed" and retries == 1
        assert scenarios[0].kb_reference == "CWE-306"
        context = " ".join(gen.call_args_list[1].kwargs["validation_failure_context"])
        assert "not one of the retrieved patterns" in context
