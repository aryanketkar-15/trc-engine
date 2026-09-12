"""
tests/threat_agent/unit/test_orchestrator.py
─────────────────────────────────────────────
Unit tests for agents/threat_agent/orchestrator.py.

Covers the automated Protocol Invariant Validator retry loop:
  1. Immediate pass: all scenarios pass on attempt 1 (retries=0, status="passed").
  2. Self-correcting retry: attempt 1 fails validation, attempt 2 succeeds with
     validation_failure_context passed to the generator (retries=1, status="passed").
  3. Retries exhausted: attempts 1-3 fail validation, capped at 3 attempts,
     escalates with validation_status="escalated_after_retries" and audit event
     "validator_retries_exhausted".
  4. Vector store unreachable fallback: catches KBStoreUnreachableError and provides
     fallback candidates for offline execution.
  5. Router status reporting: verifies validator_retry_count, human_rejection_count,
     and validation_status are stored and exposed via API endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.threat_agent.orchestrator import (
    MAX_VALIDATION_ATTEMPTS,
    _execute_retrieval_and_chaining,
    generate_and_validate_with_retry,
)
from agents.threat_agent.router import (
    clear_run_registry,
    get_orchestrator,
)
from agents.threat_agent.router import (
    router as threat_agent_router,
)
from agents.threat_agent.run_store import (
    get_in_memory_run_store,
    get_run_store,
)
from agents.threat_agent.schemas import (
    AttackPath,
    EvidenceChain,
    FailedCheck,
    KBCandidate,
    KBSource,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
    ThreatStatus,
    ValidationResult,
)
from agents.threat_agent.validator import Validator

# Canonical test fixture path
_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "e2e"
    / "fixtures"
    / "smart_door_lock"
    / "input.json"
)


@pytest.fixture()
def valid_input() -> ThreatAgentInput:
    """Load canonical Smart Door Lock fixture as ThreatAgentInput."""
    with open(_FIXTURE_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return ThreatAgentInput(**data)


def _make_valid_scenario(
    run_id: str = "RUN-ORCH-001",
    tid: str = "TID-001",
    asset_id: str = "AS-1",
) -> ThreatScenario:
    """Helper to construct a scenario that satisfies all validator invariants."""
    return ThreatScenario(
        tid=tid,
        run_id=run_id,
        asset_id=asset_id,
        stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        attack_vector="Exploiting unauthenticated BLE unlock to bypass access control.",
        kb_reference="CWE-306",
        evidence_chain=EvidenceChain(
            exposure="Unauthenticated BLE characteristic exposed on peripheral interface.",
            matched_pattern="CWE-306",
            applicability_reason=(
                "The lock allows pairing and motor unlock commands without verifying "
                "device ownership or PIN authentication over BLE GATT."
            ),
            citation="https://cwe.mitre.org/data/definitions/306.html",
        ),
        confidence_score=0.85,
        status=ThreatStatus.PENDING_TEST,
    )


def _make_candidate(
    asset_id: str = "AS-1",
    pattern_id: str = "CWE-306",
) -> KBCandidate:
    return KBCandidate(
        pattern_id=pattern_id,
        source=KBSource.CWE,
        title="Missing Authentication for Critical Function",
        description="The software does not authenticate critical functions.",
        retrieval_score=0.85,
        asset_id=asset_id,
        stride_hint=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        mitre_tactics=[],
    )


def _make_attack_path(asset_id: str = "AS-1") -> AttackPath:
    candidate = _make_candidate(asset_id=asset_id)
    return AttackPath(
        path_id="PATH-TEST-001",
        steps=[candidate],
        target_asset_ids=[asset_id],
        is_forced=False,
        chain_confidence=0.85,
        reasoning="Direct exploitation path",
    )


# ── 1. Immediate Pass Flow ───────────────────────────────────────────────────


class TestOrchestratorImmediatePass:
    """Test case 1: generation passes validator on attempt 1."""

    def test_immediate_pass_clean(self, valid_input: ThreatAgentInput) -> None:
        scenario = _make_valid_scenario(run_id=valid_input.run_id)
        mock_paths = [_make_attack_path()]

        with (
            patch(
                "agents.threat_agent.orchestrator.generate_scenarios",
                return_value=[scenario],
            ) as mock_gen,
            patch("agents.threat_agent.orchestrator.log_step") as mock_log,
        ):
            scenarios, retry_count, val_status = generate_and_validate_with_retry(
                agent_input=valid_input,
                paths=mock_paths,
            )

            assert len(scenarios) == 1
            assert retry_count == 0
            assert val_status == "passed"
            assert scenarios[0].validation_status == "passed"

            # Generator called exactly once without failure context
            mock_gen.assert_called_once_with(
                mock_paths,
                valid_input,
                validation_failure_context=None,
            )

            # Audit event validator_pass emitted
            pass_logs = [
                call for call in mock_log.call_args_list if call.args[2] == "validator_pass"
            ]
            assert len(pass_logs) == 1
            assert pass_logs[0].args[4]["retries"] == 0


# ── 2. Self-Correcting Retry Flow ─────────────────────────────────────────────


class TestOrchestratorSelfCorrectingRetry:
    """Test case 2: attempt 1 fails validation, attempt 2 passes with failure context."""

    def test_retry_on_validation_failure_succeeds(
        self, valid_input: ThreatAgentInput
    ) -> None:
        valid_scenario = _make_valid_scenario(run_id=valid_input.run_id)
        mock_paths = [_make_attack_path()]

        # Generator returns scenario on both attempts
        gen_mock = MagicMock(return_value=[valid_scenario])

        # Validator returns failed on attempt 1, passed on attempt 2
        fail_result = ValidationResult(
            passed=False,
            failed_checks=[
                FailedCheck(
                    check_id="EVIDENCE_GENERIC",
                    detail="applicability_reason is too short (< 40 chars)",
                )
            ],
            confidence_penalty=0.15,
        )
        pass_result = ValidationResult(passed=True, failed_checks=[], confidence_penalty=0.0)

        validator_mock = MagicMock(spec=Validator)
        validator_mock.validate.side_effect = [fail_result, pass_result]
        validator_mock.retry_with_context.return_value = (
            "retry_act_fetch_reason",
            "Mock failure context",
        )

        with (
            patch("agents.threat_agent.orchestrator.generate_scenarios", gen_mock),
            patch(
                "agents.threat_agent.orchestrator._execute_retrieval_and_chaining",
                return_value=mock_paths,
            ) as mock_retrieval,
            patch("agents.threat_agent.orchestrator.log_step") as mock_log,
        ):
            scenarios, retry_count, val_status = generate_and_validate_with_retry(
                agent_input=valid_input,
                paths=mock_paths,
                validator=validator_mock,
            )

            assert len(scenarios) == 1
            assert retry_count == 1
            assert val_status == "passed"
            assert scenarios[0].validation_status == "passed"

            # Retrieval re-invoked on attempt 2 with failure context
            mock_retrieval.assert_called_once_with(
                valid_input,
                ["applicability_reason is too short (< 40 chars)"],
            )

            # Generator called twice: attempt 1 without context, attempt 2 with context
            assert gen_mock.call_count == 2
            attempt2_call = gen_mock.call_args_list[1]
            assert attempt2_call.kwargs["validation_failure_context"] == [
                "applicability_reason is too short (< 40 chars)"
            ]

            # Audit events: validator_retry_triggered then validator_pass
            event_names = [call.args[2] for call in mock_log.call_args_list]
            assert "validator_retry_triggered" in event_names
            assert "validator_pass" in event_names


# ── 3. Exhausted Retries Flow ─────────────────────────────────────────────────


class TestOrchestratorExhaustedRetries:
    """Test case 3: attempts 1, 2, 3 all fail, flagged escalation after 3 attempts."""

    def test_exhausted_retries_escalates_to_human(
        self, valid_input: ThreatAgentInput
    ) -> None:
        scenario = _make_valid_scenario(run_id=valid_input.run_id)
        mock_paths = [_make_attack_path()]

        gen_mock = MagicMock(return_value=[scenario])

        fail_result = ValidationResult(
            passed=False,
            failed_checks=[
                FailedCheck(
                    check_id="CITATION_MISSING",
                    detail="Citation URL is not accessible or invalid",
                )
            ],
            confidence_penalty=0.2,
        )

        validator_mock = MagicMock(spec=Validator)
        validator_mock.validate.return_value = fail_result
        validator_mock.retry_with_context.return_value = (
            "escalate_to_human",
            "Retries exhausted",
        )

        with (
            patch("agents.threat_agent.orchestrator.generate_scenarios", gen_mock),
            patch(
                "agents.threat_agent.orchestrator._execute_retrieval_and_chaining",
                return_value=mock_paths,
            ),
            patch("agents.threat_agent.orchestrator.log_step") as mock_log,
        ):
            scenarios, retry_count, val_status = generate_and_validate_with_retry(
                agent_input=valid_input,
                paths=mock_paths,
                validator=validator_mock,
                max_attempts=MAX_VALIDATION_ATTEMPTS,
            )

            assert len(scenarios) == 1
            assert retry_count == MAX_VALIDATION_ATTEMPTS
            assert val_status == "escalated_after_retries"
            assert scenarios[0].validation_status == "escalated_after_retries"

            # Called exactly max_attempts (3) times
            assert gen_mock.call_count == MAX_VALIDATION_ATTEMPTS

            # Distinct audit event emitted
            exhausted_logs = [
                call
                for call in mock_log.call_args_list
                if call.args[2] == "validator_retries_exhausted"
            ]
            assert len(exhausted_logs) == 1
            assert exhausted_logs[0].args[4]["attempts"] == 3


# ── 4. Fallback Handling on Vector DB Unreachable ──────────────────────────────


class TestOrchestratorFallback:
    """Test fallback when vector DB is offline during orchestration."""

    def test_retrieval_and_chaining_handles_unreachable_db(
        self, valid_input: ThreatAgentInput
    ) -> None:
        from agents.threat_agent.exceptions import KBStoreUnreachableError

        with (
            patch(
                "agents.threat_agent.orchestrator.fetch_candidates",
                side_effect=KBStoreUnreachableError(
                    "postgresql://trc:trc@localhost:5433/trc_knowledge_base",
                    cause=ConnectionRefusedError("Connection refused (offline unit test)"),
                ),
            ),
            patch("agents.threat_agent.orchestrator.log_step") as mock_log,
        ):
            paths = _execute_retrieval_and_chaining(valid_input)
            assert len(paths) > 0
            for path in paths:
                assert len(path.steps) > 0
                assert path.steps[0].pattern_id == "CWE-306"

            fallback_logs = [
                call
                for call in mock_log.call_args_list
                if call.args[2] == "retrieval_fallback_engaged"
            ]
            assert len(fallback_logs) == 1
            assert fallback_logs[0].args[4]["error_type"] == "KBStoreUnreachableError"


# ── 5. Router Status & Metric Observability ───────────────────────────────────


class TestRouterValidationMetrics:
    """Test that router accurately captures validator retries and validation status."""

    def test_router_records_validator_retries_and_status(
        self, valid_input: ThreatAgentInput
    ) -> None:
        test_app = FastAPI()
        test_app.include_router(threat_agent_router)

        scenario = _make_valid_scenario(run_id=valid_input.run_id)

        # Mock orchestrator returning 1 retry and "passed"
        def _mock_retried_orchestrator() -> Any:
            return lambda _payload: ([scenario], 1, "passed")

        test_app.dependency_overrides[get_run_store] = get_in_memory_run_store
        test_app.dependency_overrides[get_orchestrator] = _mock_retried_orchestrator

        clear_run_registry()
        client = TestClient(test_app)

        # 1. Analyze
        payload_dict = json.loads(valid_input.model_dump_json())
        res_analyze = client.post("/threat-agent/analyze", json=payload_dict)
        assert res_analyze.status_code == 202

        # 2. Status poll exposes validator metrics
        res_status = client.get(f"/threat-agent/{valid_input.run_id}/status")
        assert res_status.status_code == 200
        body = res_status.json()
        assert body["status"] == ThreatStatus.PENDING_HUMAN.value
        assert body["validator_retry_count"] == 1
        assert body["human_rejection_count"] == 0
        assert body["validation_status"] == "passed"

        # 3. Reject endpoint increments human_rejection_count without touching validator retries
        res_reject = client.post(
            f"/threat-agent/{valid_input.run_id}/reject",
            json={"reason": "Human reviewer requested deeper evidence."},
        )
        assert res_reject.status_code == 200
        reject_body = res_reject.json()
        assert reject_body["status"] == ThreatStatus.REJECTED.value
        assert reject_body["retry_count"] == 1
        assert reject_body["human_rejection_count"] == 1

        # Check status after rejection
        res_status_after = client.get(f"/threat-agent/{valid_input.run_id}/status")
        assert res_status_after.status_code == 200
        body_after = res_status_after.json()
        assert body_after["validator_retry_count"] == 1
        assert body_after["human_rejection_count"] == 1
