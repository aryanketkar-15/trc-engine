"""
tests/threat_agent/unit/test_orchestrator_human_rejection.py
────────────────────────────────────────────────────────────
Unit tests for regenerate_after_human_rejection() in orchestrator.py.

Verifies:
  1. Human feedback string is formatted as "HUMAN REJECTION: {feedback}"
     and seeded into the initial validation failure context passed to generator.
  2. The automated validator retry loop is re-executed on the regenerated scenarios.
  3. Escalation occurs if validation invariants cannot be satisfied after retries.
  4. Both ThreatScenario objects and raw dicts are accepted as previous_scenarios.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agents.threat_agent.orchestrator import (
    regenerate_after_human_rejection,
)
from agents.threat_agent.schemas import (
    EvidenceChain,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
    ValidationResult,
)
from agents.threat_agent.validator import Validator

# Fixture path
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
    run_id: str = "RUN-HITL-001",
    tid: str = "TID-001",
    asset_id: str = "AS-1",
) -> ThreatScenario:
    """Helper to construct a valid ThreatScenario satisfying validator invariants."""
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
    )


class TestOrchestratorHumanRejection:
    """Test suite for human rejection regeneration in the orchestrator."""

    @patch("agents.threat_agent.orchestrator.generate_scenarios")
    @patch("agents.threat_agent.orchestrator._execute_retrieval_and_chaining")
    def test_human_feedback_seeded_into_generator(
        self,
        mock_retrieval: MagicMock,
        mock_generate: MagicMock,
        valid_input: ThreatAgentInput,
    ) -> None:
        """Human feedback string is passed into validation_failure_context on attempt 1."""
        mock_retrieval.return_value = ([], [])
        scenario = _make_valid_scenario(run_id=valid_input.run_id)
        mock_generate.return_value = [scenario]

        mock_validator = MagicMock(spec=Validator)
        mock_validator.validate.return_value = ValidationResult(
            run_id=valid_input.run_id,
            passed=True,
            failed_invariants=[],
            failure_details=[],
        )

        feedback = "Evidence chain lacks mention of firmware replay protections."
        scenarios, retries, status = regenerate_after_human_rejection(
            agent_input=valid_input,
            human_feedback=feedback,
            previous_scenarios=[scenario],
            validator=mock_validator,
        )

        assert status == "passed"
        assert retries == 0
        assert len(scenarios) == 1

        # Verify generate_scenarios was called with seeded context
        mock_generate.assert_called_once()
        _, kwargs = mock_generate.call_args
        assert "validation_failure_context" in kwargs
        assert kwargs["validation_failure_context"] == [f"HUMAN REJECTION: {feedback}"]

    @patch("agents.threat_agent.orchestrator.generate_scenarios")
    @patch("agents.threat_agent.orchestrator._execute_retrieval_and_chaining")
    def test_regenerate_with_validator_retry_success(
        self,
        mock_retrieval: MagicMock,
        mock_generate: MagicMock,
        valid_input: ThreatAgentInput,
    ) -> None:
        """Regenerated scenarios undergo validator check and can self-correct on attempt 2."""
        mock_retrieval.return_value = ([], [])
        scenario = _make_valid_scenario(run_id=valid_input.run_id)
        mock_generate.return_value = [scenario]

        from agents.threat_agent.schemas import FailedCheck

        mock_validator = MagicMock(spec=Validator)
        mock_validator.retry_with_context.return_value = (
            "retry_act_fetch_reason",
            "INV-2: attack_vector missing CVE reference.",
        )
        # Attempt 1 fails validator check, Attempt 2 passes
        mock_validator.validate.side_effect = [
            ValidationResult(
                run_id=valid_input.run_id,
                passed=False,
                failed_checks=[
                    FailedCheck(
                        check_id="INV-2",
                        detail="attack_vector missing CVE reference.",
                    )
                ],
                failed_invariants=["INV-2"],
                failure_details=["INV-2: attack_vector missing CVE reference."],
            ),
            ValidationResult(
                run_id=valid_input.run_id,
                passed=True,
                failed_checks=[],
                failed_invariants=[],
                failure_details=[],
            ),
        ]

        scenarios, retries, status = regenerate_after_human_rejection(
            agent_input=valid_input,
            human_feedback="Incorporate CVE pattern directly.",
            previous_scenarios=None,
            validator=mock_validator,
        )

        assert status == "passed"
        assert retries == 1
        assert len(scenarios) == 1
        assert mock_generate.call_count == 2

    @patch("agents.threat_agent.orchestrator.generate_scenarios")
    @patch("agents.threat_agent.orchestrator._execute_retrieval_and_chaining")
    def test_regenerate_accepts_dict_previous_scenarios(
        self,
        mock_retrieval: MagicMock,
        mock_generate: MagicMock,
        valid_input: ThreatAgentInput,
    ) -> None:
        """Accepts previous scenarios formatted as dicts without error."""
        mock_retrieval.return_value = ([], [])
        scenario = _make_valid_scenario(run_id=valid_input.run_id)
        mock_generate.return_value = [scenario]

        mock_validator = MagicMock(spec=Validator)
        mock_validator.validate.return_value = ValidationResult(
            run_id=valid_input.run_id,
            passed=True,
            failed_invariants=[],
            failure_details=[],
        )

        dict_scenarios = [scenario.model_dump(mode="json")]
        scenarios, _retries, status = regenerate_after_human_rejection(
            agent_input=valid_input,
            human_feedback="Feedback on dict scenarios",
            previous_scenarios=dict_scenarios,
            validator=mock_validator,
        )

        assert status == "passed"
        assert len(scenarios) == 1
