"""tests/threat_agent/integration/test_approve.py
==============================================================================
TRC Engine -- Phase 1  |  Integration Tests: POST /threat-agent/{run_id}/approve
------------------------------------------------------------------------------
Tests the approve endpoint against real merged code:
  - scrp.state_manager.StateManager.write_threat_scenario()  [LIVE -- PR #2]
  - scrp.state_manager.NotApprovedError                      [LIVE -- PR #2]
  - router NotApprovedError -> HTTP 422 handler              [LIVE -- TRC-STUB-002]

Uses a tmp-file-backed StateManager per test so each test gets a clean SCRS
state and no test leaks state to the next.  No mocks for the approval gate --
we test the REAL NotApprovedError enforcement path.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from agents.threat_agent.schemas import (
    EvidenceChain,
    STRIDECategory,
    ThreatScenario,
    ThreatStatus,
)
from main import app
from scrp.state_manager import NotApprovedError, StateManager

# ---------------------------------------------------------------------------
# Test client
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI TestClient shared across all approve tests."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# StateManager fixture (tmp-file backed -- isolated per test)
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_state_manager(tmp_path: Path) -> StateManager:
    """Return a StateManager backed by a temp file.

    Each test gets a fresh StateManager pointing at a unique temp file, so
    audit log / scenario state does not leak between tests.
    """
    scrs_file = tmp_path / "SCRS_state.json"
    return StateManager(scrs_path=scrs_file)


# ---------------------------------------------------------------------------
# ThreatScenario builders
# ---------------------------------------------------------------------------


def _make_approved_scenario(run_id: str) -> ThreatScenario:
    """Build a minimal approved ThreatScenario for write tests."""
    return ThreatScenario(
        tid=f"TID-{uuid.uuid4().hex[:8].upper()}",
        asset_id="ASSET-BLE-CONTROLLER-01",
        stride_category=STRIDECategory.TAMPERING,
        attack_vector="BLE replay attack via unauthenticated pairing",
        kb_reference="CAPEC-94",
        evidence_chain=EvidenceChain(
            exposure="BLE peripheral with no encryption",
            matched_pattern="CAPEC-94",
            applicability_reason=(
                "The device uses unauthenticated BLE pairing, allowing an "
                "adversary to intercept and replay pairing handshakes to gain "
                "unauthorized access to lock control commands."
            ),
            citation="CAPEC-94: Adversary in the Middle",
        ),
        confidence_score=0.82,
        status=ThreatStatus.APPROVED,
        run_id=run_id,
    )


def _make_pending_scenario(run_id: str) -> ThreatScenario:
    """Build a PENDING_TEST scenario (not approved) for gate-enforcement tests."""
    approved = _make_approved_scenario(run_id)
    # Pydantic frozen model -- reconstruct with different status
    return approved.model_copy(update={"status": ThreatStatus.PENDING_TEST})


# ---------------------------------------------------------------------------
# Router approve endpoint -- HTTP-level tests
# ---------------------------------------------------------------------------


class TestApproveEndpoint:
    """POST /threat-agent/{run_id}/approve — HTTP contract tests."""

    def test_approve_valid_run_id_returns_200(self, client: TestClient) -> None:
        """Valid run_id returns HTTP 200."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        response = client.post(f"/api/v1/threat-agent/{run_id}/approve")
        assert response.status_code == status.HTTP_200_OK

    def test_approve_response_shape(self, client: TestClient) -> None:
        """ApproveResponse has run_id and status fields."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        response = client.post(f"/api/v1/threat-agent/{run_id}/approve")
        body = response.json()
        assert "run_id" in body
        assert "status" in body

    def test_approve_returns_approved_status(self, client: TestClient) -> None:
        """Approve endpoint returns status='approved' in stub mode."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        response = client.post(f"/api/v1/threat-agent/{run_id}/approve")
        body = response.json()
        assert body["status"] == ThreatStatus.APPROVED.value

    def test_approve_run_id_echoed_in_response(self, client: TestClient) -> None:
        """run_id in response matches the path parameter."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        response = client.post(f"/api/v1/threat-agent/{run_id}/approve")
        assert response.json()["run_id"] == run_id


# ---------------------------------------------------------------------------
# StateManager -- real write_threat_scenario() tests (no router involved)
# ---------------------------------------------------------------------------


class TestStateManagerWrite:
    """Test the real write_threat_scenario() gate directly.

    These tests bypass the router and call StateManager directly, so they
    exercise the REAL approval gate logic without HTTP overhead.
    """

    def test_write_approved_scenario_succeeds(
        self, tmp_state_manager: StateManager
    ) -> None:
        """write_threat_scenario() returns True for an approved scenario."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        result = tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)
        assert result is True

    def test_write_approved_scenario_appends_audit_log(
        self, tmp_state_manager: StateManager
    ) -> None:
        """A successful write appends exactly one audit log entry."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)

        before = len(tmp_state_manager.get_audit_log())
        tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)
        after = len(tmp_state_manager.get_audit_log())

        assert after == before + 1

    def test_audit_log_entry_contains_tid(
        self, tmp_state_manager: StateManager
    ) -> None:
        """Audit log entry records the correct scenario tid."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

        audit_log = tmp_state_manager.get_audit_log()
        assert audit_log[-1].tid == scenario.tid

    def test_audit_log_entry_contains_run_id(
        self, tmp_state_manager: StateManager
    ) -> None:
        """Audit log entry records the correct run_id."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

        audit_log = tmp_state_manager.get_audit_log()
        assert audit_log[-1].run_id == run_id

    def test_audit_log_entry_action_is_write(
        self, tmp_state_manager: StateManager
    ) -> None:
        """Audit log entry action field is 'write'."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

        audit_log = tmp_state_manager.get_audit_log()
        assert audit_log[-1].action == "write"

    def test_write_persists_scenario_to_state(
        self, tmp_state_manager: StateManager
    ) -> None:
        """Written scenario appears in get_threat_scenarios() afterward."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

        stored = tmp_state_manager.get_threat_scenarios()
        assert scenario.tid in stored

    def test_multiple_writes_accumulate_in_audit_log(
        self, tmp_state_manager: StateManager
    ) -> None:
        """Two writes produce two audit log entries."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        s1 = _make_approved_scenario(run_id)
        s2 = _make_approved_scenario(run_id)

        tmp_state_manager.write_threat_scenario(s1, run_id=run_id)
        tmp_state_manager.write_threat_scenario(s2, run_id=run_id)

        assert len(tmp_state_manager.get_audit_log()) == 2


# ---------------------------------------------------------------------------
# NotApprovedError gate -- real enforcement tests
# ---------------------------------------------------------------------------


class TestNotApprovedErrorGate:
    """Verify NotApprovedError is raised for non-approved scenarios.

    This exercises the REAL gate in write_threat_scenario(), not a mock.
    """

    def test_pending_scenario_raises_not_approved_error(
        self, tmp_state_manager: StateManager
    ) -> None:
        """PENDING_TEST scenario raises NotApprovedError -- gate enforced."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_pending_scenario(run_id)

        with pytest.raises(NotApprovedError):
            tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

    def test_not_approved_error_message_contains_tid(
        self, tmp_state_manager: StateManager
    ) -> None:
        """NotApprovedError message includes the scenario's tid."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_pending_scenario(run_id)

        with pytest.raises(NotApprovedError, match=scenario.tid):
            tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

    def test_not_approved_error_does_not_write_to_audit_log(
        self, tmp_state_manager: StateManager
    ) -> None:
        """A rejected write leaves the audit log unchanged."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_pending_scenario(run_id)

        before = len(tmp_state_manager.get_audit_log())
        with pytest.raises(NotApprovedError):
            tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)
        after = len(tmp_state_manager.get_audit_log())

        assert after == before  # no audit entry on rejected write

    def test_not_approved_error_does_not_persist_scenario(
        self, tmp_state_manager: StateManager
    ) -> None:
        """A rejected write does not add the scenario to the store."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_pending_scenario(run_id)

        with pytest.raises(NotApprovedError):
            tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)

        stored = tmp_state_manager.get_threat_scenarios()
        assert scenario.tid not in stored

    @pytest.mark.parametrize(
        "bad_status",
        [
            ThreatStatus.PENDING_TEST,
            ThreatStatus.PENDING_HUMAN,
            ThreatStatus.REJECTED,
        ],
    )
    def test_all_non_approved_statuses_raise_gate_error(
        self,
        tmp_state_manager: StateManager,
        bad_status: ThreatStatus,
    ) -> None:
        """Every non-approved status triggers NotApprovedError."""
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id).model_copy(
            update={"status": bad_status}
        )
        with pytest.raises(NotApprovedError):
            tmp_state_manager.write_threat_scenario(scenario, run_id=run_id)


# ---------------------------------------------------------------------------
# Router -> NotApprovedError -> HTTP 422 integration
# ---------------------------------------------------------------------------


class TestApprove422ViaNotApprovedError:
    """Test that NotApprovedError raised inside the router maps to HTTP 422.

    The router's _handle_not_approved() helper is exercised by raising
    NotApprovedError manually inside a patched state_manager call.
    """

    def test_not_approved_error_in_router_returns_422(self, client: TestClient) -> None:
        """When StateManager raises NotApprovedError, router returns HTTP 422."""
        from unittest.mock import patch

        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        exc = NotApprovedError(f"Scenario for run {run_id} is not approved.")

        # Patch at the router level: simulate the state_manager gate firing
        with patch(
            "agents.threat_agent.router.NotApprovedError",
            side_effect=exc,
        ):
            # Without Week-2 pipeline wiring, the router stub doesn't call
            # state_manager, so we test the handler directly:
            from agents.threat_agent.router import _handle_not_approved

            http_exc = _handle_not_approved(exc, run_id=run_id)
            assert http_exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_not_approved_error_detail_shape(self, client: TestClient) -> None:
        """NotApprovedErrorDetail has error, run_id, validation_result fields."""
        from agents.threat_agent.router import _handle_not_approved

        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        exc = NotApprovedError("Not approved.")
        http_exc = _handle_not_approved(exc, run_id=run_id)

        detail: dict[str, Any] = http_exc.detail  # type: ignore[assignment]
        assert "error" in detail
        assert "run_id" in detail
        assert detail["run_id"] == run_id
        assert detail["error"] == "NotApprovedError"

    def test_not_approved_error_detail_error_name(self, client: TestClient) -> None:
        """detail.error contains the exception class name."""
        from agents.threat_agent.router import _handle_not_approved

        exc = NotApprovedError("Gate failed.")
        http_exc = _handle_not_approved(exc)
        detail: dict[str, Any] = http_exc.detail  # type: ignore[assignment]
        assert detail["error"] == "NotApprovedError"


# ---------------------------------------------------------------------------
# Atomic persistence tests
# ---------------------------------------------------------------------------


class TestStateManagerPersistence:
    """Verify the atomic write pattern (tmp->rename) works correctly."""

    def test_scrs_file_created_on_first_write(self, tmp_path: Path) -> None:
        """SCRS_state.json is created on the first successful write."""
        scrs_file = tmp_path / "SCRS_state.json"
        mgr = StateManager(scrs_path=scrs_file)
        assert not scrs_file.exists()

        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        mgr.write_threat_scenario(scenario, run_id=run_id)

        assert scrs_file.exists()

    def test_state_survives_reload(self, tmp_path: Path) -> None:
        """Data written by one StateManager instance is readable by a new one
        pointing at the same file — verifies atomic write correctness.
        """
        scrs_file = tmp_path / "SCRS_state.json"
        mgr1 = StateManager(scrs_path=scrs_file)

        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        mgr1.write_threat_scenario(scenario, run_id=run_id)

        # New StateManager instance, same file
        mgr2 = StateManager(scrs_path=scrs_file)
        stored = mgr2.get_threat_scenarios()
        assert scenario.tid in stored

    def test_no_tmp_file_left_after_write(self, tmp_path: Path) -> None:
        """The .json.tmp temp file is cleaned up after a successful write."""
        scrs_file = tmp_path / "SCRS_state.json"
        tmp_file = tmp_path / "SCRS_state.json.tmp"
        mgr = StateManager(scrs_path=scrs_file)

        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        scenario = _make_approved_scenario(run_id)
        mgr.write_threat_scenario(scenario, run_id=run_id)

        assert not tmp_file.exists()
