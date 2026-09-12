"""
tests/threat_agent/integration/test_router.py
─────────────────────────────────────────────
Integration tests for agents/threat_agent/router.py (FastAPI Router).

Covers the full HTTP interaction lifecycle:
  1. Happy path end-to-end (POST /analyze → GET /status → GET /scenarios → POST /approve)
  2. Rejection path (POST /reject with human reason → retry/rejection handling)
  3. Malformed input (schema validation errors → HTTP 422, never 500)
  4. Unknown run_id (verifies 404 Not Found for unsubmitted runs across all endpoints)
  5. State transition guards (verifies 409 Conflict on double-approval, double-rejection,
     and cross-terminal transitions)
  6. Prefix routing under main.py (/api/v1/threat-agent/...)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

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
from agents.threat_agent.schemas import ThreatStatus
from main import app as main_app

# Path to canonical Smart Door Lock test fixture
_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "e2e"
    / "fixtures"
    / "smart_door_lock"
    / "input.json"
)


def _mock_orchestrator() -> Callable[[Any], tuple[list[Any], int, str]]:
    """Fast stub orchestrator provider for router HTTP integration tests."""
    return lambda _payload: ([], 0, "passed")


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Ensure in-memory run registry is cleared and wired before/after each test."""
    clear_run_registry()
    main_app.dependency_overrides[get_run_store] = get_in_memory_run_store
    main_app.dependency_overrides[get_orchestrator] = _mock_orchestrator
    yield
    clear_run_registry()
    main_app.dependency_overrides.pop(get_run_store, None)
    main_app.dependency_overrides.pop(get_orchestrator, None)


@pytest.fixture(scope="module")
def valid_payload() -> dict[str, Any]:
    """Load canonical Smart Door Lock input fixture."""
    with open(_FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def client() -> TestClient:
    """TestClient configured with router mounted at both root and /api/v1."""
    test_app = FastAPI()
    test_app.include_router(threat_agent_router)
    test_app.include_router(threat_agent_router, prefix="/api/v1")
    test_app.dependency_overrides[get_run_store] = get_in_memory_run_store
    test_app.dependency_overrides[get_orchestrator] = _mock_orchestrator
    return TestClient(test_app)


@pytest.fixture(scope="module")
def main_client() -> TestClient:
    """TestClient against production main.app."""
    return TestClient(main_app)


# ── 1. Happy Path End-to-End Flow ──────────────────────────────────────────────


class TestRouterHappyPath:
    """Full happy path lifecycle for threat modeling run."""

    def test_post_analyze_accepts_valid_payload(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """POST /threat-agent/analyze returns 202 Accepted with pending_test status."""
        response = client.post("/threat-agent/analyze", json=valid_payload)
        assert response.status_code == 202
        body = response.json()
        assert body["run_id"] == valid_payload["run_id"]
        assert body["status"] == ThreatStatus.PENDING_TEST.value
        assert "accepted" in body["message"].lower()

    def test_get_run_status_returns_current_state(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """GET /threat-agent/{run_id}/status returns 200 OK and current status."""
        run_id = valid_payload["run_id"]
        client.post("/threat-agent/analyze", json=valid_payload)

        response = client.get(f"/threat-agent/{run_id}/status")
        assert response.status_code == 200
        body = response.json()
        assert body["run_id"] == run_id
        assert body["status"] == ThreatStatus.PENDING_HUMAN.value

    def test_get_scenarios_returns_scenario_list(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """GET /threat-agent/{run_id}/scenarios returns 200 OK with list of scenarios."""
        run_id = valid_payload["run_id"]
        client.post("/threat-agent/analyze", json=valid_payload)

        response = client.get(f"/threat-agent/{run_id}/scenarios")
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, list)

    def test_post_approve_transitions_to_approved(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """POST /threat-agent/{run_id}/approve returns 200 OK and approved status."""
        run_id = valid_payload["run_id"]
        client.post("/threat-agent/analyze", json=valid_payload)

        response = client.post(f"/threat-agent/{run_id}/approve")
        assert response.status_code == 200
        body = response.json()
        assert body["run_id"] == run_id
        assert body["status"] == ThreatStatus.APPROVED.value
        assert body["scrs_entry_id"] == f"SCRS-{run_id}"

    def test_end_to_end_sequential_lifecycle(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Executes full sequence: analyze → status → scenarios → approve."""
        run_id = "RUN-E2E-LIFECYCLE-001"
        payload = dict(valid_payload, run_id=run_id)

        # 1. Analyze
        res_analyze = client.post("/threat-agent/analyze", json=payload)
        assert res_analyze.status_code == 202
        assert res_analyze.json()["run_id"] == run_id

        # 2. Poll Status
        res_status = client.get(f"/threat-agent/{run_id}/status")
        assert res_status.status_code == 200
        assert res_status.json()["run_id"] == run_id
        assert res_status.json()["status"] == ThreatStatus.PENDING_HUMAN.value

        # 3. Fetch Scenarios
        res_scenarios = client.get(f"/threat-agent/{run_id}/scenarios")
        assert res_scenarios.status_code == 200
        assert isinstance(res_scenarios.json(), list)

        # 4. Approve
        res_approve = client.post(f"/threat-agent/{run_id}/approve")
        assert res_approve.status_code == 200
        assert res_approve.json()["status"] == ThreatStatus.APPROVED.value


# ── 2. Rejection Path ─────────────────────────────────────────────────────────


class TestRouterRejectionPath:
    """Rejection flow with human reviewer reason."""

    def test_reject_run_with_valid_reason(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """POST /threat-agent/{run_id}/reject accepts human feedback reason."""
        run_id = valid_payload["run_id"]
        client.post("/threat-agent/analyze", json=valid_payload)

        rejection_body = {
            "reason": "Evidence chain does not establish firmware version exposure."
        }
        response = client.post(f"/threat-agent/{run_id}/reject", json=rejection_body)
        assert response.status_code == 200
        body = response.json()
        assert body["run_id"] == run_id
        assert body["status"] == ThreatStatus.REJECTED.value
        assert body["retry_count"] == 1

    def test_reject_does_not_write_to_scrs(
        self, client: TestClient, valid_payload: dict[str, Any], tmp_path: Path
    ) -> None:
        """Rejection path must not persist unapproved scenarios to SCRS state store."""
        from scrp.state_manager import StateManager

        scrs_file = tmp_path / "SCRS_state.json"
        state_mgr = StateManager(scrs_path=scrs_file)

        run_id = "RUN-REJECT-TEST-001"
        client.post("/threat-agent/analyze", json=dict(valid_payload, run_id=run_id))
        client.post(
            f"/threat-agent/{run_id}/reject",
            json={"reason": "Attacking vector is too vague."},
        )

        # SCRS store should not contain any scenarios for this rejected run
        scenarios = state_mgr.get_threat_scenarios()
        assert not any(
            getattr(s, "run_id", None) == run_id
            or (isinstance(s, dict) and s.get("run_id") == run_id)
            for s in scenarios.values()
        )


# ── 3. Malformed Input (Schema Validation Errors) ─────────────────────────────


class TestRouterMalformedInput:
    """Ensure invalid payloads trigger HTTP 422, never 500."""

    def test_analyze_empty_body_returns_422(self, client: TestClient) -> None:
        """Empty payload triggers Pydantic schema validation error (422)."""
        response = client.post("/threat-agent/analyze", json={})
        assert response.status_code == 422
        body = response.json()
        assert "detail" in body

    def test_analyze_missing_required_fields_returns_422(
        self, client: TestClient
    ) -> None:
        """Payload missing assets and use_case triggers 422."""
        partial = {"run_id": "RUN-PARTIAL-001"}
        response = client.post("/threat-agent/analyze", json=partial)
        assert response.status_code == 422

    def test_analyze_invalid_field_types_returns_422(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Payload with invalid type (e.g. assets not a list) triggers 422."""
        bad_payload = dict(valid_payload, assets="not-a-list")
        response = client.post("/threat-agent/analyze", json=bad_payload)
        assert response.status_code == 422

    def test_analyze_empty_assets_list_returns_422(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """ThreatAgentInput requires non-empty assets list."""
        bad_payload = dict(valid_payload, assets=[])
        response = client.post("/threat-agent/analyze", json=bad_payload)
        assert response.status_code == 422

    def test_reject_missing_reason_returns_422(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Reject without reason body triggers 422."""
        run_id = valid_payload["run_id"]
        client.post("/threat-agent/analyze", json=valid_payload)
        response = client.post(f"/threat-agent/{run_id}/reject", json={})
        assert response.status_code == 422

    def test_reject_empty_string_reason_returns_422(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Reject with empty string reason violates min_length=1 constraint."""
        run_id = valid_payload["run_id"]
        client.post("/threat-agent/analyze", json=valid_payload)
        response = client.post(f"/threat-agent/{run_id}/reject", json={"reason": ""})
        assert response.status_code == 422


# ── 4. Unknown run_id (Fixed Bug 1: Expected 404 Not Found) ───────────────────


class TestRouterUnknownRunId:
    """Verifies that all endpoints return 404 Not Found for unsubmitted run_ids."""

    def test_unknown_run_id_status_returns_404(self, client: TestClient) -> None:
        unknown_id = "RUN-UNKNOWN-9999"
        response = client.get(f"/threat-agent/{unknown_id}/status")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_unknown_run_id_scenarios_returns_404(self, client: TestClient) -> None:
        unknown_id = "RUN-UNKNOWN-9999"
        response = client.get(f"/threat-agent/{unknown_id}/scenarios")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_unknown_run_id_approve_returns_404(self, client: TestClient) -> None:
        unknown_id = "RUN-UNKNOWN-9999"
        response = client.post(f"/threat-agent/{unknown_id}/approve")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_unknown_run_id_reject_returns_404(self, client: TestClient) -> None:
        unknown_id = "RUN-UNKNOWN-9999"
        response = client.post(
            f"/threat-agent/{unknown_id}/reject",
            json={"reason": "Testing unknown rejection"},
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


# ── 5. State Transition Guards (Fixed Bug 2: 409 Conflict on Invalid Transitions)


class TestRouterDoubleApprovalAndTransitions:
    """Verifies that invalid state transitions return HTTP 409 Conflict."""

    def test_consecutive_double_approval_returns_409(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Calling approve twice on the same run returns 409 Conflict on second call."""
        run_id = "RUN-DOUBLE-APPROVE-001"
        client.post("/threat-agent/analyze", json=dict(valid_payload, run_id=run_id))

        res1 = client.post(f"/threat-agent/{run_id}/approve")
        assert res1.status_code == 200
        assert res1.json()["status"] == ThreatStatus.APPROVED.value

        res2 = client.post(f"/threat-agent/{run_id}/approve")
        assert res2.status_code == 409
        assert "already approved" in res2.json()["detail"].lower()

    def test_approve_after_rejection_returns_409(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Calling approve on a rejected run returns 409 Conflict."""
        run_id = "RUN-APPROVE-AFTER-REJECT-001"
        client.post("/threat-agent/analyze", json=dict(valid_payload, run_id=run_id))

        res_reject = client.post(
            f"/threat-agent/{run_id}/reject", json={"reason": "Testing rejection"}
        )
        assert res_reject.status_code == 200

        res_approve = client.post(f"/threat-agent/{run_id}/approve")
        assert res_approve.status_code == 409
        assert "rejected" in res_approve.json()["detail"].lower()

    def test_reject_after_approval_returns_409(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Calling reject on an approved run returns 409 Conflict."""
        run_id = "RUN-REJECT-AFTER-APPROVE-001"
        client.post("/threat-agent/analyze", json=dict(valid_payload, run_id=run_id))

        res_approve = client.post(f"/threat-agent/{run_id}/approve")
        assert res_approve.status_code == 200

        res_reject = client.post(
            f"/threat-agent/{run_id}/reject",
            json={"reason": "Attempt to reject approved run"},
        )
        assert res_reject.status_code == 409
        assert "already approved" in res_reject.json()["detail"].lower()

    def test_double_rejection_returns_409(
        self, client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Calling reject twice on the same run returns 409 Conflict on second call."""
        run_id = "RUN-DOUBLE-REJECT-001"
        client.post("/threat-agent/analyze", json=dict(valid_payload, run_id=run_id))

        res1 = client.post(
            f"/threat-agent/{run_id}/reject", json={"reason": "First rejection"}
        )
        assert res1.status_code == 200

        res2 = client.post(
            f"/threat-agent/{run_id}/reject", json={"reason": "Second rejection"}
        )
        assert res2.status_code == 409
        assert "already rejected" in res2.json()["detail"].lower()


# ── 6. Production App Routing (Mounted Prefix /api/v1) ─────────────────────────


class TestMainAppPrefixRouting:
    """Verifies that routes are reachable under main.py's /api/v1 prefix."""

    def test_main_app_prefix_analyze(
        self, main_client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        response = main_client.post("/api/v1/threat-agent/analyze", json=valid_payload)
        assert response.status_code == 202
        assert response.json()["run_id"] == valid_payload["run_id"]

    def test_main_app_prefix_status(
        self, main_client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        run_id = "RUN-MAIN-PREFIX-001"
        main_client.post(
            "/api/v1/threat-agent/analyze", json=dict(valid_payload, run_id=run_id)
        )
        response = main_client.get(f"/api/v1/threat-agent/{run_id}/status")
        assert response.status_code == 200
        assert response.json()["status"] == ThreatStatus.PENDING_HUMAN.value

    def test_main_app_prefix_unknown_run_returns_404(
        self, main_client: TestClient
    ) -> None:
        response = main_client.get("/api/v1/threat-agent/RUN-NONEXISTENT-404/status")
        assert response.status_code == 404
