"""
tests/threat_agent/integration/test_router_reject_regenerate.py
───────────────────────────────────────────────────────────────
Integration tests for the HITL Reject → Regenerate loop in router.py.

Verifies:
  1. POST /threat-agent/{run_id}/reject under cap (< 3):
     - Regenerates scenarios with reviewer's feedback.
     - Status stays 'pending_human'.
     - retry_count and human_rejection_count increment.
     - Returns updated scenarios in response.
     - Logs rejection to SCRS audit log and revision history.
  2. Rejections at/over cap (MAX_HUMAN_REJECTIONS = 3):
     - Transitions to terminal status='rejected'.
     - Further rejections return HTTP 409 Conflict.
  3. Rejection of approved run returns HTTP 409 Conflict.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.threat_agent.router import (
    clear_run_registry,
    get_orchestrator,
    get_regenerator,
)
from agents.threat_agent.router import (
    router as threat_agent_router,
)
from agents.threat_agent.run_store import (
    get_in_memory_run_store,
    get_run_store,
)
from agents.threat_agent.schemas import (
    EvidenceChain,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
    ThreatStatus,
)
from scrp.state_manager import StateManager

_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "e2e"
    / "fixtures"
    / "smart_door_lock"
    / "input.json"
)

TEST_API_KEY = "trc-dev-secret-key"


def _make_scenario(
    run_id: str,
    tid: str,
    vector_suffix: str = "",
) -> ThreatScenario:
    """Helper to create a valid ThreatScenario."""
    return ThreatScenario(
        tid=tid,
        run_id=run_id,
        asset_id="AS-1",
        stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        attack_vector=f"BLE GATT unauthorized unlock {vector_suffix}".strip(),
        kb_reference="CWE-306",
        evidence_chain=EvidenceChain(
            exposure="BLE characteristic allows unauthenticated write.",
            matched_pattern="CWE-306",
            applicability_reason="Motor unlock command requires no authentication.",
            citation="https://cwe.mitre.org/data/definitions/306.html",
        ),
        confidence_score=0.85,
    )


@pytest.fixture()
def valid_payload() -> dict[str, Any]:
    """Load canonical Smart Door Lock fixture."""
    with open(_FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture()
def app_and_client() -> tuple[FastAPI, TestClient]:
    """Create test application and authenticated client."""
    clear_run_registry()
    test_app = FastAPI()
    test_app.include_router(threat_agent_router)

    def _mock_orch(
        payload: ThreatAgentInput,
    ) -> tuple[list[ThreatScenario], int, str]:
        sc = _make_scenario(payload.run_id, "TID-INIT-1", "v1")
        return [sc], 0, "passed"

    def _mock_regen(
        agent_input: ThreatAgentInput,
        human_feedback: str,
        previous_scenarios: list[Any] | None = None,
    ) -> tuple[list[ThreatScenario], int, str]:
        sc = _make_scenario(
            agent_input.run_id,
            f"TID-REGEN-{secrets_token()}",
            f"revised: {human_feedback[:20]}",
        )
        return [sc], 0, "passed"

    _counter = 0

    def secrets_token() -> str:
        nonlocal _counter
        _counter += 1
        return str(_counter)

    test_app.dependency_overrides[get_run_store] = get_in_memory_run_store
    test_app.dependency_overrides[get_orchestrator] = lambda: _mock_orch
    test_app.dependency_overrides[get_regenerator] = lambda: _mock_regen

    client = TestClient(test_app, headers={"X-API-Key": TEST_API_KEY})
    return test_app, client


class TestRouterRejectRegenerate:
    """Integration test suite for reject -> regenerate flow."""

    def test_single_rejection_regenerates_and_stays_in_pending_human(
        self,
        app_and_client: tuple[FastAPI, TestClient],
        valid_payload: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """First rejection regenerates scenarios and keeps run in pending_human."""
        _, client = app_and_client
        run_id = valid_payload["run_id"]

        # 1. Analyze initial submission
        res_analyze = client.post("/threat-agent/analyze", json=valid_payload)
        assert res_analyze.status_code == 202

        # 2. Reject with reason
        reason = "Clarify attack vector with specific GATT characteristic."
        res_reject = client.post(
            f"/threat-agent/{run_id}/reject",
            json={"reason": reason},
        )
        assert res_reject.status_code == 200
        data = res_reject.json()

        assert data["run_id"] == run_id
        assert data["status"] == ThreatStatus.PENDING_HUMAN.value
        assert data["retry_count"] == 1
        assert data["human_rejection_count"] == 1
        assert data["scenarios"] is not None
        assert len(data["scenarios"]) == 1
        assert "revised:" in data["scenarios"][0]["attack_vector"]

        # 3. Check status endpoint reflects pending_human and counts
        res_status = client.get(f"/threat-agent/{run_id}/status")
        assert res_status.status_code == 200
        status_data = res_status.json()
        assert status_data["status"] == ThreatStatus.PENDING_HUMAN.value
        assert status_data["human_rejection_count"] == 1

        # 4. Check SCRS StateManager recorded the rejection
        state_mgr = StateManager()
        audit_log = state_mgr.get_audit_log()
        matching_entries = [
            e for e in audit_log if e.run_id == run_id and e.action == "reject"
        ]
        assert len(matching_entries) >= 1

    def test_rejections_until_cap_transitions_to_terminal_rejected(
        self,
        app_and_client: tuple[FastAPI, TestClient],
        valid_payload: dict[str, Any],
    ) -> None:
        """Rejecting MAX_HUMAN_REJECTIONS times triggers terminal status=rejected."""
        _, client = app_and_client
        run_id = valid_payload["run_id"]

        client.post("/threat-agent/analyze", json=valid_payload)

        # Reject 1: stays pending_human
        r1 = client.post(f"/threat-agent/{run_id}/reject", json={"reason": "Rejection 1"})
        assert r1.status_code == 200
        assert r1.json()["status"] == ThreatStatus.PENDING_HUMAN.value
        assert r1.json()["retry_count"] == 1

        # Reject 2: stays pending_human
        r2 = client.post(f"/threat-agent/{run_id}/reject", json={"reason": "Rejection 2"})
        assert r2.status_code == 200
        assert r2.json()["status"] == ThreatStatus.PENDING_HUMAN.value
        assert r2.json()["retry_count"] == 2

        # Reject 3: cap reached -> terminal rejected!
        r3 = client.post(f"/threat-agent/{run_id}/reject", json={"reason": "Rejection 3"})
        assert r3.status_code == 200
        assert r3.json()["status"] == ThreatStatus.REJECTED.value
        assert r3.json()["retry_count"] == 3
        assert r3.json()["human_rejection_count"] == 3
        assert r3.json()["scenarios"] is None

        # Subsequent rejection attempt returns 409 Conflict
        r4 = client.post(f"/threat-agent/{run_id}/reject", json={"reason": "Rejection 4"})
        assert r4.status_code == 409
        assert "already rejected" in r4.json()["detail"].lower()

    def test_reject_after_approval_returns_409(
        self,
        app_and_client: tuple[FastAPI, TestClient],
        valid_payload: dict[str, Any],
    ) -> None:
        """Rejecting an already-approved run returns 409 Conflict."""
        _, client = app_and_client
        run_id = valid_payload["run_id"]

        client.post("/threat-agent/analyze", json=valid_payload)

        # Approve run
        res_approve = client.post(f"/threat-agent/{run_id}/approve")
        assert res_approve.status_code == 200

        # Attempt to reject approved run
        res_reject = client.post(
            f"/threat-agent/{run_id}/reject",
            json={"reason": "Cannot reject approved"},
        )
        assert res_reject.status_code == 409
        assert "already approved" in res_reject.json()["detail"].lower()

    def test_reject_without_stored_agent_input_returns_422(
        self,
        app_and_client: tuple[FastAPI, TestClient],
    ) -> None:
        """Rejecting a run that has no stored agent_input returns 422 with explanation."""
        _, client = app_and_client
        store = get_in_memory_run_store()
        run_id = "RUN-LEGACY-NO-INPUT"
        store.create_run(
            run_id=run_id,
            status=ThreatStatus.PENDING_HUMAN,
            scenarios=[],
            agent_input={},
        )
        res = client.post(
            f"/threat-agent/{run_id}/reject",
            json={"reason": "Cannot regenerate without input model"},
        )
        assert res.status_code == 422
        assert "no stored system model" in res.json()["detail"].lower()
