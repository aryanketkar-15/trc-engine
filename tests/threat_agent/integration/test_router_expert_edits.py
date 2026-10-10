"""Approve -> shared state, and expert prune/add, via the HTTP router.

Covers the company spec's "expert prunes/adds" checkpoint (SRS 3.2 step 4) and
the requirement that approved output reaches the shared state.  Runs fully
in-memory; the SCRS file is redirected to a temp path by tests/threat_agent/conftest.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.threat_agent.router import clear_run_registry, get_orchestrator
from agents.threat_agent.router import router as threat_agent_router
from agents.threat_agent.run_store import get_in_memory_run_store, get_run_store
from agents.threat_agent.schemas import (
    EvidenceChain,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
)
from scrp.state_manager import StateManager

API_KEY = "trc-dev-secret-key"
_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "e2e" / "fixtures" / "smart_door_lock" / "input.json"
)


def _scenario(run_id: str, tid: str, asset: str = "AS-1") -> ThreatScenario:
    return ThreatScenario(
        tid=tid,
        run_id=run_id,
        asset_id=asset,
        stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        attack_vector=f"Unauthenticated BLE command for {tid}",
        kb_reference="CWE-306",
        evidence_chain=EvidenceChain(
            exposure="BLE characteristic accepts unauthenticated writes.",
            matched_pattern="CWE-306",
            applicability_reason="Unlock command requires no authentication at all.",
            citation="CWE-306: Missing Authentication for Critical Function",
        ),
        confidence_score=0.8,
        validation_status="passed",
    )


def _mock_orch(payload: ThreatAgentInput) -> tuple[list[ThreatScenario], int, str]:
    return [_scenario(payload.run_id, "TID-A"), _scenario(payload.run_id, "TID-B")], 0, "passed"


@pytest.fixture()
def payload() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _make_client(headers: dict[str, str] | None) -> TestClient:
    app = FastAPI()
    app.include_router(threat_agent_router)
    app.dependency_overrides[get_run_store] = get_in_memory_run_store
    app.dependency_overrides[get_orchestrator] = lambda: _mock_orch
    return TestClient(app, headers=headers or {})


@pytest.fixture()
def client() -> TestClient:
    clear_run_registry()
    return _make_client({"X-API-Key": API_KEY})


def _start(client: TestClient, payload: dict[str, Any], run_id: str) -> str:
    assert client.post("/threat-agent/analyze", json={**payload, "run_id": run_id}).status_code == 202
    return run_id


def _expert_body(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "asset_id": "AS-1",
        "stride_category": "Spoofing",
        "attack_vector": "Replay of a captured BLE unlock command by a nearby attacker",
        "kb_reference": "CAPEC-94",
        "evidence_chain": {
            "exposure": "BLE unlock characteristic has no session binding or nonce.",
            "matched_pattern": "CAPEC-94",
            "applicability_reason": "The lock accepts any previously captured unlock frame.",
            "citation": "CAPEC-94: Adversary in the Middle (AiTM)",
        },
        "justification": "Expert knows this attack from field reports.",
    }
    body.update(over)
    return body


class TestApproveWritesSharedState:
    def test_approve_persists_all_scenarios_with_audit(
        self, client: TestClient, payload: dict[str, Any], scrs_path: Path
    ) -> None:
        run_id = _start(client, payload, "RUN-APPROVE-1")
        res = client.post(f"/threat-agent/{run_id}/approve")
        assert res.status_code == 200
        assert res.json()["scenarios_written"] == 2

        mgr = StateManager(scrs_path=scrs_path)
        assert set(mgr.get_threat_scenarios()) == {"TID-A", "TID-B"}
        stored = mgr.get_threat_scenarios()["TID-A"]
        assert isinstance(stored, dict) and stored["status"] == "approved"
        actions = [(e.tid, e.action) for e in mgr.get_audit_log() if e.run_id == run_id]
        for tid in ("TID-A", "TID-B"):
            assert (tid, "write") in actions and (tid, "approve") in actions

    def test_unapproved_run_writes_nothing(
        self, client: TestClient, payload: dict[str, Any], scrs_path: Path
    ) -> None:
        _start(client, payload, "RUN-APPROVE-2")
        assert not scrs_path.exists() or not StateManager(scrs_path).get_threat_scenarios()

    def test_empty_run_can_still_be_approved(
        self, client: TestClient, payload: dict[str, Any]
    ) -> None:
        run_id = _start(client, payload, "RUN-APPROVE-3")
        for tid in ("TID-A", "TID-B"):
            client.post(f"/threat-agent/{run_id}/scenarios/{tid}/prune", json={"reason": "n/a here"})
        res = client.post(f"/threat-agent/{run_id}/approve")
        assert res.status_code == 200 and res.json()["scenarios_written"] == 0


class TestExpertPrune:
    def test_prune_removes_from_review_but_keeps_audit(
        self, client: TestClient, payload: dict[str, Any], scrs_path: Path
    ) -> None:
        run_id = _start(client, payload, "RUN-PRUNE-1")
        res = client.post(
            f"/threat-agent/{run_id}/scenarios/TID-A/prune",
            json={"reason": "Not applicable: lock has no BLE write path."},
        )
        assert res.status_code == 200
        assert res.json()["remaining_scenarios"] == 1

        listed = client.get(f"/threat-agent/{run_id}/scenarios").json()
        assert [s["tid"] for s in listed] == ["TID-B"]

        record = get_in_memory_run_store().get_run(run_id)
        assert record is not None and record.edit_history[0]["action"] == "prune"
        assert record.edit_history[0]["scenario"]["tid"] == "TID-A"  # type: ignore[index]

        mgr = StateManager(scrs_path=scrs_path)
        hist = mgr.get_revision_history(run_id)
        assert hist[0]["action"] == "prune"
        assert any(e.action == "prune" and e.tid == "TID-A" for e in mgr.get_audit_log())

    def test_approve_after_prune_writes_only_remaining(
        self, client: TestClient, payload: dict[str, Any], scrs_path: Path
    ) -> None:
        run_id = _start(client, payload, "RUN-PRUNE-2")
        client.post(f"/threat-agent/{run_id}/scenarios/TID-A/prune", json={"reason": "duplicate"})
        res = client.post(f"/threat-agent/{run_id}/approve")
        assert res.json()["scenarios_written"] == 1
        assert set(StateManager(scrs_path).get_threat_scenarios()) == {"TID-B"}

    def test_prune_unknown_tid_is_404(self, client: TestClient, payload: dict[str, Any]) -> None:
        run_id = _start(client, payload, "RUN-PRUNE-3")
        res = client.post(f"/threat-agent/{run_id}/scenarios/NOPE/prune", json={"reason": "x"})
        assert res.status_code == 404

    def test_prune_requires_reason(self, client: TestClient, payload: dict[str, Any]) -> None:
        run_id = _start(client, payload, "RUN-PRUNE-4")
        res = client.post(f"/threat-agent/{run_id}/scenarios/TID-A/prune", json={"reason": ""})
        assert res.status_code == 422

    def test_prune_after_approval_is_409(self, client: TestClient, payload: dict[str, Any]) -> None:
        run_id = _start(client, payload, "RUN-PRUNE-5")
        client.post(f"/threat-agent/{run_id}/approve")
        res = client.post(f"/threat-agent/{run_id}/scenarios/TID-A/prune", json={"reason": "late"})
        assert res.status_code == 409


class TestExpertAdd:
    def test_valid_expert_scenario_is_added_and_approved(
        self, client: TestClient, payload: dict[str, Any], scrs_path: Path
    ) -> None:
        run_id = _start(client, payload, "RUN-ADD-1")
        res = client.post(f"/threat-agent/{run_id}/scenarios", json=_expert_body())
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["tid"].startswith("THR-EXP-") and body["scenario_count"] == 3

        listed = client.get(f"/threat-agent/{run_id}/scenarios").json()
        added = next(s for s in listed if s["tid"] == body["tid"])
        assert added["validation_status"] == "expert_added"

        client.post(f"/threat-agent/{run_id}/approve")
        mgr = StateManager(scrs_path)
        assert body["tid"] in mgr.get_threat_scenarios()
        assert any(e.action == "add" and e.tid == body["tid"] for e in mgr.get_audit_log())

    def test_scenario_failing_validator_is_rejected_and_list_unchanged(
        self, client: TestClient, payload: dict[str, Any]
    ) -> None:
        run_id = _start(client, payload, "RUN-ADD-2")
        bad = _expert_body()
        bad["evidence_chain"]["citation"] = "TBD"
        res = client.post(f"/threat-agent/{run_id}/scenarios", json=bad)
        assert res.status_code == 422
        ids = [fc["check_id"] for fc in res.json()["detail"]["failed_checks"]]
        assert "CITATION_MISSING" in ids
        assert len(client.get(f"/threat-agent/{run_id}/scenarios").json()) == 2

    def test_kb_reference_missing_from_kb_is_rejected(
        self, client: TestClient, payload: dict[str, Any]
    ) -> None:
        run_id = _start(client, payload, "RUN-ADD-KB")
        with patch("agents.threat_agent.router.kb_reference_exists", return_value=False):
            res = client.post(f"/threat-agent/{run_id}/scenarios", json=_expert_body())
        assert res.status_code == 422
        assert "does not exist in the knowledge base" in res.json()["detail"]
        assert len(client.get(f"/threat-agent/{run_id}/scenarios").json()) == 2

    def test_kb_unreachable_does_not_block_the_expert(
        self, client: TestClient, payload: dict[str, Any]
    ) -> None:
        run_id = _start(client, payload, "RUN-ADD-KB2")
        with patch("agents.threat_agent.router.kb_reference_exists", return_value=None):
            res = client.post(f"/threat-agent/{run_id}/scenarios", json=_expert_body())
        assert res.status_code == 201

    def test_unknown_asset_is_rejected(self, client: TestClient, payload: dict[str, Any]) -> None:
        run_id = _start(client, payload, "RUN-ADD-3")
        res = client.post(f"/threat-agent/{run_id}/scenarios", json=_expert_body(asset_id="AS-99"))
        assert res.status_code == 422

    def test_add_after_approval_is_409(self, client: TestClient, payload: dict[str, Any]) -> None:
        run_id = _start(client, payload, "RUN-ADD-4")
        client.post(f"/threat-agent/{run_id}/approve")
        assert client.post(f"/threat-agent/{run_id}/scenarios", json=_expert_body()).status_code == 409


class TestAuth:
    def test_edit_endpoints_require_api_key(self, payload: dict[str, Any]) -> None:
        clear_run_registry()
        authed = _make_client({"X-API-Key": API_KEY})
        run_id = _start(authed, payload, "RUN-AUTH-1")
        anon = _make_client(None)
        assert anon.post(f"/threat-agent/{run_id}/scenarios", json=_expert_body()).status_code == 401
        assert anon.post(
            f"/threat-agent/{run_id}/scenarios/TID-A/prune", json={"reason": "x"}
        ).status_code == 401
