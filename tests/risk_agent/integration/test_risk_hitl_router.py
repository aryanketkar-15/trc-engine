"""Human-in-the-loop endpoints of the Risk Agent: reject and regenerate, adjust, audit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.risk_agent.router import router as risk_router
from agents.threat_agent.router import get_state_manager
from agents.threat_agent.schemas import ThreatAgentInput
from scrp.state_manager import StateManager
from tests.risk_agent.integration.test_risk_router import FIXTURE, RATING, _decision, _threat

API_KEY = "trc-dev-secret-key"


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Path]:
    monkeypatch.setenv("USE_LIVE_LLM", "false")
    inp = ThreatAgentInput(**json.loads(FIXTURE.read_text(encoding="utf-8")))
    path = tmp_path / "scrs.json"
    StateManager(path).commit_approved_run(inp.run_id, [_threat(inp, "AS-1", "THR-A")])
    app = FastAPI()
    app.include_router(risk_router)
    app.dependency_overrides[get_state_manager] = lambda: StateManager(path)
    return TestClient(app, headers={"X-API-Key": API_KEY}), path


def test_reject_logs_regenerates_and_escalates_after_three(env: Any) -> None:
    client, path = env
    first = _decision("THR-A")["risk_input"]
    body = {"risk_input": first, "reason": "feasibility is too low", "approver": "Dr. Gaikwad"}
    r1 = client.post("/risk-agent/reject", json=body).json()
    assert r1["escalated"] is False and r1["rejections_used"] == 1
    assert r1["suggestion"]["suggestion_basis"].startswith("could not produce")
    client.post("/risk-agent/reject", json=body)
    r3 = client.post("/risk-agent/reject", json=body).json()
    assert r3["escalated"] is True and r3["rejections_used"] == 3 and "suggestion" not in r3
    log = StateManager(path).get_audit_log()
    assert [e.action for e in log if e.action.startswith("risk_")] == ["risk_reject"] * 3
    # the expert now enters the ratings; the approval records how many rejections came first
    assert (
        client.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]}).status_code
        == 200
    )
    stored = StateManager(path).get_risk_assessments()["THR-A"]
    assert stored["rejections_before_approval"] == 3  # type: ignore[index]


def test_reject_needs_api_key_reason_and_known_threat(env: Any) -> None:
    client, _ = env
    ri = _decision("THR-A")["risk_input"]
    ok = {"risk_input": ri, "reason": "too optimistic", "approver": "X"}
    assert (
        client.post("/risk-agent/reject", json=ok, headers={"X-API-Key": "bad"}).status_code == 401
    )
    assert client.post("/risk-agent/reject", json={**ok, "reason": "no"}).status_code == 422
    unknown = {**ok, "risk_input": {**ri, "tid": "NOPE"}}
    assert client.post("/risk-agent/reject", json=unknown).status_code == 404


def test_adjusting_the_risk_needs_a_reason_and_is_audited(env: Any) -> None:
    client, path = env
    d = _decision("THR-A")
    d["decision"]["adjusted_risk"] = "Medium"
    assert client.post("/risk-agent/approve", json={"decisions": [d]}).status_code == 422
    d["decision"]["adjustment_reason"] = "mitigated by the secure element"
    res = client.post("/risk-agent/approve", json={"decisions": [d]}).json()
    row = res["by_asset"]["AS-1"][0]
    assert row["risk"] == "High" and row["effective_risk"] == "Medium"
    assert "risk_adjust" in [e.action for e in StateManager(path).get_audit_log()]


def test_justification_is_returned_with_every_score(env: Any) -> None:
    client, _ = env
    res = client.post("/risk-agent/score", json={"inputs": [{"tid": "THR-A", **RATING}]}).json()
    assert "Risk matrix" in res["by_asset"]["AS-1"][0]["justification"]
