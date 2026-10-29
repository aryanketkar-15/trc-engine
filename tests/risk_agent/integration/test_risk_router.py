"""HTTP endpoints of the Risk Agent against a temporary SCRS file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.risk_agent.router import router as risk_router
from agents.threat_agent.router import get_state_manager
from agents.threat_agent.schemas import ThreatAgentInput, ThreatScenario
from agents.threat_agent.staleness import traceability_stamp
from scrp.state_manager import StateManager

API_KEY = "trc-dev-secret-key"
ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests/threat_agent/e2e/fixtures/smart_door_lock/input.json"


def _threat(inp: ThreatAgentInput, asset: str, tid: str) -> ThreatScenario:
    return ThreatScenario.model_validate(
        {
            "tid": tid,
            "run_id": inp.run_id,
            "asset_id": asset,
            "stride_category": "Tampering",
            "attack_vector": "Replaying a captured BLE unlock command.",
            "kb_reference": "CAPEC-94",
            "evidence_chain": {
                "exposure": "BLE channel",
                "matched_pattern": "CAPEC-94",
                "applicability_reason": "The command has no freshness check.",
                "citation": "CAPEC-94: Adversary in the Middle",
            },
            "confidence_score": 0.7,
            "status": "approved",
            "validation_status": "passed",
            **traceability_stamp(inp, asset),
        }
    )


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, StateManager, Any]:
    monkeypatch.setenv("USE_LIVE_LLM", "false")
    inp = ThreatAgentInput(**json.loads(FIXTURE.read_text(encoding="utf-8")))
    path = tmp_path / "scrs.json"
    sm = StateManager(path)
    sm.commit_approved_run(
        inp.run_id, [_threat(inp, "AS-1", "THR-A"), _threat(inp, "AS-1", "THR-B")]
    )
    app = FastAPI()
    app.include_router(risk_router)
    app.dependency_overrides[get_state_manager] = lambda: StateManager(path)
    return TestClient(app, headers={"X-API-Key": API_KEY}), sm, path


RATING = {
    "impact": {
        "safety": None,
        "financial": "Moderate",
        "operational": "Severe",
        "privacy": "Moderate",
    },
    "attack_feasibility": "Medium",
}


def _decision(tid: str, treatment: str = "Reduce", residual: str = "Low") -> dict[str, Any]:
    return {
        "risk_input": {"tid": tid, **RATING},
        "decision": {
            "treatment": treatment,
            "rationale": "add a nonce to the command",
            "residual_risk": residual,
            "residual_reason": "replay is no longer possible",
            "approver": "Dr. Gaikwad",
        },
    }


def test_ratings_endpoint_says_the_tables_are_provisional(env: Any) -> None:
    client, _, _ = env
    body = client.get("/risk-agent/ratings").json()
    assert body["ratings_version"] == "placeholder-v0" and body["provisional"] is True
    assert body["risk_matrix"]["Severe"]["Medium"] == {"risk": "High", "source": "company"}


def test_suggest_covers_every_approved_threat(env: Any) -> None:
    client, _, _ = env
    body = client.post("/risk-agent/suggest", json={}).json()
    assert body["count"] == 2 and all(s["ai_suggested"] for s in body["suggestions"])


def test_score_previews_without_storing(env: Any) -> None:
    client, _sm, path = env
    res = client.post("/risk-agent/score", json={"inputs": [{"tid": "THR-A", **RATING}]})
    assert res.status_code == 200
    row = res.json()["by_asset"]["AS-1"][0]
    assert (row["overall_impact"], row["risk"], row["risk_basis"], row["rank_in_asset"]) == (
        "Severe",
        "High",
        "company",
        1,
    )
    assert StateManager(path).get_risk_assessments() == {}


def test_unknown_threat_is_404_and_bad_value_is_422(env: Any) -> None:
    client, _, _ = env
    assert (
        client.post("/risk-agent/score", json={"inputs": [{"tid": "NOPE", **RATING}]}).status_code
        == 404
    )
    bad = {"tid": "THR-A", "impact": {"financial": "Huge"}, "attack_feasibility": "Low"}
    assert client.post("/risk-agent/score", json={"inputs": [bad]}).status_code == 422


def test_approve_requires_the_api_key(env: Any) -> None:
    client, _, _ = env
    res = client.post(
        "/risk-agent/approve",
        json={"decisions": [_decision("THR-A")]},
        headers={"X-API-Key": "wrong"},
    )
    assert res.status_code == 401


def test_approve_stores_risks_and_splits_requirements_from_residual(env: Any) -> None:
    client, _, path = env
    body = client.post(
        "/risk-agent/approve",
        json={"decisions": [_decision("THR-A"), _decision("THR-B", "Retain", "High")]},
    ).json()
    assert body["stored"] == 2 and body["needs_requirement"] == ["THR-A"]
    assert [r["tid"] for r in body["residual"]] == ["THR-B"]
    stored = StateManager(path)
    assert set(stored.get_risk_assessments()) == {"THR-A", "THR-B"}
    assert stored.get_audit_log()[-1].action == "risk_approve"
    listed = client.get("/risk-agent/assessments").json()
    assert listed["count"] == 2 and [r["rank_in_asset"] for r in listed["by_asset"]["AS-1"]] == [
        1,
        2,
    ]


def test_retain_with_a_different_residual_is_rejected(env: Any) -> None:
    client, _, path = env
    res = client.post(
        "/risk-agent/approve", json={"decisions": [_decision("THR-A", "Retain", "Low")]}
    )
    assert res.status_code == 422 and StateManager(path).get_risk_assessments() == {}


def test_stale_risk_is_found_and_retired_when_its_threat_is_retired(env: Any) -> None:
    client, _sm, path = env
    client.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]})
    StateManager(path).retire_scenarios(["THR-A"], "upstream changed")
    stale = client.post("/risk-agent/staleness").json()
    assert stale["stale"][0]["tid"] == "THR-A" and stale["unscored_threats"] == ["THR-B"]
    assert client.post("/risk-agent/retire-stale").json()["retired"] == 1
    assert StateManager(path).get_risk_assessments() == {}
