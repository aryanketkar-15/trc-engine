"""Phase 3 endpoints: asset criticality, rationale kept with the record, protection targets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.compliance_agent import explainer
from agents.compliance_agent.router import router as compliance_router
from agents.risk_agent.schemas import Treatment
from agents.threat_agent.router import get_state_manager
from scrp.state_manager import StateManager
from tests.risk_agent.integration.test_compliance_router import _risk
from tests.risk_agent.unit.test_risk_engine import _inp, _threat

API_KEY = "trc-dev-secret-key"


@pytest.fixture()
def env(tmp_path: Path) -> tuple[TestClient, Path]:
    path = tmp_path / "scrs.json"
    sm = StateManager(path)
    threat = _threat("AS-1", "THR-A")
    sm.commit_approved_run(threat.run_id, [threat])
    sm.commit_risk_assessments([_risk("THR-A", Treatment.REDUCE)])
    app = FastAPI()
    app.include_router(compliance_router)
    app.dependency_overrides[get_state_manager] = lambda: StateManager(path)
    return TestClient(app, headers={"X-API-Key": API_KEY}), path


def _asset_json() -> dict[str, Any]:
    asset = next(a for a in _inp().assets if a.asset_id == "AS-1")
    return asset.model_dump(mode="json")


def test_propose_works_without_a_body_and_cites_standards(env: Any) -> None:
    client, _ = env
    rec = client.post("/compliance-agent/propose").json()["proposals"][0]
    assert rec["asset_criticality"] == "Unknown" and len(rec["citations"]) == 2
    assert rec["ai_rationale"] is None


def test_propose_uses_the_asset_facts(env: Any) -> None:
    client, _ = env
    body = {"assets": [_asset_json()]}
    rec = client.post("/compliance-agent/propose", json=body).json()["proposals"][0]
    assert rec["asset_criticality"] in ("High", "Medium", "Low")


def test_explain_adds_a_rationale_that_confirm_keeps(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, path = env
    ai = explainer.AiRationale(
        ai_rationale="AVA_VAN.4 resists Moderate attackers.",
        ai_evidence=[{"doc": "CEM:2022 R1", "locator": "p. 464.1"}],
        ai_confidence=0.72,
        ai_model="test-model",
    )
    seen: dict[str, str] = {}

    def fake(record: Any, threat_text: str = "") -> explainer.AiRationale:
        seen["threat"] = threat_text
        return ai

    monkeypatch.setattr(explainer, "explain", fake)
    rec = client.post("/compliance-agent/propose", json={"explain": True}).json()["proposals"][0]
    assert rec["ai_rationale"] == ai.ai_rationale and seen["threat"]

    item = {
        "tid": "THR-A",
        "decision": {"approver": "Dr. A"},
        "ai": ai.model_dump(mode="json"),
    }
    res = client.post("/compliance-agent/confirm", json={"items": [item]}).json()
    assert res["rationale_dropped"] == []
    stored = StateManager(path).get_compliance_records()["THR-A"]
    assert stored["ai_rationale"] == ai.ai_rationale  # type: ignore[index]
    assert stored["cc_eal"] == "EAL4+"  # type: ignore[index]


def test_confirm_drops_a_rationale_that_names_another_level(env: Any) -> None:
    client, path = env
    item = {
        "tid": "THR-A",
        "decision": {"approver": "Dr. A"},
        "ai": {"ai_rationale": "This needs EAL6."},
    }
    res = client.post("/compliance-agent/confirm", json={"items": [item]}).json()
    assert res["rationale_dropped"] == ["THR-A"]
    stored = StateManager(path).get_compliance_records()["THR-A"]
    assert stored["ai_rationale"] is None and stored["cc_eal"] == "EAL4+"  # type: ignore[index]


def test_targets_endpoint(env: Any) -> None:
    client, _ = env
    assert client.get("/compliance-agent/targets").json()["product"] is None
    items = [{"tid": "THR-A", "decision": {"approver": "Dr. A"}}]
    client.post("/compliance-agent/confirm", json={"items": items})
    out = client.get("/compliance-agent/targets").json()
    assert out["product"]["sesip_level"] == "SESIP 3" and "AS-1" in out["per_asset"]
