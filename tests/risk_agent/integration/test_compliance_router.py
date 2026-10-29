"""HTTP endpoints of the attack-resistance mapping against a temporary SCRS file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.compliance_agent.router import router as compliance_router
from agents.risk_agent import engine
from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import (
    Feasibility,
    ImpactLevel,
    ImpactRatings,
    RiskInput,
    RiskLevel,
    Treatment,
    TreatmentDecision,
)
from agents.threat_agent.router import get_state_manager
from scrp.state_manager import StateManager
from tests.risk_agent.unit.test_risk_engine import _threat

API_KEY = "trc-dev-secret-key"


def _risk(tid: str, treatment: Treatment) -> dict[str, Any]:
    ri = RiskInput(
        tid=tid,
        impact=ImpactRatings(operational=ImpactLevel.SEVERE, financial=ImpactLevel.MODERATE),
        attack_feasibility=Feasibility.MEDIUM,
    )
    scored = engine.score(_threat("AS-1", tid), ri, Ratings.load())
    retain = treatment == Treatment.RETAIN
    done = engine.apply_treatment(
        scored,
        TreatmentDecision(
            treatment=treatment,
            rationale="decision recorded",
            residual_risk=RiskLevel.HIGH if retain else RiskLevel.LOW,
            residual_reason=None if retain else "control added",
            approver="Dr. A",
        ),
    )
    return done.model_dump(mode="json")


@pytest.fixture()
def env(tmp_path: Path) -> tuple[TestClient, Path]:
    path = tmp_path / "scrs.json"
    StateManager(path).commit_risk_assessments(
        [_risk("THR-A", Treatment.REDUCE), _risk("THR-B", Treatment.RETAIN)]
    )
    app = FastAPI()
    app.include_router(compliance_router)
    app.dependency_overrides[get_state_manager] = lambda: StateManager(path)
    return TestClient(app, headers={"X-API-Key": API_KEY}), path


def test_rules_are_reported_as_provisional(env: Any) -> None:
    client, _ = env
    body = client.get("/compliance-agent/rules").json()
    assert body["provisional"] is True and body["class_table"]["Moderate"]["cc_eal"] == "EAL4+"


def test_propose_covers_reduce_only_unless_all_is_asked(env: Any) -> None:
    client, _ = env
    proposals = client.post("/compliance-agent/propose").json()["proposals"]
    assert [p["tid"] for p in proposals] == ["THR-A"]
    assert client.post("/compliance-agent/propose?include_all=true").json()["count"] == 2


def test_confirm_override_reject_and_list(env: Any) -> None:
    client, path = env
    bad = {"items": [{"tid": "THR-A", "decision": {"approver": "X", "attacker_class": "High"}}]}
    assert client.post("/compliance-agent/confirm", json=bad).status_code == 422
    no_key = client.post("/compliance-agent/confirm", json=bad, headers={"X-API-Key": "bad"})
    assert no_key.status_code == 401
    ok = {
        "items": [
            {
                "tid": "THR-A",
                "decision": {
                    "approver": "Dr. Gaikwad",
                    "attacker_class": "Enhanced-Basic",
                    "override_reason": "BLE proximity attacker only",
                },
            }
        ]
    }
    res = client.post("/compliance-agent/confirm", json=ok).json()
    rec = res["records"][0]
    assert res["stored"] == 1 and rec["cc_eal"] == "EAL2+" and rec["overridden"] is True
    assert rec["confirmed_by"] == "Dr. Gaikwad" and res["incomplete"] == []
    assert client.get("/compliance-agent/records").json()["count"] == 1
    miss = {"items": [{"tid": "NOPE", "decision": {"approver": "X"}}]}
    assert client.post("/compliance-agent/confirm", json=miss).status_code == 404
    rej = {"tid": "THR-B", "reason": "needs a lab check", "approver": "Dr. Gaikwad"}
    assert client.post("/compliance-agent/reject", json=rej).json()["rejected"] is True
    actions = [e.action for e in StateManager(path).get_audit_log()]
    assert "compliance_override" in actions and "compliance_reject" in actions


def test_mapping_goes_stale_when_its_risk_is_retired(env: Any) -> None:
    client, path = env
    ok = {"items": [{"tid": "THR-A", "decision": {"approver": "Dr. A"}}]}
    client.post("/compliance-agent/confirm", json=ok)
    StateManager(path).retire_risk_assessments(["THR-A"], "threat retired")
    stale = client.post("/compliance-agent/staleness").json()
    assert stale["stale"][0]["tid"] == "THR-A"
    assert client.post("/compliance-agent/retire-stale").json()["retired"] == 1
    assert client.get("/compliance-agent/records").json()["count"] == 0
