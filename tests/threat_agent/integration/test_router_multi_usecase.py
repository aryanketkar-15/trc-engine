"""HTTP endpoints for several use cases per product and for stale-threat handling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.threat_agent.router import clear_run_registry, get_orchestrator
from agents.threat_agent.router import router as threat_agent_router
from agents.threat_agent.run_store import get_in_memory_run_store, get_run_store
from agents.threat_agent.schemas import ThreatAgentInput, ThreatScenario
from agents.threat_agent.staleness import traceability_stamp
from scrp.state_manager import StateManager

API_KEY = "trc-dev-secret-key"
ROOT = Path(__file__).resolve().parents[3]
PROJECT = json.loads(
    (ROOT / "projects" / "smart_door_lock_multi_use_case.json").read_text(encoding="utf-8")
)
FIXTURE = ROOT / "tests/threat_agent/e2e/fixtures/smart_door_lock/input.json"


def _scenario(inp: ThreatAgentInput, asset: str, tid: str) -> ThreatScenario:
    return ThreatScenario.model_validate(
        {
            "tid": tid,
            "run_id": inp.run_id,
            "asset_id": asset,
            "stride_category": "Tampering",
            "attack_vector": "Modifying the firmware image during a BLE OTA update.",
            "kb_reference": "CWE-1277",
            "evidence_chain": {
                "exposure": "BLE OTA interface",
                "matched_pattern": "CWE-1277",
                "applicability_reason": "The firmware image lacks signature verification.",
                "citation": "CWE-1277: Firmware Not Updateable",
            },
            "confidence_score": 0.7,
            "status": "approved",
            "validation_status": "passed",
            **traceability_stamp(inp, asset),
        }
    )


@pytest.fixture()
def client() -> TestClient:
    clear_run_registry()
    app = FastAPI()
    app.include_router(threat_agent_router)
    app.dependency_overrides[get_run_store] = get_in_memory_run_store
    app.dependency_overrides[get_orchestrator] = lambda: lambda p: ([], 0, "passed")
    return TestClient(app, headers={"X-API-Key": API_KEY})


def test_expand_project_returns_one_input_per_use_case(client: TestClient) -> None:
    res = client.post("/threat-agent/expand-project", json=PROJECT)
    assert res.status_code == 200
    inputs = res.json()
    assert [i["use_case_id"] for i in inputs] == ["UC-01", "UC-02", "UC-03", "UC-04"]
    assert all(i["project_id"] == "CSDL-100" for i in inputs)
    # each expanded input is a valid analyze payload
    for i in inputs:
        ThreatAgentInput.model_validate(i)


def test_expand_project_rejects_an_inconsistent_project(client: TestClient) -> None:
    bad = json.loads(json.dumps(PROJECT))
    bad["use_cases"][0]["asset_ids"] = ["AS-99"]
    assert client.post("/threat-agent/expand-project", json=bad).status_code == 422


def test_endpoints_require_the_api_key() -> None:
    app = FastAPI()
    app.include_router(threat_agent_router)
    anon = TestClient(app)
    for path in (
        "/threat-agent/expand-project",
        "/threat-agent/staleness",
        "/threat-agent/retire-stale",
    ):
        assert anon.post(path, json={}).status_code in (401, 403)


def test_staleness_and_retire_flow(client: TestClient, scrs_path: Path) -> None:
    inp = ThreatAgentInput(**json.loads(FIXTURE.read_text(encoding="utf-8")))
    StateManager(scrs_path).commit_approved_run(
        inp.run_id, [_scenario(inp, "AS-3", "THR-A-001"), _scenario(inp, "AS-1", "THR-A-002")]
    )
    current = json.loads(FIXTURE.read_text(encoding="utf-8"))

    same = client.post("/threat-agent/staleness", json=current).json()
    assert same["stale"] == [] and same["fresh"] == 2

    for a in current["assets"]:  # upstream change: AS-3 now verifies signatures
        if a["asset_id"] == "AS-3":
            a["device_config"]["signature_check"] = "enforced"
    changed = client.post("/threat-agent/staleness", json=current).json()
    assert [s["tid"] for s in changed["stale"]] == ["THR-A-001"]
    assert changed["changed_assets"] == ["AS-3"] and "AS-3" in changed["affected_assets"]
    # assets that have no approved threat yet are also offered for (re-)analysis
    assert "AS-2" in changed["uncovered_assets"]

    # read-only: nothing moved yet
    assert set(StateManager(scrs_path).get_threat_scenarios()) == {"THR-A-001", "THR-A-002"}

    done = client.post("/threat-agent/retire-stale", json=current).json()
    assert done["retired"] == 1
    sm = StateManager(scrs_path)
    assert set(sm.get_threat_scenarios()) == {"THR-A-002"}
    assert [e.action for e in sm.get_audit_log()][-1] == "stale"


def test_expert_added_scenario_carries_traceability_stamps(client: TestClient) -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    run_id = "RUN-STAMP-1"
    assert (
        client.post("/threat-agent/analyze", json={**payload, "run_id": run_id}).status_code == 202
    )
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
        "justification": "Expert knowledge.",
    }
    res = client.post(f"/threat-agent/{run_id}/scenarios", json=body)
    assert res.status_code == 201, res.text
    scen = next(
        s
        for s in client.get(f"/threat-agent/{run_id}/scenarios").json()
        if s["tid"].startswith("THR-EXP")
    )
    assert scen["asset_fingerprint"] and scen["context_fingerprint"] and scen["use_case_id"]
    assert scen["asset_version"] == "1.0"
