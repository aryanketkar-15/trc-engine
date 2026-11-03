"""End-to-end API behaviour of identity, overwrite protection, audit, trace and operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.compliance_agent.router import router as compliance_router
from agents.risk_agent.router import router as risk_router
from agents.threat_agent.router import router as threat_router
from common import auth, startup
from common.auth import hash_key
from scrp.router import router as scrs_router
from scrp.state_manager import ConcurrentWriteError, SCRSCorruptError, StateManager
from tests.risk_agent.integration.test_risk_router import RATING, _decision
from tests.risk_agent.unit.test_risk_engine import _threat

KEYS = {"Vidya": "approver-key", "Asha": "analyst-key", "Ravi": "viewer-key"}
ROLES = {"Vidya": "approver", "Asha": "analyst", "Ravi": "viewer"}


def _app() -> FastAPI:
    app = FastAPI()
    for r in (threat_router, risk_router, compliance_router, scrs_router):
        app.include_router(r)
    app.include_router(startup.ops_router)
    startup.install_handlers(app)
    return app


@pytest.fixture()
def scrs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "SCRS_state.json"
    monkeypatch.setattr("agents.threat_agent.router.get_scrs_path", lambda: path)
    threat = _threat("AS-1", "THR-A")
    StateManager(path).commit_approved_run(threat.run_id, [threat])
    return path


@pytest.fixture()
def shared(scrs: Path) -> TestClient:
    return TestClient(_app(), headers={"X-API-Key": "trc-dev-secret-key", "X-Reviewer": "Dr. Lal"})


@pytest.fixture()
def named(scrs: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            {
                "users": [
                    {"name": n, "role": ROLES[n], "key_sha256": hash_key(k)}
                    for n, k in KEYS.items()
                ]
            }
        ),
        encoding="utf-8",
    )
    real = auth.get_settings()

    class Settings:
        TRC_USERS_FILE = path
        REQUIRE_AUTH_FOR_READS = True
        THREAT_AGENT_API_KEY = real.THREAT_AGENT_API_KEY

    monkeypatch.setattr(auth, "get_settings", lambda: Settings())
    return TestClient(_app())


def _as(name: str) -> dict[str, str]:
    return {"X-API-Key": KEYS[name]}


def test_approver_name_comes_from_the_login_not_the_body(named: TestClient, scrs: Path) -> None:
    d = _decision("THR-A")
    d["decision"]["approver"] = "Somebody Important"
    res = named.post("/risk-agent/approve", json={"decisions": [d]}, headers=_as("Vidya"))
    assert res.status_code == 200
    state = StateManager(scrs)
    assert state.get_risk_assessments()["THR-A"]["approved_by"] == "Vidya"  # type: ignore[index]
    assert state.get_audit_log()[-1].actor == "Vidya"


@pytest.mark.parametrize("who", ["Asha", "Ravi"])
def test_only_an_approver_can_approve(named: TestClient, who: str) -> None:
    res = named.post(
        "/risk-agent/approve", json={"decisions": [_decision("THR-A")]}, headers=_as(who)
    )
    assert res.status_code == 403


def test_analyst_may_preview_but_reads_need_a_key(named: TestClient) -> None:
    body = {"inputs": [{"tid": "THR-A", **RATING}]}
    assert named.post("/risk-agent/score", json=body, headers=_as("Asha")).status_code == 200
    assert named.get("/scrs/trace").status_code == 401
    assert named.get("/scrs/trace", headers=_as("Ravi")).status_code == 200
    assert named.get("/risk-agent/ratings").status_code == 401


def test_threat_approval_endpoints_need_an_approver(named: TestClient) -> None:
    res = named.post("/threat-agent/RUN-X/approve", headers=_as("Asha"))
    assert res.status_code == 403
    assert named.post("/threat-agent/RUN-X/approve", headers=_as("Vidya")).status_code == 404


def test_shared_key_records_the_reviewer_as_unverified(shared: TestClient, scrs: Path) -> None:
    assert shared.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]}).is_success
    assert StateManager(scrs).get_audit_log()[-1].actor == "Dr. Lal (unverified)"


def test_changing_an_approved_risk_returns_the_diff_first(shared: TestClient, scrs: Path) -> None:
    shared.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]})
    changed = _decision("THR-A", residual="Medium")
    res = shared.post("/risk-agent/approve", json={"decisions": [changed]})
    assert res.status_code == 409
    detail = res.json()["detail"]
    assert detail["tid"] == "THR-A" and "residual_risk" in {c["field"] for c in detail["diff"]}
    assert StateManager(scrs).get_risk_assessments()["THR-A"]["residual_risk"] == "Low"  # type: ignore[index]
    ok = shared.post(
        "/risk-agent/approve",
        json={"decisions": [changed], "supersede_reason": "control is only partly effective"},
    )
    assert ok.status_code == 200
    assert StateManager(scrs).get_risk_assessments()["THR-A"]["residual_risk"] == "Medium"  # type: ignore[index]


def test_changing_a_confirmed_mapping_needs_a_reason(shared: TestClient) -> None:
    shared.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]})
    item = {"tid": "THR-A", "decision": {"approver": "Dr. A"}}
    assert shared.post("/compliance-agent/confirm", json={"items": [item]}).status_code == 200
    other = {
        "tid": "THR-A",
        "decision": {
            "approver": "Dr. A",
            "attacker_class": "Enhanced-Basic",
            "override_reason": "proximity only",
        },
    }
    assert shared.post("/compliance-agent/confirm", json={"items": [other]}).status_code == 409
    ok = shared.post(
        "/compliance-agent/confirm",
        json={"items": [other], "supersede_reason": "attacker model reviewed"},
    )
    assert ok.status_code == 200


def test_audit_endpoints_and_tamper_detection(shared: TestClient, scrs: Path) -> None:
    shared.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]})
    assert shared.get("/scrs/audit/verify").json()["ok"] is True
    log = shared.get("/scrs/audit/log?tid=THR-A").json()
    assert log["count"] >= 1 and log["entries"][-1]["entry_hash"]
    data = json.loads(scrs.read_text(encoding="utf-8"))
    data["risk_assessments"]["THR-A"]["risk"] = "Low"
    scrs.write_text(json.dumps(data), encoding="utf-8")
    report = shared.get("/scrs/audit/verify").json()
    assert report["ok"] is False and report["records_changed"] == ["risk:THR-A"]


def test_trace_and_chains_endpoints(shared: TestClient) -> None:
    assert shared.get("/scrs/trace/THR-A").json()["backward"]["asset_id"] == "AS-1"
    assert shared.get("/scrs/trace/NOPE").status_code == 404
    assert shared.post("/scrs/chains").json() == {"count": 0, "chains": []}


def test_report_carries_versions_and_chains(shared: TestClient) -> None:
    shared.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]})
    data = shared.get("/risk-agent/report").json()
    assert data["versions"]["state_version"] >= 1 and data["versions"]["ratings_versions"] == ["v1"]
    assert data["attack_chains"] == []
    assert "## Versions" in shared.get("/risk-agent/report?format=markdown").text


def test_risk_flags_review_until_approved(shared: TestClient) -> None:
    row = shared.post("/risk-agent/score", json={"inputs": [{"tid": "THR-A", **RATING}]}).json()[
        "by_asset"
    ]["AS-1"][0]
    assert row["needs_review"] is True and row["evidence_confidence"] == 0.7
    done = shared.post("/risk-agent/approve", json={"decisions": [_decision("THR-A")]}).json()
    assert done["by_asset"]["AS-1"][0]["needs_review"] is False


def test_health_and_request_id(shared: TestClient) -> None:
    res = shared.get("/health")
    assert res.json() == {"status": "ok"} and res.headers["X-Request-ID"]
    given = shared.get("/health", headers={"X-Request-ID": "abc"})
    assert given.headers["X-Request-ID"] == "abc"


def test_ready_reports_checks_without_configuration(shared: TestClient) -> None:
    body = shared.get("/ready").json()
    assert set(body["checks"]) == {
        "database",
        "knowledge_base",
        "rating_tables",
        "rule_base",
        "audit_chain",
    }
    text = json.dumps(body)
    assert "password" not in text and "postgresql" not in text


def test_oversized_body_is_refused(shared: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(startup, "get_settings", lambda: type("S", (), {"MAX_REQUEST_BYTES": 10})())
    app = _app()
    client = TestClient(app, headers={"X-API-Key": "trc-dev-secret-key"})
    assert client.post("/risk-agent/score", json={"inputs": ["x" * 100]}).status_code == 413


def _raising_app(exc: Exception) -> TestClient:
    app = FastAPI()
    startup.install_handlers(app)

    @app.get("/boom")
    def boom() -> Any:  # noqa: ANN401
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def test_shared_state_errors_become_clear_responses() -> None:
    assert _raising_app(ConcurrentWriteError("newer")).get("/boom").status_code == 409
    res = _raising_app(SCRSCorruptError(r"C:\secret\path")).get("/boom")
    assert res.status_code == 503 and "secret" not in res.text


def test_run_diff_endpoint(shared: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from agents.threat_agent.router import get_in_memory_run_store, get_run_store

    app = shared.app
    app.dependency_overrides[get_run_store] = get_in_memory_run_store  # type: ignore[attr-defined]
    assert shared.get("/threat-agent/NO-SUCH-RUN/diff").status_code == 404
