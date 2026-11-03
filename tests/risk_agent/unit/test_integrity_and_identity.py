"""Tamper evidence, safe saving, no silent overwrite, identity, chains and production settings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

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
from agents.threat_agent.attack_chain import build_paths
from agents.threat_agent.chains import propose_chains
from common import auth, llm_audit, startup
from scrp.integrity import field_diff, verify_chain
from scrp.schemas import AuditLogEntry
from scrp.state_manager import (
    ConcurrentWriteError,
    SCRSCorruptError,
    StateManager,
    WouldOverwriteError,
)
from scrp.trace import build_trace
from tests.risk_agent.unit.test_risk_engine import _inp, _threat


def _risk(tid: str = "THR-1", residual: RiskLevel = RiskLevel.LOW) -> dict[str, Any]:
    ri = RiskInput(
        tid=tid,
        impact=ImpactRatings(operational=ImpactLevel.SEVERE),
        attack_feasibility=Feasibility.MEDIUM,
    )
    done = engine.apply_treatment(
        engine.score(_threat("AS-1", tid), ri, Ratings.load()),
        TreatmentDecision(
            treatment=Treatment.REDUCE,
            rationale="add a control",
            residual_risk=residual,
            residual_reason="control added",
            approver="Dr. A",
        ),
    )
    return done.model_dump(mode="json")


def _state(tmp_path: Path) -> tuple[StateManager, Path]:
    path = tmp_path / "s.json"
    sm = StateManager(path, actor="Dr. A")
    threat = _threat("AS-1", "THR-1")
    sm.commit_approved_run(threat.run_id, [threat])
    sm.commit_risk_assessments([_risk()])
    return sm, path


def _edit(path: Path, change: Any) -> None:  # noqa: ANN401
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestTamperEvidence:
    def test_clean_state_verifies_and_survives_a_reload(self, tmp_path: Path) -> None:
        _, path = _state(tmp_path)
        report = StateManager(path).verify_integrity()
        assert report["ok"] and report["records_checked"] == 2
        assert report["chain"]["unsealed"] == 0 and not report["records_unverifiable"]

    def test_every_entry_records_who_did_it(self, tmp_path: Path) -> None:
        sm, _ = _state(tmp_path)
        assert {e.actor for e in sm.get_audit_log()} == {"Dr. A"}

    def test_changing_an_audit_entry_is_detected(self, tmp_path: Path) -> None:
        _, path = _state(tmp_path)
        _edit(path, lambda d: d["audit_log"][1].update(reason="nothing happened"))
        report = StateManager(path).verify_integrity()
        assert not report["ok"] and report["chain"]["broken_at"] == 1

    def test_removing_an_audit_entry_is_detected(self, tmp_path: Path) -> None:
        _, path = _state(tmp_path)
        _edit(path, lambda d: d["audit_log"].pop(0))
        assert not StateManager(path).verify_integrity()["ok"]

    def test_changing_an_approved_record_is_detected(self, tmp_path: Path) -> None:
        _, path = _state(tmp_path)
        _edit(path, lambda d: d["risk_assessments"]["THR-1"].update(risk="Low"))
        report = StateManager(path).verify_integrity()
        assert not report["ok"] and report["records_changed"] == ["risk:THR-1"]

    def test_a_key_stops_someone_recomputing_the_chain(self) -> None:
        from scrp.integrity import seal

        entries = [AuditLogEntry(run_id="R", tid="T", action="write")]
        seal(entries, "A", "secret-key")
        assert verify_chain(entries, "secret-key")["ok"]
        assert not verify_chain(entries, None)["ok"]
        assert not verify_chain(entries, "other-key")["ok"]

    def test_older_entries_are_sealed_on_the_next_save(self, tmp_path: Path) -> None:
        path = tmp_path / "old.json"
        old = AuditLogEntry(run_id="R", tid="T", action="write").model_dump(mode="json")
        path.write_text(json.dumps({"audit_log": [old]}), encoding="utf-8")
        sm = StateManager(path)
        assert sm.verify_integrity()["chain"]["unsealed"] == 1
        sm.log_compliance_rejection("T", "R", "needs a lab check", "Dr. A")
        report = StateManager(path).verify_integrity()
        assert report["ok"] and report["chain"]["unsealed"] == 0


class TestSafeSaving:
    def test_a_damaged_file_stops_instead_of_being_wiped(self, tmp_path: Path) -> None:
        path = tmp_path / "s.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(SCRSCorruptError):
            StateManager(path)
        assert path.read_text(encoding="utf-8") == "{not json"

    def test_a_stale_copy_cannot_overwrite_newer_work(self, tmp_path: Path) -> None:
        _, path = _state(tmp_path)
        first, second = StateManager(path), StateManager(path)
        first.log_compliance_rejection("T", "R", "first writer", "A")
        with pytest.raises(ConcurrentWriteError):
            second.log_compliance_rejection("T", "R", "second writer", "B")
        reasons = [e.reason or "" for e in StateManager(path).get_audit_log()]
        assert any("first writer" in r for r in reasons)
        assert not any("second writer" in r for r in reasons)

    def test_previous_version_is_kept_and_version_goes_up(self, tmp_path: Path) -> None:
        sm, path = _state(tmp_path)
        before = sm.get_state_version()
        sm.log_compliance_rejection("T", "R", "a reason", "A")
        assert sm.get_state_version() == before + 1
        backup = json.loads(path.with_suffix(".json.bak").read_text(encoding="utf-8"))
        assert backup["state_version"] == before

    def test_no_lock_file_is_left_behind(self, tmp_path: Path) -> None:
        _, path = _state(tmp_path)
        assert not path.with_suffix(".json.lock").exists()


class TestNoSilentOverwrite:
    def test_changing_an_approved_risk_needs_a_reason_and_shows_the_diff(
        self, tmp_path: Path
    ) -> None:
        sm, _ = _state(tmp_path)
        with pytest.raises(WouldOverwriteError) as caught:
            sm.commit_risk_assessments([_risk(residual=RiskLevel.MEDIUM)])
        fields = {c["field"] for c in caught.value.diff}
        assert "residual_risk" in fields and "created_at" not in fields
        assert sm.get_risk_assessments()["THR-1"]["residual_risk"] == "Low"  # type: ignore[index]

    def test_with_a_reason_the_old_version_goes_to_the_history(self, tmp_path: Path) -> None:
        sm, _ = _state(tmp_path)
        run_id = _threat().run_id
        sm.commit_risk_assessments(
            [_risk(residual=RiskLevel.MEDIUM)], supersede_reason="control only partly effective"
        )
        assert sm.get_risk_assessments()["THR-1"]["residual_risk"] == "Medium"  # type: ignore[index]
        history = sm.get_revision_history(f"risk:{run_id}")
        assert history[-1]["records"][0]["residual_risk"] == "Low"  # type: ignore[index]
        actions = [e.action for e in sm.get_audit_log()]
        assert "risk_supersede" in actions and sm.verify_integrity()["ok"]

    def test_saving_the_same_decision_again_is_not_a_change(self, tmp_path: Path) -> None:
        sm, _ = _state(tmp_path)
        assert sm.commit_risk_assessments([_risk()]) == 1

    def test_diff_ignores_listed_fields(self) -> None:
        diff = field_diff({"a": 1, "b": 2}, {"a": 1, "b": 3, "c": 4}, frozenset({"c"}))
        assert diff == [{"field": "b", "current": 2, "proposed": 3}]


class TestIdentity:
    @pytest.fixture()
    def users(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
        keys = {"Vidya": "approver-key", "Asha": "analyst-key", "Ravi": "viewer-key"}
        roles = {"Vidya": "approver", "Asha": "analyst", "Ravi": "viewer"}
        path = tmp_path / "users.json"
        path.write_text(
            json.dumps(
                {
                    "users": [
                        {"name": n, "role": roles[n], "key_sha256": auth.hash_key(k)}
                        for n, k in keys.items()
                    ]
                }
            ),
            encoding="utf-8",
        )
        settings = type(
            "S",
            (),
            {"TRC_USERS_FILE": path, "REQUIRE_AUTH_FOR_READS": True},
        )()
        monkeypatch.setattr(auth, "get_settings", lambda: settings)
        return keys

    def test_named_key_gives_a_verified_user(self, users: dict[str, str]) -> None:
        who = auth.authenticate(users["Vidya"], "Someone Else")
        assert who is not None and who.verified and who.label == "Vidya"

    def test_wrong_key_is_rejected_and_the_shared_key_stops_working(
        self, users: dict[str, str]
    ) -> None:
        assert auth.authenticate("wrong") is None
        assert auth.authenticate("trc-dev-secret-key") is None

    def test_roles_are_enforced(self, users: dict[str, str]) -> None:
        analyst = auth.authenticate(users["Asha"])
        viewer = auth.authenticate(users["Ravi"])
        assert analyst and viewer
        assert auth.require_writer(analyst) == analyst
        with pytest.raises(HTTPException) as denied:
            auth.require_approver(analyst)
        assert denied.value.status_code == 403
        with pytest.raises(HTTPException):
            auth.require_writer(viewer)

    def test_reads_need_a_key_when_required(self, users: dict[str, str]) -> None:
        with pytest.raises(HTTPException) as denied:
            auth.read_gate(None)
        assert denied.value.status_code == 401
        auth.read_gate(users["Ravi"])

    def test_decision_uses_the_logged_in_name_not_the_typed_one(
        self, users: dict[str, str]
    ) -> None:
        who = auth.authenticate(users["Vidya"])
        assert who and auth.decided_by(who, "Someone Else") == "Vidya"

    def test_shared_key_names_are_marked_unverified(self) -> None:
        who = auth.authenticate("trc-dev-secret-key", "Dr. A")
        assert who and who.label == "Dr. A (unverified)" and who.role == "approver"
        assert auth.decided_by(who, "Typed Name") == "Typed Name"


class TestProductionSettings:
    def _settings(self, **over: Any) -> Any:  # noqa: ANN401
        base = {
            "ENVIRONMENT": "production",
            "TRC_USERS_FILE": None,
            "AUDIT_HMAC_KEY": None,
            "REQUIRE_AUTH_FOR_READS": False,
            "DATABASE_URL": "postgresql://u:trc_password@db/x",
            "THREAT_AGENT_API_KEY": type(
                "K", (), {"get_secret_value": lambda _s: "trc-dev-secret-key"}
            )(),
        }
        return type("S", (), {**base, **over})()

    def test_development_settings_refuse_to_start_in_production(self) -> None:
        with pytest.raises(RuntimeError, match="Refusing to start") as caught:
            startup.check_production_settings(self._settings())
        for word in ("TRC_USERS_FILE", "THREAT_AGENT_API_KEY", "AUDIT_HMAC_KEY", "DATABASE_URL"):
            assert word in str(caught.value)

    def test_a_proper_configuration_starts(self, tmp_path: Path) -> None:
        users = tmp_path / "u.json"
        users.write_text('{"users": []}', encoding="utf-8")
        startup.check_production_settings(
            self._settings(
                TRC_USERS_FILE=users,
                AUDIT_HMAC_KEY="k",
                REQUIRE_AUTH_FOR_READS=True,
                DATABASE_URL="postgresql://u:strong@db/x",
                THREAT_AGENT_API_KEY=type("K", (), {"get_secret_value": lambda _s: "strong"})(),
            )
        )

    def test_development_is_not_blocked(self) -> None:
        startup.check_production_settings(self._settings(ENVIRONMENT="development"))


def _t(tid: str, asset: str, stride: str, score: float = 0.8) -> dict[str, Any]:
    return {
        "tid": tid,
        "asset_id": asset,
        "stride_category": stride,
        "confidence_score": score,
        "attack_vector": f"attack {tid}",
        "kb_reference": "CAPEC-1",
    }


class TestChains:
    def test_links_threats_inside_one_asset(self) -> None:
        chains = propose_chains(
            [_t("A", "AS-1", "InformationDisclosure"), _t("B", "AS-1", "Spoofing")]
        )
        assert [[s["tid"] for s in c["steps"]] for c in chains] == [["A", "B"]]
        assert chains[0]["status"] == "proposed" and chains[0]["needs_review"] is True
        assert "impersonate" in chains[0]["links"][0]["because"]

    def test_no_link_across_assets_without_a_shared_flow(self) -> None:
        threats = [_t("A", "AS-1", "InformationDisclosure"), _t("B", "AS-2", "Spoofing")]
        assert propose_chains(threats) == []

    def test_shared_flow_links_assets(self) -> None:
        assets = _inp().assets
        shared = next(
            (a, b)
            for a in assets
            for b in assets
            if a.asset_id != b.asset_id
            and {*a.dfd_context.data_flows, *a.dfd_context.interfaces}
            & {*b.dfd_context.data_flows, *b.dfd_context.interfaces}
        )
        threats = [
            _t("A", shared[0].asset_id, "InformationDisclosure"),
            _t("B", shared[1].asset_id, "Spoofing"),
        ]
        chains = propose_chains(threats, assets)
        assert len(chains) == 1 and chains[0]["links"][0]["via"]

    def test_unlinked_kinds_and_loops_produce_nothing_endless(self) -> None:
        assert (
            propose_chains([_t("A", "AS-1", "DenialOfService"), _t("B", "AS-1", "Tampering")])[0][
                "steps"
            ][0]["tid"]
            == "B"
        )
        looped = propose_chains(
            [
                _t("A", "AS-1", "Spoofing"),
                _t("B", "AS-1", "InformationDisclosure"),
                _t("C", "AS-1", "Spoofing"),
            ]
        )
        for chain in looped:
            ids = [s["tid"] for s in chain["steps"]]
            assert len(ids) == len(set(ids)) and len(ids) <= 3

    def test_a_shorter_chain_inside_a_longer_one_is_dropped(self) -> None:
        chains = propose_chains(
            [
                _t("A", "AS-1", "InformationDisclosure"),
                _t("B", "AS-1", "Spoofing"),
                _t("C", "AS-1", "DenialOfService"),
                _t("D", "AS-1", "Tampering"),
            ]
        )
        keys = [tuple(s["tid"] for s in c["steps"]) for c in chains]
        assert ("A", "B", "D") in keys and ("A", "B") not in keys

    def test_build_paths_keeps_every_candidate(self) -> None:
        from agents.threat_agent.schemas import KBCandidate, KBSource

        candidate = KBCandidate(
            pattern_id="CAPEC-94",
            source=KBSource.CAPEC,
            title="AitM",
            description="Adversary in the middle",
            retrieval_score=0.8,
            asset_id="AS-1",
        )
        system = type("N", (), {"run_id": "R"})()
        paths = build_paths([candidate, candidate], system)  # type: ignore[arg-type]
        assert len(paths) == 2 and all(len(p.steps) == 1 for p in paths)


class TestTrace:
    def test_forward_and_backward_links_and_gaps(self, tmp_path: Path) -> None:
        sm, _ = _state(tmp_path)
        extra = _threat("AS-2", "THR-2")
        sm.commit_approved_run(extra.run_id, [extra])
        out = build_trace(sm)
        row = next(r for r in out["links"] if r["tid"] == "THR-1")
        assert row["backward"]["asset_id"] == "AS-1" and row["backward"]["kb_reference"]
        assert row["forward"]["risk_id"] == "RISK-THR-1"
        assert row["forward"]["requirement_needed"] is True
        assert out["gaps"]["threats_without_risk"] == ["THR-2"]
        assert out["gaps"]["reduce_without_resistance"] == ["THR-1"]
        assert out["gaps"]["risks_without_threat"] == []


class TestLlmAudit:
    def test_call_is_recorded_with_personal_data_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "logs" / "llm.jsonl"
        monkeypatch.setattr(
            llm_audit, "get_settings", lambda: type("S", (), {"LLM_AUDIT_PATH": path})()
        )
        llm_audit.record_call(
            run_id="R",
            model="m",
            prompt_version="v1",
            system_prompt="sys",
            user_prompt="mail admin@example.com",
            response="answer",
            latency_ms=5,
        )
        entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert entry["model"] == "m" and entry["prompt_version"] == "v1"
        assert entry["response"] == "answer" and "admin@example.com" not in entry["user_prompt"]

    def test_turned_off_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            llm_audit, "get_settings", lambda: type("S", (), {"LLM_AUDIT_PATH": None})()
        )
        llm_audit.record_call(
            run_id="R",
            model="m",
            prompt_version="v",
            system_prompt="s",
            user_prompt="u",
            response="a",
            latency_ms=1,
        )
        assert not list(tmp_path.iterdir())
