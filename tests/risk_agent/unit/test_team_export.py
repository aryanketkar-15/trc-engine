"""Publishing approved results in the shapes Team 1's orchestrator and Team 3's agents read."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.compliance_agent import engine as cengine
from agents.compliance_agent.engine import ComplianceDecision, Rules
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
from scrp.router import router as scrs_router
from scrp.state_manager import StateManager
from scrp.team_export import build_export, reference, threat_numbers, use_cases_in, write_export
from tests.risk_agent.unit.test_risk_engine import _threat

ROOT = Path(__file__).resolve().parents[3]
UC = _threat().use_case_id


def _approve_threat(sm: StateManager, tid: str, asset: str = "AS-1", **over: Any) -> Any:
    threat = _threat(asset, tid).model_copy(update=over)
    sm.commit_approved_run(threat.run_id, [threat])
    return threat


def _approve_risk(
    sm: StateManager,
    threat: Any,
    treatment: Treatment = Treatment.REDUCE,
    adjusted: RiskLevel | None = None,
    **kw: Any,
) -> Any:
    ri = RiskInput(
        tid=threat.tid,
        impact=ImpactRatings(operational=ImpactLevel.SEVERE, financial=ImpactLevel.MODERATE),
        attack_feasibility=Feasibility.MEDIUM,
    )
    retain = treatment == Treatment.RETAIN
    current = adjusted or RiskLevel.HIGH
    done = engine.apply_treatment(
        engine.score(threat, ri, Ratings.load()),
        TreatmentDecision(
            treatment=treatment,
            rationale="add a nonce to the command",
            residual_risk=current if retain else RiskLevel.LOW,
            residual_reason=None if retain else "replay no longer possible",
            approver="Dr. Gaikwad",
            adjusted_risk=adjusted,
            adjustment_reason="owner assessment" if adjusted else None,
        ),
    )
    sm.commit_risk_assessments([done.model_dump(mode="json")], **kw)
    return done


def _confirm(sm: StateManager, risk: Any) -> None:
    record = cengine.confirm(risk, Rules.load(), ComplianceDecision(approver="Dr. Gaikwad"))
    sm.commit_compliance_records([record.model_dump(mode="json")])


@pytest.fixture()
def state(tmp_path: Path) -> StateManager:
    sm = StateManager(tmp_path / "s.json", actor="Dr. Gaikwad")
    a = _approve_threat(sm, "THR-A")
    b = _approve_threat(sm, "THR-B", "AS-2", kb_reference="ATT&CK-T1078.001")
    _confirm(sm, _approve_risk(sm, a))
    _approve_risk(sm, b, Treatment.RETAIN)
    return sm


@pytest.mark.parametrize(
    ("ours", "source", "ref"),
    [
        ("CAPEC-94", "CAPEC", "CAPEC-94"),
        ("ATT&CK-T1021.007", "ATT&CK", "T1021.007"),
        ("ATT&CK-T1078", "ATT&CK", "T1078"),
        ("T1566", "ATT&CK", "T1566"),
        ("CWE-1277", "CWE", "CWE-1277"),
        ("STRIDE-T-001", "STRIDE", "STRIDE-T-001"),
        ("something else", "OTHER", "something else"),
    ],
)
def test_references_are_written_the_way_team1_writes_them(ours: str, source: str, ref: str) -> None:
    assert reference(ours) == {"source": source, "reference_id": ref}


class TestThreatNumbers:
    def test_numbers_follow_approval_order(self, state: StateManager) -> None:
        assert threat_numbers(state)[(None, UC)] == {"THR-A": "T1", "THR-B": "T2"}

    def test_a_later_threat_gets_the_next_number_and_nothing_shifts(
        self, state: StateManager
    ) -> None:
        _approve_threat(state, "THR-0-SORTS-FIRST")
        assert threat_numbers(state)[(None, UC)] == {
            "THR-A": "T1",
            "THR-B": "T2",
            "THR-0-SORTS-FIRST": "T3",
        }

    def test_a_retired_threat_keeps_its_number(self, state: StateManager) -> None:
        state.retire_scenarios(["THR-A"], "asset changed")
        _approve_threat(state, "THR-C")
        numbers = threat_numbers(state)[(None, UC)]
        assert numbers == {"THR-A": "T1", "THR-B": "T2", "THR-C": "T3"}
        out = build_export(state, UC)
        assert [t["id"] for t in out["threats"]["threats"]] == ["T2", "T3"]
        assert out["retired_threat_ids"] == ["T1"]

    def test_re_approving_the_same_threat_does_not_renumber(self, state: StateManager) -> None:
        _approve_threat(state, "THR-A", attack_vector="A changed but approved description.")
        assert threat_numbers(state)[(None, UC)]["THR-A"] == "T1"

    def test_each_use_case_has_its_own_numbers(self, state: StateManager) -> None:
        _approve_threat(state, "THR-X", use_case_id="UC-02", project_id="P")
        numbers = threat_numbers(state)
        assert numbers[("P", "UC-02")] == {"THR-X": "T1"}
        assert use_cases_in(state) == [(None, UC), ("P", "UC-02")]
        assert [t["id"] for t in build_export(state, "UC-02")["threats"]["threats"]] == ["T1"]


class TestShapes:
    def test_threats_have_the_agreed_fields(self, state: StateManager) -> None:
        doc = build_export(state, UC, session_id="S-1")["threats"]
        assert doc["session_id"] == "S-1" and doc["usecase_id"] == UC and doc["asset_version"] == 1
        first, second = doc["threats"]
        assert first["id"] == "T1" and first["asset_ids"] == ["AS-1"] and first["stride"] == ["T"]
        assert first["references"] == [{"source": "CAPEC", "reference_id": "CAPEC-94"}]
        assert first["scenario"] and first["attack_vector"] == "BLE channel"
        assert second["references"] == [{"source": "ATT&CK", "reference_id": "T1078.001"}]
        assert first["team2_tid"] == "THR-A" and first["approved_by"] == "Dr. Gaikwad"

    def test_risks_use_the_effective_level_and_say_who_decided(self, tmp_path: Path) -> None:
        sm = StateManager(tmp_path / "s.json", actor="Dr. Gaikwad")
        threat = _approve_threat(sm, "THR-A")
        _approve_risk(sm, threat, Treatment.RETAIN, adjusted=RiskLevel.MEDIUM)
        row = build_export(sm, UC)["risks"]["risks"][0]
        assert row["threat_id"] == "T1" and row["risk_level"] == "Medium"
        assert row["computed_risk_level"] == "High" and row["adjusted"] is True
        assert row["treatment"] == "Retain" and row["residual_risk"] == "Medium"
        assert row["treatment_source"].startswith("Decided by Dr. Gaikwad")
        assert row["impact"]["operational"] == "Severe" and row["overall_impact"] == "Severe"

    def test_compliance_mappings(self, state: StateManager) -> None:
        mapping = build_export(state, UC)["compliance"]["mappings"]
        assert [m["threat_id"] for m in mapping] == ["T1"]
        assert (mapping[0]["sesip_level"], mapping[0]["cc_eal"]) == ("SESIP 3", "EAL4+")
        assert mapping[0]["assurance_component"] == "AVA_VAN.4"
        assert mapping[0]["confirmed_by"] == "Dr. Gaikwad"

    def test_team3_starter_logic_can_read_it(self, state: StateManager) -> None:
        """The same reads Team 3's stub Requirements agent makes (their requirement_agent.py)."""
        out = build_export(state, UC)
        risk_by_threat = {r["threat_id"]: r for r in out["risks"]["risks"]}
        mapping_by_threat = {m["threat_id"]: m for m in out["compliance"]["mappings"]}
        derived = []
        for threat in out["threats"]["threats"]:
            risk = risk_by_threat.get(threat["id"])
            if risk is None or risk.get("treatment") != "Reduce":
                continue
            ref = (threat.get("references") or [None])[0]
            derived.append(
                (
                    threat["id"],
                    list(threat.get("asset_ids", [])),
                    risk.get("risk_level"),
                    (mapping_by_threat.get(threat["id"]) or {}).get("sesip_level"),
                    ref["source"],
                    ref["reference_id"],
                )
            )
        assert derived == [("T1", ["AS-1"], "High", "SESIP 3", "CAPEC", "CAPEC-94")]
        assert {"threat", "risk", "compliance"} <= set(out["versions"])


class TestProblemsAndVersions:
    def test_gaps_are_reported_not_hidden(self, tmp_path: Path) -> None:
        sm = StateManager(tmp_path / "s.json")
        a = _approve_threat(sm, "THR-A")
        _approve_threat(sm, "THR-B")
        _approve_risk(sm, a)
        out = build_export(sm, UC)
        assert any("T2" in p and "no approved risk" in p for p in out["problems"])
        assert any("no confirmed resistance level yet for: T1" in p for p in out["problems"])
        assert len(out["risks"]["risks"]) == 1 and out["compliance"]["mappings"] == []

    def test_versions_change_only_with_their_own_artefact(self, state: StateManager) -> None:
        before = build_export(state, UC)["versions"]
        state.log_compliance_rejection("THR-B", "R", "needs a lab check", "Dr. Gaikwad")
        assert build_export(state, UC)["versions"] == before
        risk = _approve_risk(
            state, _threat("AS-1", "THR-A"), Treatment.RETAIN, supersede_reason="owner accepted it"
        )
        after = build_export(state, UC)["versions"]
        assert after["risk"] > before["risk"] and after["threat"] == before["threat"]
        assert risk.treatment == Treatment.RETAIN

    def test_upstream_versions_are_carried(self, state: StateManager) -> None:
        versions = build_export(state, UC, upstream_versions={"asset": 4, "usecase": 2})["versions"]
        assert versions["asset"] == 4 and versions["usecase"] == 2

    def test_an_empty_use_case_exports_nothing(self, state: StateManager) -> None:
        out = build_export(state, "UC-NOPE")
        assert out["threats"]["threats"] == [] and out["versions"]["threat"] == 0


class TestAuditTrail:
    def test_decisions_are_exported_in_team1s_event_names(self, state: StateManager) -> None:
        state.log_risk_rejection("THR-B", "R", "feasibility too low", "Dr. Gaikwad")
        trail = build_export(state, UC)["audit_trail"]
        assert trail["audit_chain"].startswith("chain intact across")
        events = {(e["event_type"], e["artefact_type"]) for e in trail["entries"]}
        assert {
            ("human_approval", "threat"),
            ("human_approval", "risk"),
            ("human_approval", "compliance"),
            ("human_rejection", "risk"),
        } <= events
        approval = next(e for e in trail["entries"] if e["detail"]["action"] == "risk_approve")
        assert approval["detail"]["threat_id"] == "T1" and approval["actor"] == "Dr. Gaikwad"
        assert all(e["entry_hash"] for e in trail["entries"])

    def test_tampering_shows_in_the_export(self, state: StateManager, tmp_path: Path) -> None:
        path = tmp_path / "s.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["risk_assessments"]["THR-A"]["risk"] = "Low"
        path.write_text(json.dumps(data), encoding="utf-8")
        chain = build_export(StateManager(path), UC)["audit_trail"]["audit_chain"]
        assert chain.startswith("CHAIN OR CONTENT CHECK FAILED")


class TestFilesAndApi:
    def test_files_are_written_with_team3s_names(self, state: StateManager, tmp_path: Path) -> None:
        written = write_export(build_export(state, UC), tmp_path / "out")
        assert [p.name for p in written] == [
            "threats.json",
            "risks.json",
            "compliance.json",
            "versions.json",
            "audit_trail.json",
            "export_notes.json",
        ]
        assert json.loads((tmp_path / "out" / "threats.json").read_text(encoding="utf-8"))[
            "threats"
        ]

    def _export(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(ROOT / "scripts" / "export_team1.py"), *args]
        options = {
            "capture_output": True,
            "text": True,
            "timeout": 120,
            "check": False,
            "cwd": ROOT,
        }
        return subprocess.run(command, **options)  # noqa: S603

    def test_command_line(self, state: StateManager, tmp_path: Path) -> None:
        scrs = str(tmp_path / "s.json")
        done = self._export("--scrs", scrs, "--out", str(tmp_path / "exp"), "--session-id", "S-9")
        assert done.returncode == 0, done.stdout + done.stderr
        risks = json.loads((tmp_path / "exp" / UC / "risks.json").read_text(encoding="utf-8"))
        assert risks["session_id"] == "S-9" and len(risks["risks"]) == 2
        missing = self._export(
            "--scrs", scrs, "--use-case", "UC-NOPE", "--out", str(tmp_path / "x")
        )
        assert missing.returncode == 1 and not (tmp_path / "x").exists()

    def test_api(self, state: StateManager, tmp_path: Path) -> None:
        app = FastAPI()
        app.include_router(scrs_router)
        app.dependency_overrides[get_state_manager] = lambda: StateManager(tmp_path / "s.json")
        client = TestClient(app)
        body = client.get(f"/scrs/export?use_case_id={UC}&session_id=S-1").json()
        assert [t["id"] for t in body["threats"]["threats"]] == ["T1", "T2"]
        assert body["threats"]["session_id"] == "S-1"
        assert client.get("/scrs/export?use_case_id=UC-NOPE").status_code == 404
        assert client.get("/scrs/export").status_code == 422
