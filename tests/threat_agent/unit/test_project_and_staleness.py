"""Several use cases per product, and "go back one step": stale-threat detection and re-run."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.threat_agent.project import (
    ProjectInput,
    expand_project,
    is_project_payload,
    load_inputs,
)
from agents.threat_agent.schemas import ThreatAgentInput, ThreatScenario
from agents.threat_agent.staleness import (
    asset_fingerprint,
    check_staleness,
    context_fingerprint,
    traceability_stamp,
)
from scrp.state_manager import StateManager

ROOT = Path(__file__).resolve().parents[3]
PROJECT_FILE = ROOT / "projects" / "smart_door_lock_multi_use_case.json"
FIXTURE = ROOT / "tests/threat_agent/e2e/fixtures/smart_door_lock/input.json"


def _input() -> ThreatAgentInput:
    return ThreatAgentInput(**json.loads(FIXTURE.read_text(encoding="utf-8")))


def _scenario(
    inp: ThreatAgentInput, asset_id: str, tid: str = "THR-X-001", **over: Any
) -> ThreatScenario:
    base = {
        "tid": tid,
        "run_id": inp.run_id,
        "asset_id": asset_id,
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
        **traceability_stamp(inp, asset_id),
    }
    base.update(over)
    return ThreatScenario.model_validate(base)


class TestProjectExpansion:
    def test_shared_example_loads_and_expands_to_one_input_per_use_case(self) -> None:
        inputs = load_inputs(PROJECT_FILE, "T1")
        assert [i.use_case_id for i in inputs] == ["UC-01", "UC-02", "UC-03", "UC-04"]
        assert {i.project_id for i in inputs} == {"CSDL-100"}
        assert len({i.run_id for i in inputs}) == 4
        assert [a.asset_id for a in inputs[0].assets] == ["AS-1", "AS-2", "AS-4", "AS-6"]
        assert "AS-3" in [a.asset_id for a in inputs[3].assets]

    def test_single_run_files_still_load(self) -> None:
        assert len(load_inputs(FIXTURE)) == 1

    def test_detects_the_project_format(self) -> None:
        assert is_project_payload(json.loads(PROJECT_FILE.read_text(encoding="utf-8")))
        assert not is_project_payload(json.loads(FIXTURE.read_text(encoding="utf-8")))

    def test_unknown_asset_and_duplicate_use_case_are_rejected(self) -> None:
        data = json.loads(PROJECT_FILE.read_text(encoding="utf-8"))
        bad = json.loads(json.dumps(data))
        bad["use_cases"][0]["asset_ids"] = ["AS-99"]
        with pytest.raises(ValueError, match="unknown assets"):
            ProjectInput.model_validate(bad)
        dup = json.loads(json.dumps(data))
        dup["use_cases"][1]["use_case_id"] = "UC-01"
        with pytest.raises(ValueError, match="unique"):
            ProjectInput.model_validate(dup)

    def test_empty_asset_list_means_all_assets(self) -> None:
        data = json.loads(PROJECT_FILE.read_text(encoding="utf-8"))
        data["use_cases"][0]["asset_ids"] = []
        inputs = expand_project(ProjectInput.model_validate(data))
        assert len(inputs[0].assets) == 6


class TestFingerprints:
    def test_stable_and_sensitive_to_asset_facts(self) -> None:
        a = _input().assets[0]
        assert asset_fingerprint(a) == asset_fingerprint(a.model_copy())
        changed = a.model_copy(update={"device_config": {**a.device_config, "x": "y"}})
        assert asset_fingerprint(changed) != asset_fingerprint(a)
        flipped = a.model_copy(
            update={
                "security_attributes": a.security_attributes.model_copy(
                    update={"confidentiality": not a.security_attributes.confidentiality}
                )
            }
        )
        assert asset_fingerprint(flipped) != asset_fingerprint(a)

    def test_context_fingerprint_changes_with_the_text(self) -> None:
        assert context_fingerprint("a b c", "m") != context_fingerprint("a b c", "m2")
        assert context_fingerprint(" a ", "m") == context_fingerprint("a", "m")


class TestStaleness:
    def test_nothing_changed_means_nothing_is_stale(self) -> None:
        inp = _input()
        rep = check_staleness(inp, [_scenario(inp, "AS-3"), _scenario(inp, "AS-1", "THR-X-002")])
        assert not rep.has_changes and len(rep.fresh_tids) == 2

    def test_a_changed_asset_makes_only_its_threats_stale(self) -> None:
        inp = _input()
        approved = [_scenario(inp, "AS-3"), _scenario(inp, "AS-1", "THR-X-002")]
        new_assets = [
            a.model_copy(update={"device_config": {**a.device_config, "signed": "yes"}})
            if a.asset_id == "AS-3"
            else a
            for a in inp.assets
        ]
        rep = check_staleness(inp.model_copy(update={"assets": new_assets}), approved)
        assert [(s.tid, s.reason) for s in rep.stale] == [("THR-X-001", "asset facts changed")]
        assert rep.changed_assets == ["AS-3"] and rep.fresh_tids == ["THR-X-002"]

    def test_removed_asset_and_new_asset(self) -> None:
        inp = _input()
        approved = [_scenario(inp, "AS-3")]
        remaining = [a for a in inp.assets if a.asset_id != "AS-3"]
        rep = check_staleness(inp.model_copy(update={"assets": remaining}), approved)
        assert rep.removed_assets == ["AS-3"] and rep.stale[0].reason.startswith("asset removed")
        # a still-present asset that has no approved threat is reported as uncovered
        rep2 = check_staleness(inp, [_scenario(inp, "AS-3")])
        assert "AS-1" in rep2.uncovered_assets and "AS-3" not in rep2.uncovered_assets

    def test_changed_system_model_makes_every_threat_of_the_use_case_stale(self) -> None:
        inp = _input()
        approved = [_scenario(inp, "AS-3"), _scenario(inp, "AS-1", "THR-X-002")]
        rep = check_staleness(inp.model_copy(update={"system_model": "new boundaries"}), approved)
        assert {s.tid for s in rep.stale} == {"THR-X-001", "THR-X-002"} and rep.context_changed
        assert set(rep.affected_assets) >= {"AS-1", "AS-3"}

    def test_old_scenarios_without_fingerprints_use_the_asset_version(self) -> None:
        inp = _input()
        old = _scenario(inp, "AS-3", asset_fingerprint=None, context_fingerprint=None)
        assert not check_staleness(inp, [old]).has_changes
        bumped = [
            a.model_copy(update={"version": "2.0"}) if a.asset_id == "AS-3" else a
            for a in inp.assets
        ]
        rep = check_staleness(inp.model_copy(update={"assets": bumped}), [old])
        assert rep.stale[0].reason == "asset version changed"

    def test_other_use_cases_and_projects_are_ignored(self) -> None:
        inp = _input().model_copy(update={"project_id": "P", "use_case_id": "UC-01"})
        other_uc = _scenario(inp, "AS-3", use_case_id="UC-02")
        other_project = _scenario(inp, "AS-3", tid="THR-X-009", project_id="OTHER")
        rep = check_staleness(inp, [other_uc, other_project])
        assert not rep.stale and not rep.fresh_tids


class TestRetire:
    def test_retired_scenarios_move_to_history_and_are_audited(self, tmp_path: Path) -> None:
        inp = _input()
        sm = StateManager(tmp_path / "s.json")
        sc = _scenario(inp, "AS-3")
        sm.commit_approved_run(inp.run_id, [sc])
        assert (
            sm.retire_scenarios([sc.tid, "NOPE"], "Upstream data changed: asset facts changed") == 1
        )
        assert sm.get_threat_scenarios() == {}
        history = sm.get_revision_history(inp.run_id)
        assert history[-1]["action"] == "stale" and history[-1]["scenarios"][0]["tid"] == sc.tid
        assert [e.action for e in sm.get_audit_log()][-1] == "stale"
        # survives a reload
        assert StateManager(tmp_path / "s.json").get_revision_history(inp.run_id)


def test_orchestrator_style_stamp_carries_all_traceability_fields() -> None:
    inp = _input().model_copy(update={"project_id": "CSDL-100", "use_case_id": "UC-01"})
    stamp = traceability_stamp(inp, "AS-3")
    assert stamp["project_id"] == "CSDL-100" and stamp["use_case_id"] == "UC-01"
    assert stamp["asset_fingerprint"] and stamp["context_fingerprint"]
    assert traceability_stamp(inp, "AS-404")["asset_version"] is None
