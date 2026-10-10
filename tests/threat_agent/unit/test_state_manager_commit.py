"""StateManager: all-or-nothing commit and the non-overwrite rule (SRS 3.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.threat_agent.schemas import EvidenceChain, STRIDECategory, ThreatScenario, ThreatStatus
from scrp.state_manager import NotApprovedError, StateManager


def _sc(tid: str, vector: str = "Unauthenticated BLE unlock", status: ThreatStatus = ThreatStatus.APPROVED) -> ThreatScenario:
    return ThreatScenario(
        tid=tid,
        run_id="RUN-X",
        asset_id="AS-1",
        stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        attack_vector=vector,
        kb_reference="CWE-306",
        evidence_chain=EvidenceChain(
            exposure="BLE write without authentication.",
            matched_pattern="CWE-306",
            applicability_reason="Unlock command requires no authentication at all.",
            citation="CWE-306: Missing Authentication for Critical Function",
        ),
        confidence_score=0.8,
        status=status,
    )


def test_commit_is_all_or_nothing(tmp_path: Path) -> None:
    path = tmp_path / "scrs.json"
    mgr = StateManager(path)
    with pytest.raises(NotApprovedError):
        mgr.commit_approved_run("RUN-X", [_sc("A"), _sc("B", status=ThreatStatus.PENDING_HUMAN)])
    assert not path.exists()  # nothing persisted, not even the valid first scenario


def test_rewrite_with_changed_content_archives_the_old_version(tmp_path: Path) -> None:
    mgr = StateManager(tmp_path / "scrs.json")
    mgr.write_threat_scenario(_sc("A", "first wording"), "RUN-X")
    mgr.write_threat_scenario(_sc("A", "changed wording"), "RUN-X")

    stored = mgr.get_threat_scenarios()["A"]
    assert isinstance(stored, dict) and stored["attack_vector"] == "changed wording"

    history = mgr.get_revision_history("RUN-X")
    assert history[0]["action"] == "superseded"
    assert history[0]["scenarios"][0]["attack_vector"] == "first wording"  # type: ignore[index]
    assert any(e.action == "revise" and e.previous_tid == "A" for e in mgr.get_audit_log())


def test_rewrite_of_identical_content_is_not_logged_as_revision(tmp_path: Path) -> None:
    mgr = StateManager(tmp_path / "scrs.json")
    sc = _sc("A")
    mgr.write_threat_scenario(sc, "RUN-X")
    mgr.write_threat_scenario(sc, "RUN-X")
    assert not mgr.get_revision_history("RUN-X")
