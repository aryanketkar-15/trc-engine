"""
tests/threat_agent/unit/test_state_manager_rejection_log.py
───────────────────────────────────────────────────────────
Unit tests for StateManager.log_rejection() and revision_history in SCRS.

Verifies:
  1. log_rejection() appends AuditLogEntry records with action="reject" and the reason.
  2. log_rejection() saves the rejected scenarios snapshot in revision_history[run_id].
  3. get_revision_history(run_id) returns the revision history for that run.
  4. The NotApprovedError approval gate on write_threat_scenario() remains strictly enforced.
  5. Persistence and round-trip reloading from disk works correctly for revision history.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.threat_agent.schemas import (
    EvidenceChain,
    STRIDECategory,
    ThreatScenario,
)
from scrp.state_manager import NotApprovedError, StateManager


def _make_scenario(
    run_id: str = "RUN-SCRS-001",
    tid: str = "TID-001",
    status: str = "pending_human",
) -> ThreatScenario:
    """Helper to construct a ThreatScenario for SCRS testing."""
    return ThreatScenario(
        tid=tid,
        run_id=run_id,
        asset_id="AS-1",
        stride_category=STRIDECategory.SPOOFING,
        attack_vector="Spoofing BLE advertisement frames to impersonate peripheral.",
        kb_reference="CWE-290",
        evidence_chain=EvidenceChain(
            exposure="BLE advertisement packets are unauthenticated.",
            matched_pattern="CWE-290",
            applicability_reason="Allows device spoofing without cryptographic signature.",
            citation="https://cwe.mitre.org/data/definitions/290.html",
        ),
        confidence_score=0.8,
        status=status,
    )


class TestStateManagerRejectionLog:
    """Test suite for SCRS StateManager rejection logging and revision tracking."""

    def test_log_rejection_records_audit_and_history(self, tmp_path: Path) -> None:
        """log_rejection() records audit log entries and revision history snapshot."""
        scrs_file = tmp_path / "SCRS_state.json"
        state_mgr = StateManager(scrs_path=scrs_file)

        run_id = "RUN-REJ-001"
        sc1 = _make_scenario(run_id=run_id, tid="TID-101")
        sc2 = _make_scenario(run_id=run_id, tid="TID-102")
        reason = "BLE vector is too generic; specify GATT characteristic UUID."

        state_mgr.log_rejection(
            run_id=run_id,
            reason=reason,
            rejected_scenarios=[sc1, sc2],
        )

        # 1. Audit log checks
        audit_log = state_mgr.get_audit_log()
        assert len(audit_log) == 2
        for entry in audit_log:
            assert entry.run_id == run_id
            assert entry.action == "reject"
            assert entry.reason == reason
            assert entry.tid in {"TID-101", "TID-102"}

        # 2. Revision history checks
        history = state_mgr.get_revision_history(run_id=run_id)
        assert len(history) == 1
        assert history[0]["reason"] == reason
        assert len(history[0]["scenarios"]) == 2

        # 3. Threat scenarios store remains empty (only approved scenarios enter)
        assert len(state_mgr.get_threat_scenarios()) == 0

    def test_log_rejection_empty_scenarios(self, tmp_path: Path) -> None:
        """log_rejection() handles empty scenario lists gracefully."""
        scrs_file = tmp_path / "SCRS_state.json"
        state_mgr = StateManager(scrs_path=scrs_file)

        run_id = "RUN-REJ-EMPTY"
        state_mgr.log_rejection(
            run_id=run_id,
            reason="Empty scenario run rejected.",
            rejected_scenarios=[],
        )

        audit_log = state_mgr.get_audit_log()
        assert len(audit_log) == 1
        assert audit_log[0].run_id == run_id
        assert audit_log[0].action == "reject"
        assert audit_log[0].tid == "N/A"

        history = state_mgr.get_revision_history(run_id=run_id)
        assert len(history) == 1
        assert history[0]["scenarios"] == []

    def test_not_approved_gate_strictly_enforced(self, tmp_path: Path) -> None:
        """write_threat_scenario() still raises NotApprovedError for non-approved scenarios."""
        scrs_file = tmp_path / "SCRS_state.json"
        state_mgr = StateManager(scrs_path=scrs_file)

        run_id = "RUN-GATE-TEST"
        unapproved_scenario = _make_scenario(
            run_id=run_id, tid="TID-UNAPPROVED", status="pending_human"
        )

        with pytest.raises(NotApprovedError) as exc_info:
            state_mgr.write_threat_scenario(unapproved_scenario, run_id=run_id)

        assert "expected 'approved'" in str(exc_info.value).lower()
        assert len(state_mgr.get_threat_scenarios()) == 0

    def test_persistence_and_reload(self, tmp_path: Path) -> None:
        """Rejection log and revision history round-trip persist through file reload."""
        scrs_file = tmp_path / "SCRS_state.json"
        state_mgr1 = StateManager(scrs_path=scrs_file)

        run_id = "RUN-PERSIST-001"
        sc = _make_scenario(run_id=run_id, tid="TID-P1")
        state_mgr1.log_rejection(
            run_id=run_id,
            reason="Persistence test rejection.",
            rejected_scenarios=[sc],
        )

        # Reload fresh StateManager from the same file
        state_mgr2 = StateManager(scrs_path=scrs_file)
        assert len(state_mgr2.get_audit_log()) == 1
        assert state_mgr2.get_audit_log()[0].reason == "Persistence test rejection."

        history = state_mgr2.get_revision_history(run_id=run_id)
        assert len(history) == 1
        assert history[0]["reason"] == "Persistence test rejection."
