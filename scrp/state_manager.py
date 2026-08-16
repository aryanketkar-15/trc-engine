"""
scrp/state_manager.py
──────────────────────
Shared Cybersecurity Reasoning State (SCRS) — write path for Phase 1
(Threat Agent output only).

DESIGN INTENT:
StateManager is the *only* authorised entry point for writing threat
scenarios into the SCRS.  All write-path logic (approval gate, audit
logging, persistence) is centralised here rather than scattered across
agent code, so that:
  - The approval gate ("only write approved scenarios") is enforced in
    one place and cannot be bypassed by calling a different method.
  - The audit log is guaranteed to contain an entry for every successful
    write — no code path can write without logging.
  - Persistence details (currently a local JSON file) are hidden behind the
    write interface, so swapping to a real database in Phase 2 only requires
    changes here, not in every agent.

PHASE 1 PERSISTENCE:
Writing to a local SCRS_state.json file at the repo root.  This is
explicitly a scaffold for Day 1 — it gives the team a working interface
and a real file to inspect/diff without needing DB infrastructure.  The
path is configurable via the constructor so tests can point at a temp file.

NO SECRETS IN THIS FILE.  DB credentials will live in config/settings.py
(pydantic-settings) when real persistence is added.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from agents.threat_agent.schemas import ThreatScenario
from scrp.schemas import AuditLogEntry, SCRSState

logger = logging.getLogger(__name__)

#: Default path for the Phase 1 flat-file SCRS store.
DEFAULT_SCRS_PATH: Final[Path] = Path("SCRS_state.json")


class NotApprovedError(ValueError):
    """
    Raised when a caller attempts to write a non-approved ThreatScenario.

    This is a typed exception (not just ValueError) so the API layer and
    tests can catch it by name rather than by message string.
    """


class StateManager:
    """
    SCRS write interface for the Threat Agent (Phase 1).

    Thread-safety: NOT thread-safe in Phase 1 (single-process, single-run
    assumption).  Phase 2 will add file locking or a proper DB transaction.
    """

    def __init__(self, scrs_path: Path = DEFAULT_SCRS_PATH) -> None:
        """
        Args:
            scrs_path: Path to the SCRS_state.json file.  Overridable for
                       testing (point at a tmp file) or future config.
        """
        self._scrs_path = scrs_path
        self._state: SCRSState = self._load()

    # ------------------------------------------------------------------
    # Public write interface
    # ------------------------------------------------------------------

    def write_threat_scenario(
        self, scenario: ThreatScenario, run_id: str
    ) -> bool:
        """
        Write an approved ThreatScenario into the SCRS.

        Enforcement contract:
          - ONLY scenarios with status == "approved" are accepted.
          - Any other status raises NotApprovedError (and logs a warning).
            This is enforced in code, not just by convention.
          - A successful write is always accompanied by an audit_log entry.

        Args:
            scenario: The ThreatScenario to persist.
            run_id:   Unique identifier for the pipeline run initiating this
                      write.  Included in the audit log entry.

        Returns:
            True on successful write.

        Raises:
            NotApprovedError: If scenario.status != "approved".
            OSError:          If the SCRS file cannot be written (propagated).
        """
        if scenario.status != "approved":
            message = (
                f"write_threat_scenario rejected: scenario '{scenario.tid}' has "
                f"status '{scenario.status}', expected 'approved'.  "
                "Only human-approved scenarios may enter the SCRS."
            )
            logger.warning(message)
            raise NotApprovedError(message)

        # Persist scenario (overwrite if same tid was previously written —
        # this can happen on human-override re-approval in future phases).
        self._state.threat_scenarios[scenario.tid] = scenario.model_dump(mode="json")

        # Append audit log entry — MUST happen atomically with the write.
        audit_entry = AuditLogEntry(
            run_id=run_id,
            tid=scenario.tid,
            timestamp=datetime.now(UTC),
            action="write",
        )
        self._state.audit_log.append(audit_entry)

        self._persist()

        logger.info(
            "SCRS write: tid=%s run_id=%s status=%s timestamp=%s",
            scenario.tid,
            run_id,
            scenario.status,
            audit_entry.timestamp.isoformat(),
        )
        return True

    # ------------------------------------------------------------------
    # Read helpers (Phase 1 stubs — full read interface in Phase 2)
    # ------------------------------------------------------------------

    def get_audit_log(self) -> list[AuditLogEntry]:
        """Return a copy of the current audit log (read-only)."""
        return list(self._state.audit_log)

    def get_threat_scenarios(self) -> dict[str, object]:
        """Return a shallow copy of all stored threat scenarios (read-only)."""
        return dict(self._state.threat_scenarios)

    # ------------------------------------------------------------------
    # Private persistence helpers
    # ------------------------------------------------------------------

    def _load(self) -> SCRSState:
        """
        Load SCRS state from disk, or return a fresh empty state if the file
        does not exist yet.
        """
        if not self._scrs_path.exists():
            logger.info(
                "SCRS file not found at %s — initialising empty state.",
                self._scrs_path,
            )
            return SCRSState()

        try:
            raw = self._scrs_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            return SCRSState.model_validate(data)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.error(
                "Failed to parse SCRS file at %s: %s.  Starting with empty state.",
                self._scrs_path,
                exc,
            )
            return SCRSState()

    def _persist(self) -> None:
        """
        Serialize the current in-memory state and write it to disk.

        Writes to a .tmp file first, then renames — this is the simplest
        atomic-ish write pattern on most OSes, protecting against partial
        writes corrupting the file.
        """
        tmp_path = self._scrs_path.with_suffix(".json.tmp")
        payload = self._state.model_dump(mode="json")
        tmp_path.write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
        tmp_path.replace(self._scrs_path)
