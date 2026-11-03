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

import getpass
import json
import logging
import os
import shutil
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from agents.threat_agent.schemas import ThreatScenario
from scrp.integrity import digest, field_diff, seal, verify_chain
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


class SCRSCorruptError(RuntimeError):
    """The state file exists but cannot be read. Nothing is overwritten until a person looks."""


class ConcurrentWriteError(RuntimeError):
    """Someone else saved the state after this copy was loaded. Reload and try again."""


class WouldOverwriteError(ValueError):
    """Approved content would change. The diff goes to a person, who supplies a reason to merge."""

    def __init__(self, tid: str, diff: list[dict[str, Any]]) -> None:
        super().__init__(f"{tid} is already approved and this would change it")
        self.tid = tid
        self.diff = diff


#: Fields that change on every save and say nothing about the decision itself.
_VOLATILE: Final[frozenset[str]] = frozenset({"created_at", "rank_in_asset"})
_LOCK_TIMEOUT_SECONDS: Final[float] = 10.0
_STALE_LOCK_SECONDS: Final[float] = 60.0


def _audit_key() -> str | None:
    from config.settings import get_settings

    secret = getattr(get_settings(), "AUDIT_HMAC_KEY", None)
    return secret.get_secret_value() if secret else None


class StateManager:
    """
    SCRS write interface for the Threat, Risk and Compliance agents.

    Safe for several processes on one host: saves take a lock file and refuse to overwrite a newer
    version. It is not a multi-host store.
    """

    def __init__(self, scrs_path: Path = DEFAULT_SCRS_PATH, actor: str | None = None) -> None:
        """
        Args:
            scrs_path: Path to the SCRS_state.json file.  Overridable for
                       testing (point at a tmp file) or future config.
            actor:     Who is making changes; recorded on every audit entry.
        """
        self._scrs_path = scrs_path
        self._actor = actor
        self._state: SCRSState = self._load()

    def set_actor(self, actor: str) -> None:
        """Record this name on the audit entries written from now on."""
        self._actor = actor

    def _default_actor(self) -> str:
        if self._actor:
            return self._actor
        try:
            return f"local:{getpass.getuser()} (unverified)"
        except OSError:
            return "local (unverified)"

    def _supersede(
        self,
        store: dict[str, object],
        item: dict[str, object],
        reason: str | None,
    ) -> dict[str, object] | None:
        """Return the record this one replaces, or raise if a person has not accepted the change."""
        tid = str(item["tid"])
        existing = store.get(tid)
        if not isinstance(existing, dict):
            return None
        diff = field_diff(existing, item, _VOLATILE)
        if not diff:
            return None
        if not (reason or "").strip():
            raise WouldOverwriteError(tid, diff)
        return existing

    def _record_supersede(
        self, namespace: str, item: dict[str, object], old: dict[str, object], reason: str
    ) -> None:
        run_id = str(item.get("run_id") or "unknown")
        self._state.revision_history.setdefault(f"{namespace}:{run_id}", []).append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "action": f"{namespace}_supersede",
                "reason": reason,
                "records": [old],
            }
        )
        action = "risk_supersede" if namespace == "risk" else "compliance_supersede"
        self._state.audit_log.append(
            AuditLogEntry(
                run_id=run_id,
                tid=str(item["tid"]),
                timestamp=datetime.now(UTC),
                action=action,  # type: ignore[arg-type]
                reason=reason,
            )
        )

    # ------------------------------------------------------------------
    # Public write interface
    # ------------------------------------------------------------------

    def write_threat_scenario(self, scenario: ThreatScenario, run_id: str) -> bool:
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
        audit_entry = self._apply_write(scenario, run_id)
        self._persist()

        logger.info(
            "SCRS write: tid=%s run_id=%s status=%s timestamp=%s",
            scenario.tid,
            run_id,
            scenario.status,
            audit_entry.timestamp.isoformat(),
        )
        return True

    def commit_approved_run(self, run_id: str, scenarios: list[ThreatScenario]) -> int:
        """Write every scenario of an approved run in ONE all-or-nothing file write.

        Each scenario gets a ``write`` audit entry, plus one ``approve`` entry,
        so the log shows both the persistence and the human decision.

        Raises:
            NotApprovedError: If any scenario is not ``approved`` (nothing is persisted).
        """
        for scenario in scenarios:
            self._apply_write(scenario, run_id)
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid=scenario.tid,
                    timestamp=datetime.now(UTC),
                    action="approve",
                )
            )
        if scenarios:
            self._persist()
        logger.info("SCRS commit: run_id=%s scenarios=%d", run_id, len(scenarios))
        return len(scenarios)

    def log_edit(
        self,
        run_id: str,
        tid: str,
        action: str,
        reason: str,
        scenario: dict[str, object] | None = None,
    ) -> None:
        """Record an expert prune/add and keep the affected scenario's content.

        Pruned scenarios are never deleted from the record: their full content,
        the reason and the time are preserved in ``revision_history``.
        """
        if action not in {"prune", "add"}:
            raise ValueError(f"unsupported edit action '{action}'")
        self._state.revision_history.setdefault(run_id, []).append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
                "reason": reason,
                "scenarios": [scenario] if scenario else [],
            }
        )
        self._state.audit_log.append(
            AuditLogEntry(
                run_id=run_id,
                tid=tid,
                timestamp=datetime.now(UTC),
                action=action,  # type: ignore[arg-type]
                reason=reason,
            )
        )
        self._persist()
        logger.info("SCRS edit logged: run_id=%s tid=%s action=%s", run_id, tid, action)

    def retire_scenarios(self, tids: list[str], reason: str) -> int:
        """Take approved scenarios out of the active set because their upstream data changed.

        Nothing is deleted: each scenario is moved into ``revision_history`` (action ``stale``)
        with the reason, and an audit entry is written.  Returns how many were retired.
        """
        retired = 0
        for tid in tids:
            raw = self._state.threat_scenarios.pop(tid, None)
            if raw is None:
                continue
            run_id = str(raw.get("run_id", "unknown")) if isinstance(raw, dict) else "unknown"
            self._state.revision_history.setdefault(run_id, []).append(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "action": "stale",
                    "reason": reason,
                    "scenarios": [raw],
                }
            )
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid=tid,
                    timestamp=datetime.now(UTC),
                    action="stale",
                    reason=reason,
                )
            )
            retired += 1
        if retired:
            self._persist()
            logger.info("SCRS retired %d stale scenario(s): %s", retired, reason)
        return retired

    def commit_risk_assessments(
        self, assessments: list[dict[str, object]], *, supersede_reason: str | None = None
    ) -> int:
        """Store approved risk assessments (keyed by tid) in one file write, with audit entries.

        Raises:
            NotApprovedError: If an assessment is not ``approved`` or has no approver.
            WouldOverwriteError: If it changes an approved one and no reason was given.
        """
        for item in assessments:
            if item.get("status") != "approved" or not item.get("approved_by"):
                raise NotApprovedError(
                    f"risk {item.get('risk_id')} is not approved by a named person"
                )
        replaced = {
            str(item["tid"]): self._supersede(self._state.risk_assessments, item, supersede_reason)
            for item in assessments
        }
        for item in assessments:
            tid = str(item["tid"])
            run_id = str(item.get("run_id") or "unknown")
            who = item.get("approved_by")
            old = replaced[tid]
            if old is not None:
                self._record_supersede("risk", item, old, str(supersede_reason))
            self._state.risk_assessments[tid] = item
            if item.get("ai_suggested") is False:
                self._state.audit_log.append(
                    AuditLogEntry(
                        run_id=run_id,
                        tid=tid,
                        timestamp=datetime.now(UTC),
                        action="risk_edit",
                        reason=(
                            f"ratings entered or edited by {who}: {item.get('suggestion_basis')}"
                        ),
                    )
                )
            if item.get("adjusted_risk"):
                self._state.audit_log.append(
                    AuditLogEntry(
                        run_id=run_id,
                        tid=tid,
                        timestamp=datetime.now(UTC),
                        action="risk_adjust",
                        reason=(
                            f"{who} changed computed risk {item.get('risk')} to "
                            f"{item.get('adjusted_risk')}: {item.get('adjustment_reason')}"
                        ),
                    )
                )
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid=tid,
                    timestamp=datetime.now(UTC),
                    action="risk_approve",
                    reason=f"treatment={item.get('treatment')}; approver={who}",
                    content_hash=digest(item, _audit_key()),
                )
            )
        if assessments:
            self._persist()
        return len(assessments)

    def retire_risk_assessments(self, tids: list[str], reason: str) -> int:
        """Move risk assessments out of the active set (their threat changed or was retired)."""
        retired = 0
        for tid in tids:
            raw = self._state.risk_assessments.pop(tid, None)
            if raw is None:
                continue
            run_id = str(raw.get("run_id") or "unknown") if isinstance(raw, dict) else "unknown"
            self._state.revision_history.setdefault(f"risk:{run_id}", []).append(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "action": "risk_stale",
                    "reason": reason,
                    "assessments": [raw],
                }
            )
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid=tid,
                    timestamp=datetime.now(UTC),
                    action="risk_stale",
                    reason=reason,
                )
            )
            retired += 1
        if retired:
            self._persist()
        return retired

    def log_risk_rejection(self, tid: str, run_id: str, reason: str, approver: str) -> int:
        """Record that the expert rejected the suggested ratings. Returns the rejection count."""
        self._state.audit_log.append(
            AuditLogEntry(
                run_id=run_id or "unknown",
                tid=tid,
                timestamp=datetime.now(UTC),
                action="risk_reject",
                reason=f"{approver}: {reason}",
            )
        )
        self._persist()
        return self.risk_rejection_count(tid)

    def risk_rejection_count(self, tid: str) -> int:
        return sum(1 for e in self._state.audit_log if e.tid == tid and e.action == "risk_reject")

    def commit_compliance_records(
        self, records: list[dict[str, object]], *, supersede_reason: str | None = None
    ) -> int:
        """Store expert-confirmed attack-resistance records (keyed by tid), with audit entries.

        Raises:
            NotApprovedError: If a record is not ``confirmed`` or has no confirming expert.
            WouldOverwriteError: If it changes a confirmed one and no reason was given.
        """
        for item in records:
            if item.get("status") != "confirmed" or not item.get("confirmed_by"):
                raise NotApprovedError(
                    f"compliance record for {item.get('tid')} is not confirmed by a named person"
                )
        replaced = {
            str(item["tid"]): self._supersede(
                self._state.compliance_records, item, supersede_reason
            )
            for item in records
        }
        for item in records:
            tid = str(item["tid"])
            old = replaced[tid]
            if old is not None:
                self._record_supersede("compliance", item, old, str(supersede_reason))
            self._state.compliance_records[tid] = item
            overridden = bool(item.get("overridden"))
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=str(item.get("run_id") or "unknown"),
                    tid=tid,
                    timestamp=datetime.now(UTC),
                    action="compliance_override" if overridden else "compliance_confirm",
                    reason=(
                        f"{item.get('confirmed_by')}: attacker class {item.get('attacker_class')}"
                        f" (rule {item.get('rule_id')})"
                        + (
                            f"; override reason: {item.get('override_reason')}"
                            if overridden
                            else ""
                        )
                    ),
                    content_hash=digest(item, _audit_key()),
                )
            )
        if records:
            self._persist()
        return len(records)

    def retire_compliance_records(self, tids: list[str], reason: str) -> int:
        retired = 0
        for tid in tids:
            raw = self._state.compliance_records.pop(tid, None)
            if raw is None:
                continue
            run_id = str(raw.get("run_id") or "unknown") if isinstance(raw, dict) else "unknown"
            self._state.revision_history.setdefault(f"compliance:{run_id}", []).append(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "action": "compliance_stale",
                    "reason": reason,
                    "records": [raw],
                }
            )
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid=tid,
                    timestamp=datetime.now(UTC),
                    action="compliance_stale",
                    reason=reason,
                )
            )
            retired += 1
        if retired:
            self._persist()
        return retired

    def log_compliance_rejection(self, tid: str, run_id: str, reason: str, approver: str) -> None:
        self._state.audit_log.append(
            AuditLogEntry(
                run_id=run_id or "unknown",
                tid=tid,
                timestamp=datetime.now(UTC),
                action="compliance_reject",
                reason=f"{approver}: {reason}",
            )
        )
        self._persist()

    def get_compliance_records(self) -> dict[str, object]:
        return dict(self._state.compliance_records)

    def get_risk_assessments(self) -> dict[str, object]:
        """Return a shallow copy of all approved risk assessments (read-only)."""
        return dict(self._state.risk_assessments)

    def _apply_write(self, scenario: ThreatScenario, run_id: str) -> AuditLogEntry:
        """Gate-check and stage one scenario in memory (does not persist)."""
        if scenario.status != "approved":
            message = (
                f"write_threat_scenario rejected: scenario '{scenario.tid}' has "
                f"status '{scenario.status}', expected 'approved'.  "
                "Only human-approved scenarios may enter the SCRS."
            )
            logger.warning(message)
            raise NotApprovedError(message)

        new_dump = scenario.model_dump(mode="json")
        existing = self._state.threat_scenarios.get(scenario.tid)
        if existing is not None and existing != new_dump:
            # Non-overwrite rule: approved content is never silently replaced.
            self._state.revision_history.setdefault(run_id, []).append(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "action": "superseded",
                    "reason": "re-approval with changed content",
                    "scenarios": [existing],
                }
            )
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid=scenario.tid,
                    timestamp=datetime.now(UTC),
                    action="revise",
                    previous_tid=scenario.tid,
                )
            )
        self._state.threat_scenarios[scenario.tid] = new_dump

        audit_entry = AuditLogEntry(
            run_id=run_id,
            tid=scenario.tid,
            timestamp=datetime.now(UTC),
            action="write",
            content_hash=digest(new_dump, _audit_key()),
        )
        self._state.audit_log.append(audit_entry)
        return audit_entry

    def log_rejection(
        self,
        run_id: str,
        reason: str,
        rejected_scenarios: list[ThreatScenario] | list[dict[str, object]] | None = None,
    ) -> None:
        """Record a human rejection and preserve rejected scenarios in revision history.

        Args:
            run_id: Unique identifier for the pipeline run.
            reason: Feedback / rationale provided by the human reviewer.
            rejected_scenarios: Scenarios rejected in this round.
        """
        raw_scenarios = rejected_scenarios or []
        scenarios_payload = [
            s.model_dump(mode="json") if hasattr(s, "model_dump") else s for s in raw_scenarios
        ]

        history_entry: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": reason,
            "scenarios": scenarios_payload,
        }
        self._state.revision_history.setdefault(run_id, []).append(history_entry)

        if scenarios_payload:
            for item in scenarios_payload:
                tid = str(item.get("tid", "UNKNOWN")) if isinstance(item, dict) else "UNKNOWN"
                self._state.audit_log.append(
                    AuditLogEntry(
                        run_id=run_id,
                        tid=tid,
                        timestamp=datetime.now(UTC),
                        action="reject",
                        reason=reason,
                    )
                )
        else:
            self._state.audit_log.append(
                AuditLogEntry(
                    run_id=run_id,
                    tid="N/A",
                    timestamp=datetime.now(UTC),
                    action="reject",
                    reason=reason,
                )
            )

        self._persist()
        logger.info(
            "SCRS rejection logged: run_id=%s reason=%s scenario_count=%d",
            run_id,
            reason,
            len(scenarios_payload),
        )

    # ------------------------------------------------------------------
    # Read helpers (Phase 1 stubs — full read interface in Phase 2)
    # ------------------------------------------------------------------

    def verify_integrity(self) -> dict[str, Any]:
        """Check the audit chain, and that active records still match what was approved."""
        key = _audit_key()
        chain = verify_chain(self._state.audit_log, key)
        latest: dict[tuple[str, str], str] = {}
        kinds = {
            "write": "threat",
            "risk_approve": "risk",
            "compliance_confirm": "compliance",
            "compliance_override": "compliance",
        }
        for entry in self._state.audit_log:
            kind = kinds.get(entry.action)
            if kind and entry.content_hash:
                latest[(kind, entry.tid)] = entry.content_hash
        stores = {
            "threat": self._state.threat_scenarios,
            "risk": self._state.risk_assessments,
            "compliance": self._state.compliance_records,
        }
        changed: list[str] = []
        unverifiable: list[str] = []
        checked = 0
        for kind, store in stores.items():
            for tid, record in store.items():
                expected = latest.get((kind, str(tid)))
                if expected is None:
                    unverifiable.append(f"{kind}:{tid}")
                    continue
                checked += 1
                if digest(record, key) != expected:
                    changed.append(f"{kind}:{tid}")
        return {
            "ok": chain["ok"] and not changed,
            "chain": chain,
            "keyed": bool(key),
            "state_version": self._state.state_version,
            "records_checked": checked,
            "records_changed": changed,
            "records_unverifiable": unverifiable,
        }

    def get_state_version(self) -> int:
        return self._state.state_version

    def get_audit_log(self) -> list[AuditLogEntry]:
        """Return a copy of the current audit log (read-only)."""
        return list(self._state.audit_log)

    def get_threat_scenarios(self) -> dict[str, object]:
        """Return a shallow copy of all stored threat scenarios (read-only)."""
        return dict(self._state.threat_scenarios)

    def get_revision_history(
        self, run_id: str | None = None
    ) -> dict[str, list[dict[str, object]]] | list[dict[str, object]]:
        """Return a copy of the revision history, optionally filtered by run_id."""
        if run_id is not None:
            return list(self._state.revision_history.get(run_id, []))
        return dict(self._state.revision_history)

    # ------------------------------------------------------------------
    # Private persistence helpers
    # ------------------------------------------------------------------

    def _load(self) -> SCRSState:
        """
        Load SCRS state from disk, or return a fresh empty state if the file
        does not exist yet.

        Raises:
            SCRSCorruptError: If the file exists but cannot be read. An empty state here would
                let the next save wipe every approved result, so this stops instead.
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
            backup = self._scrs_path.with_suffix(".json.bak")
            raise SCRSCorruptError(
                f"Cannot read the shared state file {self._scrs_path}: {exc}. Nothing was changed. "
                f"The last good copy, if any, is {backup}."
            ) from exc

    def _persist(self) -> None:
        """
        Serialize the current in-memory state and write it to disk.

        Takes a lock, refuses to overwrite a newer version, seals the audit log, keeps the
        previous file as ``.json.bak``, then writes a flushed temp file and renames it, so a crash
        cannot leave a half-written state.

        Raises:
            ConcurrentWriteError: If another writer saved after this copy was loaded.
        """
        self._scrs_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock():
            on_disk = self._version_on_disk()
            if on_disk > self._state.state_version:
                raise ConcurrentWriteError(
                    f"{self._scrs_path} is at version {on_disk} but this copy was loaded at "
                    f"{self._state.state_version}. Reload and repeat the action."
                )
            seal(self._state.audit_log, self._default_actor(), _audit_key())
            self._state.state_version += 1
            payload = self._state.model_dump(mode="json")
            tmp_path = self._scrs_path.with_suffix(".json.tmp")
            with tmp_path.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, indent=2, default=str))
                handle.flush()
                os.fsync(handle.fileno())
            if self._scrs_path.exists():
                shutil.copy2(self._scrs_path, self._scrs_path.with_suffix(".json.bak"))
            self._replace(tmp_path)

    def _replace(self, tmp_path: Path) -> None:
        """Rename into place; on Windows a reader can hold the file for a moment, so retry."""
        for attempt in range(20):
            try:
                tmp_path.replace(self._scrs_path)
                return
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)

    def _version_on_disk(self) -> int:
        if not self._scrs_path.exists():
            return 0
        try:
            data = json.loads(self._scrs_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise SCRSCorruptError(f"Cannot read {self._scrs_path}: {exc}") from exc
        return int(data.get("state_version", 0))

    @contextmanager
    def _lock(self) -> Iterator[None]:
        lock_path = self._scrs_path.with_suffix(".json.lock")
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while True:
            try:
                handle = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:
                    if time.time() - lock_path.stat().st_mtime > _STALE_LOCK_SECONDS:
                        lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise ConcurrentWriteError(f"{lock_path} is held by another writer") from None
                time.sleep(0.05)
        try:
            os.close(handle)
            yield
        finally:
            lock_path.unlink(missing_ok=True)
