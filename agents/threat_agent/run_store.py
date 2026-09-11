"""
agents/threat_agent/run_store.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Run Registry Store
──────────────────────────────────────────────────────────────────────────────
Provides a durable, abstract interface and implementations for tracking
active and completed threat modeling runs.

Implementations:
    1. InMemoryRunRegistryStore: Thread-safe in-memory store for unit tests
       and local scaffold execution without external database dependencies.
    2. PostgresRunRegistryStore: Persistent PostgreSQL-backed store with
       atomic SQL conditional state transitions ensuring strict race safety.

Ruff compliance:
    • Line length <= 88 chars.
    • Full type annotations (ANN rules).
    • No unused imports.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from agents.threat_agent.schemas import ThreatStatus
from common.db import get_db_connection

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Domain Models & Exceptions
# ──────────────────────────────────────────────────────────────────────────────


class RunRecord(BaseModel):
    """Internal tracking record for active threat modeling runs."""

    run_id: str
    status: ThreatStatus
    scenarios: list[dict[str, object]] = Field(default_factory=list)
    retry_count: int = 0
    scrs_entry_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class RunNotFoundError(Exception):
    """Raised when a run_id is not found in the store."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(f"Run '{run_id}' not found.")


class InvalidStateTransitionError(Exception):
    """Raised when an atomic state transition fails due to mismatched current status."""

    def __init__(
        self,
        run_id: str,
        current_status: ThreatStatus,
        expected_status: ThreatStatus,
        new_status: ThreatStatus,
    ) -> None:
        self.run_id = run_id
        self.current_status = current_status
        self.expected_status = expected_status
        self.new_status = new_status
        super().__init__(
            f"Run '{run_id}' cannot transition from '{current_status.value}' "
            f"to '{new_status.value}' (expected '{expected_status.value}')."
        )


def _row_to_run_record(row: dict[str, Any]) -> RunRecord:
    """Map a database row dictionary to a RunRecord domain model."""
    scenarios = row.get("scenarios")
    if scenarios is None:
        scenarios_list: list[dict[str, object]] = []
    elif isinstance(scenarios, list):
        scenarios_list = scenarios
    else:
        scenarios_list = []

    return RunRecord(
        run_id=row["run_id"],
        status=ThreatStatus(row["status"]),
        scenarios=scenarios_list,
        retry_count=row.get("retry_count", 0),
        scrs_entry_id=row.get("scrs_entry_id"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Abstract Store Interface
# ──────────────────────────────────────────────────────────────────────────────


class RunRegistryStore(ABC):
    """Abstract interface for threat agent run registry storage."""

    @abstractmethod
    def create_run(
        self,
        run_id: str,
        status: ThreatStatus = ThreatStatus.PENDING_HUMAN,
        scenarios: list[dict[str, object]] | None = None,
        retry_count: int = 0,
        scrs_entry_id: str | None = None,
    ) -> RunRecord:
        """Create or register a run record (idempotent upsert)."""
        ...

    @abstractmethod
    def get_run(self, run_id: str) -> RunRecord | None:
        """Retrieve a run record by run_id, or None if not found."""
        ...

    @abstractmethod
    def set_run(self, record: RunRecord) -> None:
        """Explicitly register or update a run record."""
        ...

    @abstractmethod
    def transition_run(
        self,
        run_id: str,
        expected_status: ThreatStatus,
        new_status: ThreatStatus,
        scrs_entry_id: str | None = None,
        increment_retry: bool = False,
    ) -> RunRecord:
        """Atomically transition run from expected_status to new_status.

        Raises:
            RunNotFoundError: If run_id does not exist.
            InvalidStateTransitionError: If run exists but current status != expected_status.
        """
        ...

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored runs (used primarily in test suites)."""
        ...


# ──────────────────────────────────────────────────────────────────────────────
# In-Memory Implementation (Thread-Safe)
# ──────────────────────────────────────────────────────────────────────────────


class InMemoryRunRegistryStore(RunRegistryStore):
    """Thread-safe in-memory store backed by a dictionary and a threading lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[str, RunRecord] = {}

    def create_run(
        self,
        run_id: str,
        status: ThreatStatus = ThreatStatus.PENDING_HUMAN,
        scenarios: list[dict[str, object]] | None = None,
        retry_count: int = 0,
        scrs_entry_id: str | None = None,
    ) -> RunRecord:
        record = RunRecord(
            run_id=run_id,
            status=status,
            scenarios=scenarios or [],
            retry_count=retry_count,
            scrs_entry_id=scrs_entry_id,
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        with self._lock:
            self._runs[run_id] = record
        return record.model_copy()

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                return None
            return record.model_copy()

    def set_run(self, record: RunRecord) -> None:
        with self._lock:
            self._runs[record.run_id] = record.model_copy()

    def transition_run(
        self,
        run_id: str,
        expected_status: ThreatStatus,
        new_status: ThreatStatus,
        scrs_entry_id: str | None = None,
        increment_retry: bool = False,
    ) -> RunRecord:
        with self._lock:
            record = self._runs.get(run_id)
            if record is None:
                raise RunNotFoundError(run_id)

            if record.status != expected_status:
                raise InvalidStateTransitionError(
                    run_id=run_id,
                    current_status=record.status,
                    expected_status=expected_status,
                    new_status=new_status,
                )

            record.status = new_status
            if scrs_entry_id is not None:
                record.scrs_entry_id = scrs_entry_id
            if increment_retry:
                record.retry_count += 1
            record.updated_at = datetime.now()
            return record.model_copy()

    def clear(self) -> None:
        with self._lock:
            self._runs.clear()


# ──────────────────────────────────────────────────────────────────────────────
# PostgreSQL Implementation (Atomic SQL Transitions)
# ──────────────────────────────────────────────────────────────────────────────


def init_postgres_run_store_schema() -> None:
    """Create the threat_agent_runs table and indexes if not present."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_agent_runs (
                    run_id          TEXT PRIMARY KEY,
                    status          TEXT NOT NULL,
                    scenarios       JSONB NOT NULL DEFAULT '[]'::jsonb,
                    retry_count     INTEGER NOT NULL DEFAULT 0,
                    scrs_entry_id   TEXT,
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_threat_agent_runs_status "
                "ON threat_agent_runs (status);"
            )
        conn.commit()


class PostgresRunRegistryStore(RunRegistryStore):
    """Persistent PostgreSQL store with atomic conditional SQL state transitions."""

    def __init__(self) -> None:
        # Schema is created idempotently on first use or startup
        init_postgres_run_store_schema()

    def create_run(
        self,
        run_id: str,
        status: ThreatStatus = ThreatStatus.PENDING_HUMAN,
        scenarios: list[dict[str, object]] | None = None,
        retry_count: int = 0,
        scrs_entry_id: str | None = None,
    ) -> RunRecord:
        scenarios_payload = scenarios or []
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO threat_agent_runs (
                        run_id, status, scenarios, retry_count,
                        scrs_entry_id, created_at, updated_at
                    ) VALUES (
                        %(run_id)s, %(status)s, %(scenarios)s, %(retry_count)s,
                        %(scrs_entry_id)s, now(), now()
                    )
                    ON CONFLICT (run_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        scenarios = EXCLUDED.scenarios,
                        retry_count = EXCLUDED.retry_count,
                        scrs_entry_id = EXCLUDED.scrs_entry_id,
                        updated_at = now()
                    RETURNING *;
                    """,
                    {
                        "run_id": run_id,
                        "status": status.value,
                        "scenarios": Jsonb(scenarios_payload),
                        "retry_count": retry_count,
                        "scrs_entry_id": scrs_entry_id,
                    },
                )
                row = cur.fetchone()
            conn.commit()
            if row is None:
                raise RuntimeError(f"Failed to create run '{run_id}'.")
            return _row_to_run_record(row)

    def get_run(self, run_id: str) -> RunRecord | None:
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT * FROM threat_agent_runs WHERE run_id = %s;",
                    (run_id,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return _row_to_run_record(row)

    def set_run(self, record: RunRecord) -> None:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO threat_agent_runs (
                        run_id, status, scenarios, retry_count,
                        scrs_entry_id, created_at, updated_at
                    ) VALUES (
                        %(run_id)s, %(status)s, %(scenarios)s, %(retry_count)s,
                        %(scrs_entry_id)s, COALESCE(%(created_at)s, now()),
                        COALESCE(%(updated_at)s, now())
                    )
                    ON CONFLICT (run_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        scenarios = EXCLUDED.scenarios,
                        retry_count = EXCLUDED.retry_count,
                        scrs_entry_id = EXCLUDED.scrs_entry_id,
                        updated_at = now();
                    """,
                    {
                        "run_id": record.run_id,
                        "status": record.status.value,
                        "scenarios": Jsonb(record.scenarios),
                        "retry_count": record.retry_count,
                        "scrs_entry_id": record.scrs_entry_id,
                        "created_at": record.created_at,
                        "updated_at": record.updated_at,
                    },
                )
            conn.commit()

    def transition_run(
        self,
        run_id: str,
        expected_status: ThreatStatus,
        new_status: ThreatStatus,
        scrs_entry_id: str | None = None,
        increment_retry: bool = False,
    ) -> RunRecord:
        """Atomic conditional UPDATE enforcing status = expected_status."""
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                if increment_retry:
                    query = """
                        UPDATE threat_agent_runs
                        SET status = %(new_status)s,
                            retry_count = retry_count + 1,
                            updated_at = now()
                        WHERE run_id = %(run_id)s AND status = %(expected_status)s
                        RETURNING *;
                    """
                else:
                    query = """
                        UPDATE threat_agent_runs
                        SET status = %(new_status)s,
                            scrs_entry_id = COALESCE(%(scrs_entry_id)s, scrs_entry_id),
                            updated_at = now()
                        WHERE run_id = %(run_id)s AND status = %(expected_status)s
                        RETURNING *;
                    """
                cur.execute(
                    query,
                    {
                        "run_id": run_id,
                        "expected_status": expected_status.value,
                        "new_status": new_status.value,
                        "scrs_entry_id": scrs_entry_id,
                    },
                )
                row = cur.fetchone()
                if row is not None:
                    conn.commit()
                    return _row_to_run_record(row)

                # Conditional update affected 0 rows: distinguish 404 vs 409
                cur.execute(
                    "SELECT status FROM threat_agent_runs WHERE run_id = %s;",
                    (run_id,),
                )
                existing = cur.fetchone()
                if existing is None:
                    raise RunNotFoundError(run_id)

                current_status = ThreatStatus(existing["status"])
                raise InvalidStateTransitionError(
                    run_id=run_id,
                    current_status=current_status,
                    expected_status=expected_status,
                    new_status=new_status,
                )

    def clear(self) -> None:
        """Truncate table (used for test resets)."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE threat_agent_runs;")
            conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Dependency Providers
# ──────────────────────────────────────────────────────────────────────────────

_GLOBAL_IN_MEMORY_STORE = InMemoryRunRegistryStore()


def get_in_memory_run_store() -> InMemoryRunRegistryStore:
    """Return the global in-memory run store instance.

    Used by tests via FastAPI's dependency_overrides to swap in a fast,
    Docker-free store without touching the default production store.
    """
    return _GLOBAL_IN_MEMORY_STORE


def get_postgres_run_store() -> PostgresRunRegistryStore:
    """Return a Postgres-backed run store instance."""
    return PostgresRunRegistryStore()


def get_run_store() -> RunRegistryStore:
    """Default FastAPI dependency provider for RunRegistryStore.

    Returns the PostgreSQL-backed store by default — this is the safe,
    durable production behavior and requires no special wiring to obtain.

    Tests that need speed (no Docker) should use FastAPI's dependency_overrides
    to substitute get_in_memory_run_store, which is the idiomatic use of that
    mechanism.  Production code never needs to call dependency_overrides.
    """
    return get_postgres_run_store()
