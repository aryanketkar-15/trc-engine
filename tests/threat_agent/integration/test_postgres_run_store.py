"""
tests/threat_agent/integration/test_postgres_run_store.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: PostgreSQL Run Registry Integration Tests
──────────────────────────────────────────────────────────────────────────────
Verifies the persistent PostgresRunRegistryStore against a live PostgreSQL
database instance.

Covers:
  1. CRUD and schema verification (create, get, atomic update, scenarios JSONB).
  2. Process-restart durability (records persist across independent store instances).
  3. Atomic state transitions and error differentiation (404 vs. 409).
  4. Full FastAPI Router integration backed by PostgreSQL.
  5. Concurrency & race condition test: parallel simultaneous approvals on
     the same run guarantee exactly one 200 OK and one 409 Conflict.
  6. Thread-safety verification of InMemoryRunRegistryStore under concurrency.

Gated behind TRC_INTEGRATION_TESTS=1 so the default test suite stays fast
and requires no running Docker container.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agents.threat_agent.router import (
    get_orchestrator,
)
from agents.threat_agent.router import (
    router as threat_agent_router,
)
from agents.threat_agent.run_store import (
    InMemoryRunRegistryStore,
    InvalidStateTransitionError,
    PostgresRunRegistryStore,
    RunNotFoundError,
    get_run_store,
)
from agents.threat_agent.schemas import ThreatStatus

# Gate entire module behind TRC_INTEGRATION_TESTS environment variable
pytestmark = pytest.mark.skipif(
    not os.getenv("TRC_INTEGRATION_TESTS"),
    reason="Requires live PostgreSQL container (set TRC_INTEGRATION_TESTS=1)",
)

_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent
    / "e2e"
    / "fixtures"
    / "smart_door_lock"
    / "input.json"
)


@pytest.fixture
def valid_payload() -> dict[str, Any]:
    with open(_FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def pg_store() -> PostgresRunRegistryStore:
    """Provide a fresh PostgresRunRegistryStore with table truncated before each test."""
    store = PostgresRunRegistryStore()
    store.clear()
    yield store
    store.clear()


@pytest.fixture
def pg_client(pg_store: PostgresRunRegistryStore) -> TestClient:
    """TestClient wired directly to PostgresRunRegistryStore."""
    test_app = FastAPI()
    test_app.include_router(threat_agent_router)
    test_app.dependency_overrides[get_run_store] = lambda: pg_store
    test_app.dependency_overrides[get_orchestrator] = lambda: (lambda _p: ([], 0, "passed"))
    return TestClient(test_app)


class TestPostgresRunStoreDirect:
    """Direct tests against PostgresRunRegistryStore methods."""

    def test_postgres_store_validator_and_rejection_counts(
        self, pg_store: PostgresRunRegistryStore
    ) -> None:
        """Verify validator_retry_count, human_rejection_count, and validation_status."""
        run_id = "RUN-PG-COUNTS-001"
        created = pg_store.create_run(
            run_id=run_id,
            status=ThreatStatus.PENDING_HUMAN,
            validator_retry_count=2,
            human_rejection_count=0,
            validation_status="passed",
        )
        assert created.validator_retry_count == 2
        assert created.human_rejection_count == 0
        assert created.retry_count == 0
        assert created.validation_status == "passed"

        # Simulate rejection
        rejected = pg_store.transition_run(
            run_id=run_id,
            expected_status=ThreatStatus.PENDING_HUMAN,
            new_status=ThreatStatus.REJECTED,
            increment_retry=True,
        )
        assert rejected.status == ThreatStatus.REJECTED
        assert rejected.human_rejection_count == 1
        assert rejected.retry_count == 1
        assert rejected.validator_retry_count == 2
        assert rejected.validation_status == "passed"

        # Re-fetch across fresh store instance
        fresh_store = PostgresRunRegistryStore()
        fetched = fresh_store.get_run(run_id)
        assert fetched is not None
        assert fetched.human_rejection_count == 1
        assert fetched.validator_retry_count == 2
        assert fetched.validation_status == "passed"

    def test_postgres_store_crud_and_fields(
        self, pg_store: PostgresRunRegistryStore
    ) -> None:
        """Verify create, get, scenarios JSONB roundtrip, and transition in Postgres."""
        run_id = "RUN-PG-CRUD-001"
        scenarios = [
            {"scenario_id": "SCEN-001", "name": "BLE Relay Attack", "score": 0.88}
        ]

        created = pg_store.create_run(
            run_id=run_id,
            status=ThreatStatus.PENDING_HUMAN,
            scenarios=scenarios,
        )
        assert created.run_id == run_id
        assert created.status == ThreatStatus.PENDING_HUMAN
        assert created.scenarios == scenarios
        assert created.retry_count == 0
        assert created.scrs_entry_id is None
        assert created.created_at is not None
        assert created.updated_at is not None

        # Fetch record
        fetched = pg_store.get_run(run_id)
        assert fetched is not None
        assert fetched.run_id == run_id
        assert fetched.status == ThreatStatus.PENDING_HUMAN
        assert fetched.scenarios == scenarios

        # Transition to approved
        approved = pg_store.transition_run(
            run_id=run_id,
            expected_status=ThreatStatus.PENDING_HUMAN,
            new_status=ThreatStatus.APPROVED,
            scrs_entry_id=f"SCRS-{run_id}",
        )
        assert approved.status == ThreatStatus.APPROVED
        assert approved.scrs_entry_id == f"SCRS-{run_id}"

        # Re-fetch and confirm persistence of transition
        refetched = pg_store.get_run(run_id)
        assert refetched is not None
        assert refetched.status == ThreatStatus.APPROVED
        assert refetched.scrs_entry_id == f"SCRS-{run_id}"

    def test_process_restart_durability(
        self, pg_store: PostgresRunRegistryStore
    ) -> None:
        """Verify runs survive process restart (simulated by fresh store instantiation)."""
        run_id = "RUN-PG-RESTART-001"
        scenarios = [{"name": "Tamper Switch Bypass"}]

        # Write via initial store instance
        pg_store.create_run(
            run_id=run_id,
            status=ThreatStatus.PENDING_HUMAN,
            scenarios=scenarios,
        )

        # Simulate process termination: discard initial instance and instantiate brand-new store
        del pg_store
        new_store_after_restart = PostgresRunRegistryStore()

        recovered_run = new_store_after_restart.get_run(run_id)
        assert recovered_run is not None, "Run state was lost on simulated process restart!"
        assert recovered_run.run_id == run_id
        assert recovered_run.status == ThreatStatus.PENDING_HUMAN
        assert recovered_run.scenarios == scenarios

    def test_atomic_state_guards_and_error_types(
        self, pg_store: PostgresRunRegistryStore
    ) -> None:
        """Verify RunNotFoundError for unknown runs and InvalidStateTransitionError."""
        # 1. Unknown run raises RunNotFoundError
        with pytest.raises(RunNotFoundError) as exc_info:
            pg_store.transition_run(
                run_id="RUN-UNKNOWN-404",
                expected_status=ThreatStatus.PENDING_HUMAN,
                new_status=ThreatStatus.APPROVED,
            )
        assert exc_info.value.run_id == "RUN-UNKNOWN-404"

        # 2. Existing run in wrong state raises InvalidStateTransitionError
        run_id = "RUN-GUARD-001"
        pg_store.create_run(run_id, status=ThreatStatus.APPROVED)

        with pytest.raises(InvalidStateTransitionError) as exc_trans:
            pg_store.transition_run(
                run_id=run_id,
                expected_status=ThreatStatus.PENDING_HUMAN,
                new_status=ThreatStatus.APPROVED,
            )
        assert exc_trans.value.run_id == run_id
        assert exc_trans.value.current_status == ThreatStatus.APPROVED
        assert exc_trans.value.expected_status == ThreatStatus.PENDING_HUMAN


class TestPostgresRouterIntegration:
    """Router API endpoints backed by PostgresRunRegistryStore."""

    def test_router_full_lifecycle_postgres(
        self, pg_client: TestClient, valid_payload: dict[str, Any]
    ) -> None:
        """Verify analyze → status → scenarios → approve flow backed by PostgreSQL."""
        run_id = "RUN-PG-API-001"
        payload = dict(valid_payload, run_id=run_id)

        # 1. Analyze
        res = pg_client.post("/threat-agent/analyze", json=payload)
        assert res.status_code == 202
        assert res.json()["run_id"] == run_id

        # 2. Status poll
        res_status = pg_client.get(f"/threat-agent/{run_id}/status")
        assert res_status.status_code == 200
        assert res_status.json()["status"] == ThreatStatus.PENDING_HUMAN.value

        # 3. Approve
        res_approve = pg_client.post(f"/threat-agent/{run_id}/approve")
        assert res_approve.status_code == 200
        assert res_approve.json()["status"] == ThreatStatus.APPROVED.value
        assert res_approve.json()["scrs_entry_id"] == f"SCRS-{run_id}"

        # 4. Double approve returns 409 Conflict
        res_double = pg_client.post(f"/threat-agent/{run_id}/approve")
        assert res_double.status_code == 409
        assert "already approved" in res_double.json()["detail"].lower()

        # 5. Unknown run returns 404
        res_404 = pg_client.get("/threat-agent/RUN-NOT-FOUND-999/status")
        assert res_404.status_code == 404
        assert "not found" in res_404.json()["detail"].lower()

    def test_postgres_concurrent_approval_race_condition(
        self, pg_client: TestClient, pg_store: PostgresRunRegistryStore
    ) -> None:
        """Prove SQL atomicity: 2 simultaneous approvals result in exactly 1x 200 and 1x 409."""
        run_id = "RUN-PG-RACE-001"
        pg_store.create_run(run_id=run_id, status=ThreatStatus.PENDING_HUMAN)

        # Fire two concurrent approve requests via separate threads
        def _call_approve() -> tuple[int, dict[str, Any]]:
            res = pg_client.post(f"/threat-agent/{run_id}/approve")
            return res.status_code, res.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut1 = executor.submit(_call_approve)
            fut2 = executor.submit(_call_approve)
            status1, body1 = fut1.result()
            status2, body2 = fut2.result()

        status_codes = sorted([status1, status2])
        assert status_codes == [200, 409], (
            f"Expected exactly one 200 and one 409, but received: {status1}, {status2}"
        )

        conflict_body = body1 if status1 == 409 else body2
        assert "already approved" in conflict_body["detail"].lower()

        # Final database state must be approved
        record = pg_store.get_run(run_id)
        assert record is not None
        assert record.status == ThreatStatus.APPROVED


class TestInMemoryStoreConcurrency:
    """Verify threading.Lock atomicity contract in InMemoryRunRegistryStore."""

    def test_in_memory_concurrent_approval_race_condition(
        self, valid_payload: dict[str, Any]
    ) -> None:
        """Prove in-memory store lock prevents race condition during simultaneous approvals."""
        store = InMemoryRunRegistryStore()
        run_id = "RUN-MEM-RACE-001"
        store.create_run(run_id=run_id, status=ThreatStatus.PENDING_HUMAN)

        test_app = FastAPI()
        test_app.include_router(threat_agent_router)
        test_app.dependency_overrides[get_run_store] = lambda: store
        client = TestClient(test_app)

        def _call_approve() -> int:
            return client.post(f"/threat-agent/{run_id}/approve").status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut1 = executor.submit(_call_approve)
            fut2 = executor.submit(_call_approve)
            status1 = fut1.result()
            status2 = fut2.result()

        assert sorted([status1, status2]) == [200, 409], (
            f"InMemory store race condition: got {status1} and {status2}"
        )
