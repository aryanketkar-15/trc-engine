"""
tests/threat_agent/integration/test_pgvector_regression.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  pgvector Retrieval Regression Test
──────────────────────────────────────────────────────────────────────────────
Spins up the real pgvector container (via docker-compose), runs build_index.py
against the actual seed data, and verifies the known retrieval result for the
Smart Door Lock fixture.

Expected top match:  CWE-306 "Missing Authentication for Critical Function"
Expected score:      ≈ 0.8385  (same tolerance as the old FAISS regression)

Run only with Docker available:
    pytest tests/threat_agent/integration/ -v -m integration

Skip in regular CI if Postgres is unavailable:
    pytest tests/ -v --ignore=tests/threat_agent/integration/
"""

from __future__ import annotations

import os
import subprocess
import time

import psycopg
import pytest

# ── Skip marker ────────────────────────────────────────────────────────────

POSTGRES_AVAILABLE = os.environ.get("TRC_INTEGRATION_TESTS", "0") == "1"

pytestmark = pytest.mark.skipif(
    not POSTGRES_AVAILABLE,
    reason=(
        "Integration tests require a running pgvector Postgres instance. "
        "Set TRC_INTEGRATION_TESTS=1 and run docker compose up -d first."
    ),
)


# ── Helpers ────────────────────────────────────────────────────────────────


def _wait_for_postgres(dsn: str, retries: int = 20, delay: float = 1.0) -> None:
    """Poll until Postgres accepts connections or timeout."""
    for _ in range(retries):
        try:
            with psycopg.connect(dsn):
                return
        except Exception:  # noqa: BLE001
            time.sleep(delay)
    raise RuntimeError(f"Postgres not ready after {retries * delay}s: {dsn}")


# ── Integration test ───────────────────────────────────────────────────────


class TestPgvectorRegression:
    """Regression test: build_index.py → fetch_candidates() produces the same
    top match and similarity score as the old FAISS implementation."""

    DSN = "postgresql://trc_user:trc_password@localhost:5432/trc_engine"

    def test_build_index_and_retrieve_smart_door_lock(self) -> None:
        """Run build_index then query for BLE Controller.

        Asserts:
        - Top match is CWE-306 (same as FAISS implementation).
        - Similarity ≈ 0.8385 (within ±0.02 tolerance for float rounding).
        """
        # Wait for Postgres to be ready
        _wait_for_postgres(self.DSN)

        # Run build_index.py to populate the DB from seed files
        result = subprocess.run(
            ["python", "-m", "kb.scripts.build_index"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, (
            f"build_index.py failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )

        # Now run retrieval for the BLE Controller asset
        from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
        from agents.threat_agent.schemas import AssetModel, DFDContext, ThreatAgentInput

        agent_input = ThreatAgentInput(
            run_id="RUN-INTEGRATION-001",
            use_case="Smart Door Lock BLE Controller regression test.",
            system_model='{"trust_boundaries": [], "data_flows": []}',
            assets=[
                AssetModel(
                    asset_id="AS-1",
                    name="BLE Controller",
                    asset_type="embedded firmware",
                    dfd_context=DFDContext(
                        interfaces=["BLE 5.0"],
                        trust_zone="untrusted",
                    ),
                    device_config={
                        "auth_mechanism": "PIN-only",
                        "encryption": "none",
                    },
                )
            ],
        )

        plan = build_retrieval_plan(agent_input, top_k=5)
        candidates = fetch_candidates(plan)

        assert len(candidates) > 0, "Expected at least one candidate from pgvector."

        top = candidates[0]
        assert top.pattern_id == "CWE-306", (
            f"Expected top match CWE-306, got {top.pattern_id!r}. "
            "pgvector migration may have changed retrieval ranking."
        )
        assert abs(top.retrieval_score - 0.8385) < 0.02, (
            f"Expected retrieval_score ≈ 0.8385, got {top.retrieval_score:.4f}. "
            "Score normalisation may be broken."
        )

    def test_build_index_is_idempotent(self) -> None:
        """Running build_index.py twice must not create duplicate rows."""
        _wait_for_postgres(self.DSN)

        for _ in range(2):
            result = subprocess.run(
                ["python", "-m", "kb.scripts.build_index"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert result.returncode == 0

        # Count rows — must be exactly the number of seed entries, not doubled
        with psycopg.connect(self.DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM threat_patterns;")
                (count,) = cur.fetchone()

        # We have 4 seed files; exact count depends on seed data size
        # At minimum must be > 0, and re-run must not double them
        assert count > 0, "No rows in threat_patterns after two build_index runs."
        # Check no duplicates on the unique key
        with psycopg.connect(self.DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM ("
                    "  SELECT source, pattern_id, COUNT(*) "
                    "  FROM threat_patterns "
                    "  GROUP BY source, pattern_id "
                    "  HAVING COUNT(*) > 1"
                    ") AS dups;"
                )
                (dups,) = cur.fetchone()
        assert dups == 0, f"{dups} duplicate (source, pattern_id) pairs found after idempotent re-run."
