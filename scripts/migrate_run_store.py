"""
scripts/migrate_run_store.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Database Migration for Threat Agent Run Registry
──────────────────────────────────────────────────────────────────────────────
Creates the `threat_agent_runs` table and indexes in PostgreSQL.
Matches the migration convention used by `kb/scripts/build_index.py`.

Usage:
    python scripts/migrate_run_store.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.threat_agent.run_store import init_postgres_run_store_schema


def main() -> None:
    print("Migrating database schema for Threat Agent run registry...", file=sys.stderr)
    init_postgres_run_store_schema()
    print("Schema migration complete: table 'threat_agent_runs' is ready.", file=sys.stderr)


if __name__ == "__main__":
    main()
