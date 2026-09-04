"""
common/db.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  Database Connection Pool
──────────────────────────────────────────────────────────────────────────────
Provides a thin, synchronous connection pool over psycopg3 (psycopg).

The rest of the TRC Engine uses synchronous I/O (see common/llm_client.py —
chat_completion and _call_api are plain def, not async def), so we keep the
DB layer synchronous too to avoid mixed sync/async complexity.

Usage::

    from common.db import get_db_connection

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            row = cur.fetchone()

The pool is lazily initialised on first call and cached for the process
lifetime.  DATABASE_URL is read from config/settings.py (which in turn reads
from the .env file or real environment variables).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Generator

from psycopg_pool import ConnectionPool

from config.settings import get_settings

if TYPE_CHECKING:
    import psycopg

# Module-level pool — None until first call to get_db_connection().
_POOL: ConnectionPool | None = None


def _get_pool() -> ConnectionPool:
    """Return (or lazily initialise) the global connection pool."""
    global _POOL
    if _POOL is None:
        settings = get_settings()
        _POOL = ConnectionPool(
            conninfo=settings.DATABASE_URL,
            min_size=1,
            max_size=10,
            # Open connections eagerly so the first request is fast.
            open=True,
        )
    return _POOL


@contextmanager
def get_db_connection() -> Generator[psycopg.Connection, None, None]:  # type: ignore[type-arg]
    """Yield a live psycopg connection from the pool.

    The connection is automatically returned to the pool when the context
    manager exits, whether normally or via an exception.

    Example::

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM threat_patterns;")
                (count,) = cur.fetchone()
    """
    pool = _get_pool()
    with pool.connection() as conn:
        yield conn
