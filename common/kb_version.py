"""A real version for the knowledge base: a fingerprint of its content, not the label 'latest'."""

from __future__ import annotations

import logging
from functools import lru_cache

from common.db import get_db_connection

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def kb_fingerprint() -> str | None:
    """Short hash of every threat pattern's id and text; None if the database cannot be reached."""
    try:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*),
                       md5(coalesce(string_agg(md5(metadata::text), '' ORDER BY id), ''))
                FROM threat_patterns;
                """
            )
            row = cur.fetchone()
    except Exception as exc:  # a missing version must never stop an analysis
        logger.warning("could not fingerprint the knowledge base: %s", exc)
        return None
    if row is None or not row[0]:
        return None
    return f"kb-{row[0]}-{str(row[1])[:12]}"
