"""
kb/scripts/build_index.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  pgvector Index Builder  (Aryan)
──────────────────────────────────────────────────────────────────────────────
CLI script that loads all KB seed data, embeds entries with
sentence-transformers, and upserts them into PostgreSQL (pgvector).

Usage::

    # Spin up Postgres first:
    docker compose up -d

    # Then populate the KB:
    python -m kb.scripts.build_index

    # Or with an explicit data dir / model override:
    python -m kb.scripts.build_index \\
        --data-dir kb/data \\
        --model all-MiniLM-L6-v2

Idempotent: re-running does an ON CONFLICT ... DO UPDATE so no rows are
duplicated.  Safe to run after adding new seed entries.

Embedding model: ``all-MiniLM-L6-v2`` (384-dim, CPU-only) — unchanged.

Re-run this script whenever:
    1. New entries are added to a seed JSON file.
    2. A new seed file is added.
    3. The embedding model is changed.
    4. Full CAPEC/ATT&CK/CWE XML files are added (Week 3).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ── Dependency guards ──────────────────────────────────────────────────────

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
except ImportError as e:
    print(
        "[ERROR] sentence-transformers or numpy is not installed.\n"
        "Run: pip install sentence-transformers numpy\n"
        f"Original error: {e}",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import psycopg  # noqa: F401
    from pgvector.psycopg import register_vector
except ImportError as e:
    print(
        "[ERROR] psycopg or pgvector is not installed.\n"
        "Run: pip install psycopg[binary,pool] pgvector\n"
        f"Original error: {e}",
        file=sys.stderr,
    )
    sys.exit(1)

from common.db import get_db_connection
from kb.loaders.attck_loader import ATTCKLoader
from kb.loaders.base_loader import KBEntry
from kb.loaders.capec_loader import CAPECLoader
from kb.loaders.cwe_loader import CWELoader
from kb.loaders.stride_loader import STRIDELoader

# ── Loader registry — add new loaders here in Week 3 ──────────────────────

_LOADER_MAP: list[tuple[object, str]] = [
    (CAPECLoader(), "capec_seed.json"),
    (ATTCKLoader(), "attck_seed.json"),
    (CWELoader(), "cwe_seed.json"),
    (STRIDELoader(), "stride_seed.json"),
]


# ── Core build functions ───────────────────────────────────────────────────


def _load_all_entries(data_dir: Path) -> list[KBEntry]:
    """Run all loaders and return the merged, deduplicated entry list."""
    all_entries: list[KBEntry] = []
    seen: set[str] = set()

    for loader, filename in _LOADER_MAP:
        data_path = data_dir / filename
        if not data_path.exists():
            print(f"  [SKIP] {filename} not found in {data_dir}", file=sys.stderr)
            continue

        entries = loader.load(data_path)  # type: ignore[union-attr]
        added = 0
        for entry in entries:
            key = f"{entry.source}::{entry.pattern_id}"
            if key not in seen:
                seen.add(key)
                all_entries.append(entry)
                added += 1
            else:
                print(f"  [DEDUP] Skipping duplicate {key}", file=sys.stderr)

        print(
            f"  [LOAD] {loader.source}: {added} entries loaded from {filename}",  # type: ignore[union-attr]
            file=sys.stderr,
        )

    return all_entries


def _embed_entries(
    entries: list[KBEntry],
    model_name: str,
) -> np.ndarray:  # type: ignore[type-arg]
    """Embed all KB entries using the sentence transformer model.

    Each entry's embedding_text() is encoded into a 384-dim unit vector.
    The model and dimensionality are UNCHANGED from the FAISS implementation.
    """
    print(f"  [EMBED] Loading model '{model_name}'…", file=sys.stderr)
    model = SentenceTransformer(model_name)
    texts = [e.embedding_text() for e in entries]
    print(f"  [EMBED] Encoding {len(texts)} entries…", file=sys.stderr)
    embeddings: np.ndarray = model.encode(  # type: ignore[assignment]
        texts,
        normalize_embeddings=True,
        show_progress_bar=True,
        batch_size=32,
    )
    return embeddings.astype(np.float32)


def _init_schema() -> None:
    """Create the pgvector extension and threat_patterns table if not present."""
    print("  [DB] Initialising schema…", file=sys.stderr)
    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    id          SERIAL PRIMARY KEY,
                    source      TEXT NOT NULL,           -- 'STRIDE' | 'CAPEC' | 'ATTACK' | 'CWE'
                    pattern_id  TEXT NOT NULL,           -- e.g. 'CWE-306', 'CAPEC-94'
                    title       TEXT NOT NULL,
                    description TEXT NOT NULL,
                    embedding   vector(384) NOT NULL,
                    metadata    JSONB DEFAULT '{}',
                    created_at  TIMESTAMPTZ DEFAULT now(),
                    UNIQUE (source, pattern_id)
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_threat_patterns_source "
                "ON threat_patterns (source);"
            )
            # NOTE: No IVFFlat/HNSW approximate vector index is added here.
            # With ~24 rows, a sequential scan with <=> is effectively instant.
            # Add an HNSW index once the KB grows into the thousands of entries.
        conn.commit()
    print("  [DB] Schema ready.", file=sys.stderr)


def _upsert_entries(
    entries: list[KBEntry],
    embeddings: np.ndarray,  # type: ignore[type-arg]
) -> None:
    """Upsert embedded KB entries into the threat_patterns table.

    Uses ON CONFLICT (source, pattern_id) DO UPDATE so re-running this
    script after adding new seed entries is fully idempotent.
    """
    import json  # noqa: PLC0415

    print(f"  [DB] Upserting {len(entries)} entries…", file=sys.stderr)
    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            for entry, emb in zip(entries, embeddings, strict=True):
                meta_json = json.dumps(entry.to_metadata_dict())
                cur.execute(
                    """
                    INSERT INTO threat_patterns
                        (source, pattern_id, title, description, embedding, metadata)
                    VALUES
                        (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source, pattern_id) DO UPDATE SET
                        title       = EXCLUDED.title,
                        description = EXCLUDED.description,
                        embedding   = EXCLUDED.embedding,
                        metadata    = EXCLUDED.metadata;
                    """,
                    (
                        entry.source,
                        entry.pattern_id,
                        entry.title,
                        entry.description,
                        emb,
                        meta_json,
                    ),
                )
        conn.commit()
    print(f"  [DB] Upsert complete ({len(entries)} rows).", file=sys.stderr)


# ── CLI entry point ────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build pgvector KB from seed data.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("kb/data"),
        help="Directory containing seed JSON files.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="all-MiniLM-L6-v2",
        help="Sentence transformer model name.",
    )
    return parser.parse_args()


def build(
    data_dir: Path = Path("kb/data"),
    model_name: str = "all-MiniLM-L6-v2",
) -> None:
    """Programmatic entry point — usable from tests / CI.

    Args:
        data_dir:   Directory containing seed JSON files.
        model_name: Sentence transformer model name.
    """
    print("[BUILD] Starting KB pgvector build…", file=sys.stderr)

    _init_schema()

    entries = _load_all_entries(data_dir)
    if not entries:
        print("[ERROR] No KB entries loaded. Check seed files.", file=sys.stderr)
        sys.exit(1)

    print(f"[BUILD] Total entries to embed: {len(entries)}", file=sys.stderr)
    embeddings = _embed_entries(entries, model_name)
    _upsert_entries(entries, embeddings)

    print("[BUILD] Done.", file=sys.stderr)


if __name__ == "__main__":
    args = _parse_args()
    build(data_dir=args.data_dir, model_name=args.model)
