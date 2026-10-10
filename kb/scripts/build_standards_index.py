"""Build the Compliance/Standards reference index in the FULL-KB database.

Writes table ``standards_chunks`` into ``trc_engine_fullkb`` (never the baseline
DB).  ``threat_patterns`` is not touched.

    python -m kb.scripts.fetch_standards_kb
    python -m kb.scripts.build_standards_index
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


def _db_name(url: str) -> str:
    return re.search(r"/([^/?]+)(\?.*)?$", url).group(1)  # type: ignore[union-attr]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-name", default="trc_engine_fullkb")
    parser.add_argument("--dir", type=Path, default=Path("kb/data/standards"))
    parser.add_argument("--model", default="all-MiniLM-L6-v2")
    parser.add_argument("--only", choices=["all", "cra"], default="all",
                        help="'cra' refreshes only the Cyber Resilience Act rows.")
    args = parser.parse_args()

    from config.settings import Settings, get_settings

    base = Settings().DATABASE_URL
    if args.database_name == _db_name(base):
        sys.exit(f"[ABORT] refusing to write into baseline DB '{_db_name(base)}'.")
    os.environ["DATABASE_URL"] = re.sub(r"/[^/?]+(\?.*)?$", rf"/{args.database_name}\1", base)
    get_settings.cache_clear()
    effective = _db_name(get_settings().DATABASE_URL)
    if effective != args.database_name:
        sys.exit(f"[ABORT] effective DB '{effective}' != '{args.database_name}'.")
    print(f"[BUILD] target database: {effective}", file=sys.stderr)

    from pgvector.psycopg import register_vector
    from sentence_transformers import SentenceTransformer

    from common.db import get_db_connection
    from kb.loaders.standards_loaders import load_cra, load_pdf

    chunks = []
    d = args.dir
    if args.only == "all":
        for part in range(1, 6):
            chunks += load_pdf(
                d / f"CC2022PART{part}R1.pdf", "Common Criteria", f"CC:2022 R1 Part {part}"
            )
        chunks += load_pdf(d / "CEM2022R1.pdf", "Common Criteria", "CEM:2022 R1")
        chunks += load_pdf(
            d / "JIL-Attack-Potential-Smartcards-v3.2.1.pdf",
            "JIL",
            "JIL Application of Attack Potential to Smartcards v3.2.1",
        )
    chunks += load_cra(d / "CRA-2024-2847.xhtml")
    by_doc: dict[str, int] = {}
    for c in chunks:
        by_doc[c.doc] = by_doc.get(c.doc, 0) + 1
    for k, v in by_doc.items():
        print(f"  [LOAD] {v:5d} chunks  {k}", file=sys.stderr)

    model = SentenceTransformer(args.model)
    texts = [f"{c.doc} {c.locator} {c.title}. {c.text}" for c in chunks]
    emb = model.encode(texts, normalize_embeddings=True, batch_size=32, show_progress_bar=False)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        conn.commit()
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute(
                """CREATE TABLE IF NOT EXISTS standards_chunks (
                    id SERIAL PRIMARY KEY,
                    standard TEXT NOT NULL, doc TEXT NOT NULL, locator TEXT NOT NULL,
                    title TEXT NOT NULL DEFAULT '', text TEXT NOT NULL,
                    embedding vector(384) NOT NULL, metadata JSONB DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT now(),
                    UNIQUE (doc, locator));"""
            )
            for c, e in zip(chunks, emb, strict=True):
                cur.execute(
                    """INSERT INTO standards_chunks
                       (standard, doc, locator, title, text, embedding, metadata)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (doc, locator) DO UPDATE SET
                         text=EXCLUDED.text, title=EXCLUDED.title,
                         embedding=EXCLUDED.embedding;""",
                    (c.standard, c.doc, c.locator, c.title, c.text, e,
                     json.dumps({"kind": "reference-text"})),
                )
        conn.commit()
    print(f"[BUILD] Done: {len(chunks)} chunks.", file=sys.stderr)


if __name__ == "__main__":
    main()
