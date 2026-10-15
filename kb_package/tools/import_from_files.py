"""Load the knowledge base into a PostgreSQL database with pgvector, from the JSONL/NPY files.

Use this if you cannot restore the SQL dump. It creates two tables in the database you give it.
Always use a SEPARATE database; never one that Alembic or another team manages.

    pip install "psycopg[binary]" pgvector numpy
    python tools/import_from_files.py --db postgresql://USER:PASS@HOST:PORT/trc_kb
"""

import argparse
import json
from pathlib import Path

import numpy as np
import psycopg
from pgvector.psycopg import register_vector

PKG = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser()
p.add_argument("--db", required=True)
a = p.parse_args()

with psycopg.connect(a.db, autocommit=True) as c0:
    c0.execute("CREATE EXTENSION IF NOT EXISTS vector")
with psycopg.connect(a.db) as conn:
    register_vector(conn)
    conn.execute((PKG / "sql/schema.sql").read_text(encoding="utf-8"))
    pats = [json.loads(x) for x in (PKG / "data/threat_patterns.jsonl").read_text("utf-8").splitlines()]
    ep = np.load(PKG / "data/threat_patterns_embeddings.npy")
    for r, e in zip(pats, ep, strict=True):
        conn.execute(
            """INSERT INTO threat_patterns (source, pattern_id, title, description, embedding, metadata)
               VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (source, pattern_id) DO NOTHING""",
            (r["source"], r["pattern_id"], r["title"], r["description"], e, json.dumps(r["metadata"])),
        )
    chunks = [json.loads(x) for x in (PKG / "data/standards_chunks.jsonl").read_text("utf-8").splitlines()]
    ec = np.load(PKG / "data/standards_chunks_embeddings.npy")
    for r, e in zip(chunks, ec, strict=True):
        conn.execute(
            """INSERT INTO standards_chunks (standard, doc, locator, title, text, embedding, metadata)
               VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (doc, locator) DO NOTHING""",
            (r["standard"], r["doc"], r["locator"], r["title"], r["text"], e, json.dumps(r["metadata"])),
        )
    conn.commit()
    n1 = conn.execute("SELECT count(*) FROM threat_patterns").fetchone()[0]
    n2 = conn.execute("SELECT count(*) FROM standards_chunks").fetchone()[0]
print(f"loaded: threat_patterns={n1}, standards_chunks={n2}")
