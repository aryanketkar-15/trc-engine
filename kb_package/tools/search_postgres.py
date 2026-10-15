"""Search the knowledge base in PostgreSQL (after you restored it).

    pip install "psycopg[binary]" pgvector numpy sentence-transformers
    python tools/search_postgres.py "firmware update without signature" \
        --db postgresql://USER:PASS@HOST:PORT/trc_kb
"""

import argparse

import numpy as np
import psycopg
from pgvector.psycopg import register_vector
from sentence_transformers import SentenceTransformer

p = argparse.ArgumentParser()
p.add_argument("query")
p.add_argument("--db", required=True, help="connection URL of the database holding the tables")
p.add_argument("--top", type=int, default=10)
p.add_argument("--source", nargs="*", default=["CAPEC", "ATT&CK", "CWE", "STRIDE"])
a = p.parse_args()

q = SentenceTransformer("all-MiniLM-L6-v2").encode([a.query], normalize_embeddings=True)[0]
q = q.astype(np.float32)
with psycopg.connect(a.db) as conn:
    register_vector(conn)
    rows = conn.execute(
        """SELECT pattern_id, source, title, 1 - (embedding <=> %s) AS similarity
           FROM threat_patterns WHERE source = ANY(%s)
           ORDER BY embedding <=> %s LIMIT %s""",
        (q, a.source, q, a.top),
    ).fetchall()
for pid, src, title, sim in rows:
    print(f"{sim:.3f}  {pid:<18} {src:<7} {title[:70]}")
