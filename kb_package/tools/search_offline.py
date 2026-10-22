# ruff: noqa: E501
"""Search the knowledge base with NO database (numpy + sentence-transformers only).

    pip install numpy sentence-transformers
    python tools/search_offline.py "firmware update over bluetooth without signature check"
    python tools/search_offline.py "key extraction side channel" --source CAPEC --top 5
    python tools/search_offline.py "audit log deletion" --tags firmware
    python tools/search_offline.py "evaluation of attack potential" --standards
"""

import argparse
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

PKG = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser()
p.add_argument("query")
p.add_argument("--top", type=int, default=10)
p.add_argument("--source", choices=["CAPEC", "ATT&CK", "CWE", "STRIDE"], help="only this catalogue")
p.add_argument("--tags", help="only patterns with this domain tag (firmware, hardware, cloud, ...)")
p.add_argument("--standards", action="store_true", help="search the standards text, not the attacks")
a = p.parse_args()

name = "standards_chunks" if a.standards else "threat_patterns"
rows = [json.loads(x) for x in (PKG / f"data/{name}.jsonl").read_text("utf-8").splitlines()]
emb = np.load(PKG / f"data/{name}_embeddings.npy")
q = SentenceTransformer("all-MiniLM-L6-v2").encode([a.query], normalize_embeddings=True)[0]
sim = emb @ q  # cosine similarity, because every vector has unit length
shown = 0
for i in np.argsort(-sim):
    r = rows[i]
    if a.standards:
        print(f"{sim[i]:.3f}  {r['doc'][:28]:<28} {r['locator']:<18} {r['title'][:50]}")
    else:
        if a.source and r["source"] != a.source:
            continue
        if a.tags and a.tags not in r["metadata"].get("domain_tags", []):
            continue
        print(f"{sim[i]:.3f}  {r['pattern_id']:<18} {r['source']:<7} {r['title'][:70]}")
    shown += 1
    if shown >= a.top:
        break
