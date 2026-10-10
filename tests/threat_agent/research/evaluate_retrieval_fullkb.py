"""Evaluate retrieval on the graded full-KB benchmark (dev / company / held-out).

    python tests/threat_agent/research/evaluate_retrieval_fullkb.py baseline
    python tests/threat_agent/research/evaluate_retrieval_fullkb.py full

``baseline`` = the 24-entry seed KB (database trc_engine).
``full``     = the 2,300-entry KB (database trc_engine_fullkb) with domain tags.

For ``full`` the rerank weights are CHOSEN ON THE DEV SPLIT ONLY (grid below);
the company and held-out splits are reported for that choice and never used to
select it.  The whole grid is saved for transparency (sensitivity analysis).

Metrics at K=10 (relevance: 2 = expert-cited seed, 1 = MITRE-linked neighbour):
    ndcg      graded nDCG@10
    seed_rec  fraction of seeds found in the top 10
    hit       any relevant (>=1) in the top 10
    mrr       reciprocal rank of the first relevant result
    p5, p10   precision at 5 / 10 over relevant (>=1)
    strict    company split: recall of the company document's own references
"""

from __future__ import annotations

import json
import math
import os
import re
import statistics
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT))

which = sys.argv[1] if len(sys.argv) > 1 else "baseline"
if which == "full":
    from config.settings import Settings

    os.environ["DATABASE_URL"] = re.sub(
        r"/[^/?]+(\?.*)?$", r"/trc_engine_fullkb\1", Settings().DATABASE_URL
    )

from agents.threat_agent import retrieval as rv  # noqa: E402
from agents.threat_agent.rerank import RerankParams, infer_asset_tags, rerank_score  # noqa: E402
from agents.threat_agent.schemas import AssetModel, DFDContext  # noqa: E402
from common.db import get_db_connection  # noqa: E402

K = 10
POOL = 60
DATA = Path(__file__).resolve().parent / "retrieval_eval_fullkb.json"
BOOSTS = [0.0, 0.01, 0.02, 0.04, 0.08]
PENALTIES = [0.0, 0.03, 0.06, 0.10, 0.20]
# Production defaults (config/settings.py).  boost = dev-selected; penalty 0.03 is a
# POST-HOC choice: dev is indifferent to it (no hardware noise there) and the
# sensitivity grid shows >=0.03 helps the held-out split, so held-out is slightly optimistic.
DEPLOYED = RerankParams(tag_boost=0.02, hardware_penalty=0.03)


def _asset(q: dict) -> AssetModel:
    a = q["asset"]
    return AssetModel(
        asset_id=a["asset_id"], name=a["name"], asset_type=a["asset_type"],
        dfd_context=DFDContext(interfaces=a["interfaces"], trust_zone=a["trust_zone"]),
        device_config=a["device_config"],
    )


def fetch_pool(queries: list[dict]) -> dict[str, dict]:
    import numpy as np
    from pgvector.psycopg import register_vector

    enc = rv._get_encoder()
    out: dict[str, dict] = {}
    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            for q in queries:
                asset = _asset(q)
                text = rv._build_query_text(asset)
                vec = enc.encode([text], normalize_embeddings=True).astype(np.float32)[0]
                cur.execute(
                    "SELECT metadata, 1 - (embedding <=> %s) FROM threat_patterns "
                    "WHERE source = ANY(%s) ORDER BY embedding <=> %s LIMIT %s;",
                    (vec, rv._select_kb_sources(asset), vec, POOL),
                )
                rows = []
                for meta, sim in cur.fetchall():
                    meta = json.loads(meta) if isinstance(meta, str) else meta
                    rows.append((meta["pattern_id"], float(sim), meta.get("domain_tags", [])))
                out[q["query_id"]] = {"rows": rows, "tags": sorted(infer_asset_tags(asset))}
    return out


def rank(entry: dict, params: RerankParams) -> list[str]:
    rows = entry["rows"]
    tagged = any(r[2] for r in rows)
    if tagged and not params.is_noop:
        rows = sorted(rows, key=lambda r: rerank_score(r[1], entry["tags"], r[2], params), reverse=True)
    else:
        rows = sorted(rows, key=lambda r: r[1], reverse=True)
    return [r[0] for r in rows[:K]]


def metrics(ranked: list[str], q: dict) -> dict[str, float]:
    rel: dict[str, int] = q["relevant"]
    gains = [rel.get(p, 0) for p in ranked]
    dcg = sum(g / math.log2(i + 2) for i, g in enumerate(gains))
    ideal = sorted(rel.values(), reverse=True)[:K]
    idcg = sum(g / math.log2(i + 2) for i, g in enumerate(ideal))
    first = next((i + 1 for i, g in enumerate(gains) if g >= 1), None)
    seeds = q["seeds"]
    out = {
        "ndcg": dcg / idcg if idcg else 0.0,
        "seed_rec": sum(1 for s in seeds if s in ranked) / len(seeds),
        "hit": 1.0 if first else 0.0,
        "mrr": 1.0 / first if first else 0.0,
        "p5": sum(1 for g in gains[:5] if g >= 1) / 5,
        "p10": sum(1 for g in gains if g >= 1) / K,
    }
    if q.get("strict_seeds"):
        out["strict"] = sum(1 for s in q["strict_seeds"] if s in ranked) / len(q["strict_seeds"])
    return out


def evaluate(queries: list[dict], pool: dict, params: RerankParams) -> dict:
    per_q = {q["query_id"]: metrics(rank(pool[q["query_id"]], params), q) for q in queries}
    splits: dict[str, dict[str, float]] = {}
    for split in ("dev", "company", "heldout"):
        ids = [q["query_id"] for q in queries if q["split"] == split]
        keys = {k for i in ids for k in per_q[i]}
        splits[split] = {k: round(statistics.mean(per_q[i][k] for i in ids if k in per_q[i]), 4)
                         for k in sorted(keys)}
    return {"splits": splits, "per_query": per_q}


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    queries = data["queries"]
    pool = fetch_pool(queries)
    result: dict = {"kb": which, "k": K, "pool": POOL}
    result["raw_cosine"] = evaluate(queries, pool, RerankParams())

    if which == "full":
        grid = []
        for b in BOOSTS:
            for p in PENALTIES:
                ev = evaluate(queries, pool, RerankParams(tag_boost=b, hardware_penalty=p))
                grid.append({"tag_boost": b, "hardware_penalty": p, **ev["splits"]["dev"],
                             "company": ev["splits"]["company"], "heldout": ev["splits"]["heldout"]})
        # Selection uses DEV nDCG only; ties -> the smaller (simpler) adjustment.
        best = max(grid, key=lambda g: (round(g["ndcg"], 4), -(g["tag_boost"] + g["hardware_penalty"])))
        chosen = RerankParams(tag_boost=best["tag_boost"], hardware_penalty=best["hardware_penalty"])
        result["grid"] = grid
        result["chosen"] = {"tag_boost": best["tag_boost"], "hardware_penalty": best["hardware_penalty"],
                            "selected_on": "dev nDCG@10"}
        result["rerank"] = evaluate(queries, pool, chosen)
        result["deployed"] = {"tag_boost": DEPLOYED.tag_boost,
                              "hardware_penalty": DEPLOYED.hardware_penalty,
                              **evaluate(queries, pool, DEPLOYED)}

    out = _ROOT / "docs" / "research" / f"retrieval_fullkb_eval_{which}.json"
    out.write_text(json.dumps(result, indent=1), encoding="utf-8")

    def show(label: str, ev: dict) -> None:
        print(f"\n[{label}]")
        for split, m in ev["splits"].items():
            print(f"  {split:8s} " + "  ".join(f"{k}={v:.3f}" for k, v in m.items()))

    show(f"{which} / raw cosine", result["raw_cosine"])
    if which == "full":
        print("\nchosen on dev:", result["chosen"])
        show("full / rerank (chosen on dev)", result["rerank"])
        show("full / DEPLOYED defaults (boost 0.02, penalty 0.03)", result["deployed"])
    print("\nwrote", out)


if __name__ == "__main__":
    main()
