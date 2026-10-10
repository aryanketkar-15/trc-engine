"""Evaluate retrieval on the graded full-KB benchmark (dev / company / held-out).

    python tests/threat_agent/research/evaluate_retrieval_fullkb.py baseline
    python tests/threat_agent/research/evaluate_retrieval_fullkb.py full

``baseline`` = the 24-entry seed KB (database trc_engine).
``full``     = the 2,300-entry KB (database trc_engine_fullkb) with domain tags.

For ``full`` the rerank weights and STRIDE slots are CHOSEN ON THE DEV SPLIT ONLY
(grid below); company and held-out are reported for that choice and never used to
select it.  The whole grid is saved for transparency (sensitivity analysis).
Selection logic is the production function ``agents.threat_agent.rerank.select_top``.

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
from agents.threat_agent.rerank import (  # noqa: E402
    Cand,
    RerankParams,
    implied_stride,
    infer_asset_tags,
    select_top,
)
from agents.threat_agent.schemas import AssetModel, DFDContext, SecurityAttributes  # noqa: E402
from common.db import get_db_connection  # noqa: E402

K = 10
POOL = 60
STRIDE_ALL = ["Spoofing", "Tampering", "InformationDisclosure", "DenialOfService"]
DATA = Path(__file__).resolve().parent / "retrieval_eval_fullkb.json"
BOOSTS = [0.0, 0.01, 0.02, 0.04, 0.08]
PENALTIES = [0.0, 0.03, 0.06, 0.10, 0.20]
SLOTS = [0, 1, 2, 3]
# Production defaults (config/settings.py).  boost = dev-selected; penalty 0.03 is a
# POST-HOC choice (see docs/research/full_kb_retrieval_results.md).
DEPLOYED = RerankParams(tag_boost=0.02, hardware_penalty=0.03)


def _asset(q: dict) -> AssetModel:
    a = q["asset"]
    return AssetModel(
        asset_id=a["asset_id"], name=a["name"], asset_type=a["asset_type"],
        dfd_context=DFDContext(interfaces=a["interfaces"], trust_zone=a["trust_zone"]),
        device_config=a["device_config"],
        security_attributes=SecurityAttributes(**a.get("security_attributes", {})),
    )


def _cand(meta: dict, sim: float) -> Cand:
    return Cand(meta["pattern_id"], float(sim), tuple(meta.get("domain_tags", [])),
                meta.get("stride_hint"))


def fetch_pool(queries: list[dict], all_sources: bool = False) -> dict[str, dict]:
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
                sources = (
                    ["ATT&CK", "CAPEC", "CWE", "STRIDE"] if all_sources else rv._select_kb_sources(asset)
                )
                cur.execute(
                    "SELECT metadata, 1 - (embedding <=> %s) FROM threat_patterns "
                    "WHERE source = ANY(%s) ORDER BY embedding <=> %s LIMIT %s;",
                    (vec, sources, vec, POOL),
                )
                pool = []
                for meta, sim in cur.fetchall():
                    meta = json.loads(meta) if isinstance(meta, str) else meta
                    pool.append(_cand(meta, sim))
                cats: dict[str, list[Cand]] = {}
                for cat in STRIDE_ALL:  # deepest slot setting uses slots*3 = 9 per category
                    cur.execute(
                        "SELECT metadata, 1 - (embedding <=> %s) FROM threat_patterns "
                        "WHERE source = ANY(%s) AND metadata->>'stride_hint' = %s "
                        "ORDER BY embedding <=> %s LIMIT 9;",
                        (vec, sources, cat, vec),
                    )
                    cats[cat] = [
                        _cand(json.loads(m) if isinstance(m, str) else m, s)
                        for m, s in cur.fetchall()
                    ]
                out[q["query_id"]] = {
                    "pool": pool, "cats": cats, "tags": sorted(infer_asset_tags(asset)),
                    "stride": implied_stride(asset),
                }
    return out


def rank(entry: dict, params: RerankParams, slots: int = 0) -> list[str]:
    pool: list[Cand] = list(entry["pool"])
    tagged = any(c.tags for c in pool)
    if not tagged:  # untagged KB (baseline): legacy pure-cosine order
        return [c.pid for c in sorted(pool, key=lambda c: c.sim, reverse=True)[:K]]
    cands = list(pool)
    if slots > 0:
        have = {c.pid for c in cands}
        for cat in entry["stride"]:
            for c in entry["cats"].get(cat, [])[: slots * 3]:
                if c.pid not in have:
                    have.add(c.pid)
                    cands.append(c)
    return select_top(cands, entry["tags"], params, entry["stride"], slots, K)


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


def evaluate(queries: list[dict], pool: dict, params: RerankParams, slots: int = 0) -> dict:
    per_q = {q["query_id"]: metrics(rank(pool[q["query_id"]], params, slots), q) for q in queries}
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
                for sl in SLOTS:
                    ev = evaluate(queries, pool, RerankParams(tag_boost=b, hardware_penalty=p), sl)
                    grid.append({"tag_boost": b, "hardware_penalty": p, "stride_slots": sl,
                                 **ev["splits"]["dev"], "company": ev["splits"]["company"],
                                 "heldout": ev["splits"]["heldout"]})
        # Selection uses DEV nDCG only; ties -> the smaller (simpler) adjustment.
        best = max(grid, key=lambda g: (round(g["ndcg"], 4),
                                        -(g["tag_boost"] + g["hardware_penalty"] + g["stride_slots"])))
        chosen = RerankParams(tag_boost=best["tag_boost"], hardware_penalty=best["hardware_penalty"])
        result["grid"] = grid
        result["chosen"] = {"tag_boost": best["tag_boost"], "hardware_penalty": best["hardware_penalty"],
                            "stride_slots": best["stride_slots"], "selected_on": "dev nDCG@10"}
        result["rerank"] = evaluate(queries, pool, chosen, best["stride_slots"])
        result["rerank_only"] = evaluate(queries, pool, DEPLOYED, 0)
        # Coverage on top of the deployed rerank, at each slot setting (sensitivity view).
        result["deployed_by_slots"] = {
            str(sl): evaluate(queries, pool, DEPLOYED, sl)["splits"] for sl in SLOTS
        }
        # Source routing: production searches ALL sources on a tagged KB (principle, not tuned).
        pool_all = fetch_pool(queries, all_sources=True)
        result["all_sources_by_slots"] = {
            str(sl): evaluate(queries, pool_all, DEPLOYED, sl)["splits"] for sl in SLOTS
        }

    out = _ROOT / "docs" / "research" / f"retrieval_fullkb_eval_{which}.json"
    out.write_text(json.dumps(result, indent=1), encoding="utf-8")

    def show(label: str, splits: dict) -> None:
        print(f"\n[{label}]")
        for split, m in splits.items():
            print(f"  {split:8s} " + "  ".join(f"{k}={v:.3f}" for k, v in m.items()))

    show(f"{which} / raw cosine", result["raw_cosine"]["splits"])
    if which == "full":
        print("\nchosen on dev:", result["chosen"])
        show("full / chosen on dev", result["rerank"]["splits"])
        show("full / rerank only (deployed weights, no coverage)", result["rerank_only"]["splits"])
        for sl, sp in result["deployed_by_slots"].items():
            show(f"full / routed sources + STRIDE slots={sl}", sp)
        for sl, sp in result["all_sources_by_slots"].items():
            show(f"full / ALL sources + STRIDE slots={sl}", sp)
    print("\nwrote", out)


if __name__ == "__main__":
    main()
