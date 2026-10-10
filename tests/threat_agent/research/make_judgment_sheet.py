"""Generate a relevance-judgment sheet for an EXPERT (pooled top-10 results).

The graded labels in retrieval_eval_fullkb.json are conservative: a pattern is
only "relevant" if it is expert-cited or MITRE-linked to a seed.  Many correct
results (e.g. 'Component Firmware' for a firmware asset) are therefore counted
as misses.  The standard fix is pooled judgment: an expert marks each of the
pooled top-10 results Relevant / Partly / Not relevant, and metrics are
recomputed on those judgments.

    python tests/threat_agent/research/make_judgment_sheet.py full
    -> docs/research/retrieval_judgment_sheet.csv   (give to the expert)

Columns: query_id, asset, pattern_id, title, systems (which rankings returned it),
expert_judgment (blank: R / P / N), expert_comment (blank).
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT))

which = sys.argv[1] if len(sys.argv) > 1 else "full"
if which == "full":
    from config.settings import Settings

    os.environ["DATABASE_URL"] = re.sub(
        r"/[^/?]+(\?.*)?$", r"/trc_engine_fullkb\1", Settings().DATABASE_URL
    )

import evaluate_retrieval_fullkb as ev  # noqa: E402

from agents.threat_agent.rerank import RerankParams  # noqa: E402
from common.db import get_db_connection  # noqa: E402


def main() -> None:
    data = json.loads(ev.DATA.read_text(encoding="utf-8"))
    queries = data["queries"]
    pool = ev.fetch_pool(queries)
    configs = {
        "cosine": RerankParams(),
        "rerank": RerankParams(tag_boost=0.02, hardware_penalty=0.0),
    }
    with get_db_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pattern_id, title FROM threat_patterns;")
        titles = dict(cur.fetchall())

    out = _ROOT / "docs" / "research" / "retrieval_judgment_sheet.csv"
    n = 0
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["query_id", "asset", "pattern_id", "title", "systems",
                    "expert_judgment (R/P/N)", "expert_comment"])
        for q in queries:
            seen: dict[str, list[str]] = {}
            for name, params in configs.items():
                for pid in ev.rank(pool[q["query_id"]], params):
                    seen.setdefault(pid, []).append(name)
            for pid, systems in seen.items():
                w.writerow([q["query_id"], q["asset"]["name"], pid, titles.get(pid, ""),
                            "+".join(systems), "", ""])
                n += 1
    print(f"wrote {out} ({n} rows to judge)")


if __name__ == "__main__":
    main()
