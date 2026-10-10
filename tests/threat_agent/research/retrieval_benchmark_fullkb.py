"""Run the existing retrieval benchmark against the baseline or full KB database.

Does NOT modify retrieval_benchmark.py or overwrite its report: the markdown
writer is disabled and results go to a separate JSON file.

    python tests/threat_agent/research/retrieval_benchmark_fullkb.py baseline
    python tests/threat_agent/research/retrieval_benchmark_fullkb.py full

NOTE: the labelled "relevant" patterns come from the 24-entry seed KB.  Against
the full KB, unlabelled-but-relevant patterns count as misses, so precision is
a lower bound on quality, not a like-for-like comparison.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

which = sys.argv[1] if len(sys.argv) > 1 else "baseline"
if which == "full":
    from config.settings import Settings

    os.environ["DATABASE_URL"] = re.sub(
        r"/[^/?]+(\?.*)?$", r"/trc_engine_fullkb\1", Settings().DATABASE_URL
    )

import retrieval_benchmark as rb  # noqa: E402

from agents.threat_agent.retrieval import (  # noqa: E402
    build_retrieval_plan,
    fetch_candidates,
)
from agents.threat_agent.schemas import ThreatAgentInput  # noqa: E402

rb.write_results_markdown = lambda *a, **k: None  # type: ignore[assignment]
summary = rb.run_benchmark()

fixture = json.loads(
    (_ROOT / "tests/threat_agent/e2e/fixtures/smart_door_lock/input.json").read_text(
        encoding="utf-8"
    )
)
supp: dict[str, list[dict[str, object]]] = {}
for asset_id in ("AS-3", "AS-6"):
    sub = {**fixture, "assets": [a for a in fixture["assets"] if a["asset_id"] == asset_id]}
    cands = fetch_candidates(
        build_retrieval_plan(ThreatAgentInput.model_validate(sub), top_k=10)
    )
    supp[asset_id] = [
        {"id": c.pattern_id, "title": c.title, "score": round(c.retrieval_score, 4)}
        for c in cands
    ]
summary["smart_door_lock_top10"] = supp
summary["kb"] = which

out = _ROOT / "docs" / "research" / f"retrieval_benchmark_{which}_run.json"
out.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
print("wrote", out)
