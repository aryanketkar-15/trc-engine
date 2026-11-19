r"""How often is a generated threat card right on the first attempt?

    python scripts/measure_first_pass.py \
        --project projects/imported/<project>_project.json
    python scripts/measure_first_pass.py --paths 6 \
        --project projects/smart_door_lock_multi_use_case.json

For every use case in the project file it builds the attack paths, asks the model for one scenario
per path ONCE (no retry, no human review) and runs the same checks the Threat Agent uses: the
four validator checks and the grounding checks. It prints the share that passed everything at the
first attempt and why the others failed. A model fallback (the model failed and a rule-based
scenario was written instead) is counted separately and is NOT counted as a pass.

Needs the full knowledge base in the database and the model switched on (see
docs/Ollama_Setup_and_Test.md). Nothing is approved or written to the shared state.
Exit code: 0 finished, 2 setup problem.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.threat_agent import generator
from agents.threat_agent.attack_chain import build_paths
from agents.threat_agent.grounding import check_grounding, path_id_from_tid
from agents.threat_agent.project import load_inputs
from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
from agents.threat_agent.validator import Validator
from config.settings import get_settings

LABEL = {
    "CITATION_MISSING": "Citation",
    "SCHEMA_INCOMPLETE": "Schema",
    "CONSISTENCY_MISMATCH": "STRIDE fit",
    "EVIDENCE_GENERIC": "Evidence",
    "CITATION_NOT_RETRIEVED": "Grounded: cites a pattern not retrieved",
    "ASSET_NOT_IN_INPUT": "Grounded: asset not in input",
    "CITATION_MISMATCH": "Grounded: citation names another pattern",
    "EXPOSURE_NOT_GROUNDED": "Grounded: exposure not about the asset",
}


def measure_use_case(run: Any, max_paths: int, validator: Validator) -> dict[str, Any]:  # noqa: ANN401
    """One use case: generate once, check, and count."""
    fell_back: set[str] = set()
    real_fallback = generator._deterministic_fallback_for_path

    def counted(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        fell_back.add(str(getattr(args[0], "path_id", "")))
        return real_fallback(*args, **kwargs)

    generator._deterministic_fallback_for_path = counted  # type: ignore[assignment]
    started = time.perf_counter()
    try:
        candidates = fetch_candidates(build_retrieval_plan(run))
        paths = sorted(build_paths(candidates, run), key=lambda p: -p.chain_confidence)[:max_paths]
        by_id = {p.path_id: p for p in paths}
        scenarios = generator.generate_scenarios(paths, run)
    finally:
        generator._deterministic_fallback_for_path = real_fallback  # type: ignore[assignment]

    failures: Counter[str] = Counter()
    passed = 0
    for scenario in scenarios:
        result = validator.validate(scenario)
        failed = [fc.check_id for fc in result.failed_checks]
        pid = path_id_from_tid(scenario.tid)
        if pid in fell_back:
            continue  # a rule-based scenario is not the model's answer: never a pass
        if pid in by_id:
            failed += [g.check_id for g in check_grounding(scenario, by_id[pid], run.assets)]
        if failed:
            failures.update(set(failed))
        else:
            passed += 1
    total = len(scenarios)
    return {
        "use_case": run.use_case_id,
        "paths": len(paths),
        "scenarios": total,
        "model_fallbacks": sum(1 for s in scenarios if path_id_from_tid(s.tid) in fell_back),
        "first_attempt_passed": passed,
        "first_attempt_rate": round(passed / total, 3) if total else None,
        "failures_by_check": {LABEL.get(k, k): v for k, v in failures.most_common()},
        "seconds": round(time.perf_counter() - started, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="project file (one or several use cases)")
    parser.add_argument(
        "--paths", type=int, default=8, help="attack paths per use case (default 8)"
    )
    parser.add_argument("--out", default=str(_ROOT / "demo_output" / "first_pass.json"))
    args = parser.parse_args()

    settings = get_settings()
    print(f"Endpoint: {settings.OPENAI_BASE_URL or 'default'}   Model: {settings.OPENAI_MODEL}")
    if (
        os.environ.get("USE_LIVE_LLM", "").lower() in ("false", "0", "no")
        or not settings.USE_LIVE_LLM
    ):
        print("USE_LIVE_LLM is off: set it to true to measure the model.")
        return 2

    try:
        runs = load_inputs(Path(args.project), "MEASURE")
    except Exception as exc:  # report plainly; this is a diagnostic tool
        print(f"Could not read the project file: {type(exc).__name__}: {str(exc)[:300]}")
        return 2

    validator = Validator()
    rows = []
    for run in runs:
        try:
            rows.append(measure_use_case(run, args.paths, validator))
        except Exception as exc:
            print(f"{run.use_case_id}: stopped, {type(exc).__name__}: {str(exc)[:300]}")
            return 2
        row = rows[-1]
        print(
            f"{row['use_case']}: {row['first_attempt_passed']} of {row['scenarios']} passed at the "
            f"first attempt ({row['model_fallbacks']} model fallbacks, {row['seconds']} s)"
        )
        for check, count in row["failures_by_check"].items():
            print(f"    {count} x {check}")

    scenarios = sum(r["scenarios"] for r in rows)
    passed = sum(r["first_attempt_passed"] for r in rows)
    summary = {
        "model": settings.OPENAI_MODEL,
        "paths_per_use_case": args.paths,
        "use_cases": rows,
        "total_scenarios": scenarios,
        "total_first_attempt_passed": passed,
        "first_attempt_rate": round(passed / scenarios, 3) if scenarios else None,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    rate = f"{summary['first_attempt_rate']:.0%}" if scenarios else "n/a"
    print(f"\nTotal: {passed} of {scenarios} passed at the first attempt ({rate}). Report: {out}")
    return 0


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    finally:
        sys.stdout.flush()
    os._exit(code)
