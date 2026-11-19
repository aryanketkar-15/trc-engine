r"""How uniform are the model's risk suggestions?

    python scripts/measure_risk_spread.py --runs 3
    python scripts/measure_risk_spread.py --scrs demo_output/SCRS_demo.json \
        --project projects/imported/<project>_project.json --use-case UC-01
    python scripts/measure_risk_spread.py --t1t6 --runs 3

For every approved threat it calls the real suggester (``agents.risk_agent.suggester.suggest``)
with the live model, then computes with the rule engine what the suggestion means: the
feasibility points and level, the overall impact and the risk level. It prints how often each
impact value and each feasibility factor value was chosen, and how many threats ended up with the
same feasibility level and the same risk level. Every run is printed separately.

``--t1t6`` uses the company's six reference threats (tests/threat_agent/research/
ground_truth_t1_t6.json) on the smart door lock fixture and sets the model's suggestion next to the
company's own feasibility and risk (COMPANY_ROWS in tests/risk_agent/unit/test_risk_engine.py).
This is a check only. Nothing is tuned to match.

Nothing is written to the shared state: the state file is only read. Needs the live model switched
on (docs/Ollama_Setup_and_Test.md). Exit code: 0 finished, 2 setup problem.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.risk_agent import engine, suggester
from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import ImpactLevel
from agents.threat_agent.project import load_inputs
from agents.threat_agent.schemas import AssetModel, ThreatAgentInput, ThreatScenario
from agents.threat_agent.staleness import traceability_stamp
from config.settings import get_settings

DEFAULT_SCRS = _ROOT / "demo_output" / "SCRS_demo.json"
DEFAULT_PROJECT = (
    _ROOT / "projects" / "imported" / "Connected-Smart-Door-Lock-product-code-CSDL-100_project.json"
)
FIXTURE = _ROOT / "tests" / "threat_agent" / "e2e" / "fixtures" / "smart_door_lock" / "input.json"
GROUND_TRUTH = _ROOT / "tests" / "threat_agent" / "research" / "ground_truth_t1_t6.json"
AXES = ("safety", "financial", "operational", "privacy")
FACTORS = ("elapsed_time", "expertise", "knowledge", "window", "equipment")
SHORT = {"Negligible": "N", "Moderate": "M", "Major": "J", "Severe": "S", None: "-"}


class SetupError(Exception):
    """Something is missing before the measurement can start."""


def threats_from_state(
    scrs: Path, project: Path, use_case: str | None
) -> list[tuple[ThreatScenario, AssetModel | None]]:
    """Approved threats of the shared state, each with its asset from the project file."""
    state = json.loads(scrs.read_text(encoding="utf-8"))
    assets: dict[tuple[str | None, str], AssetModel] = {}
    for run in load_inputs(project):
        for asset in run.assets:
            assets[(run.use_case_id, asset.asset_id)] = asset
    out: list[tuple[ThreatScenario, AssetModel | None]] = []
    for raw in state.get("threat_scenarios", {}).values():
        threat = ThreatScenario.model_validate(raw)
        if use_case and threat.use_case_id != use_case:
            continue
        out.append((threat, assets.get((threat.use_case_id, threat.asset_id))))
    if not out:
        raise SetupError(f"no approved threats found in {scrs}")
    return out


def company_threats() -> list[tuple[ThreatScenario, AssetModel | None]]:
    """T1 to T6 as threats on the smart door lock fixture (the company's own attack text)."""
    inp = ThreatAgentInput(**json.loads(FIXTURE.read_text(encoding="utf-8")))
    by_id = {a.asset_id: a for a in inp.assets}
    out: list[tuple[ThreatScenario, AssetModel | None]] = []
    for row in json.loads(GROUND_TRUTH.read_text(encoding="utf-8")):
        stride = row["stride_category"]
        stride = stride[0] if isinstance(stride, list) else stride
        asset_id = row["asset_id"]
        threat = ThreatScenario.model_validate(
            {
                "tid": row["threat_id"],
                "run_id": inp.run_id,
                "asset_id": asset_id,
                "stride_category": stride,
                "attack_vector": row["attack_vector"],
                "kb_reference": row["kb_reference"],
                "evidence_chain": {
                    "exposure": row["title"],
                    "matched_pattern": row["kb_reference"],
                    "applicability_reason": f"Company reference threat: {row['title']}.",
                    "citation": f"{row['kb_reference']}: {row['title']}",
                },
                "confidence_score": 0.7,
                "status": "approved",
                "validation_status": "passed",
                **traceability_stamp(inp, asset_id),
            }
        )
        out.append((threat, by_id.get(asset_id)))
    return out


def one_run(
    items: list[tuple[ThreatScenario, AssetModel | None]], ratings: Ratings
) -> list[dict[str, Any]]:
    valid = {k: list(v) for k, v in ratings.points.items()}
    rows: list[dict[str, Any]] = []
    for threat, asset in items:
        suggestion = suggester.suggest(threat, asset, valid)
        basis = suggestion.suggestion_basis or ""
        factors = suggestion.feasibility_factors
        points, feasibility = engine.feasibility_from_factors(factors, ratings)
        overall = engine.overall_impact(suggestion.impact, ratings)
        risk = engine.risk_from_matrix(overall, feasibility, ratings)
        rows.append(
            {
                "tid": threat.tid,
                "use_case": threat.use_case_id,
                "asset": threat.asset_id,
                "impact": {a: _value(getattr(suggestion.impact, a)) for a in AXES},
                "factors": {f: str(getattr(factors, f)) for f in FACTORS},
                "points": points,
                "feasibility": feasibility.value,
                "overall_impact": overall.value,
                "risk": risk.value,
                "model_used": basis.startswith("LLM suggestion"),
            }
        )
    return rows


def _value(level: ImpactLevel | None) -> str | None:
    return level.value if level else None


def show_run(number: int, rows: list[dict[str, Any]], seconds: float) -> None:
    print(f"\n=== run {number}: {len(rows)} threats, {seconds:.0f} s ===")
    used = sum(r["model_used"] for r in rows)
    fallbacks = len(rows) - used
    print(f"model suggestions used: {used} of {len(rows)}; rule-based fallbacks: {fallbacks}")
    print("impact values chosen (counts):")
    for axis in AXES:
        c = Counter(str(r["impact"][axis]) for r in rows)
        print(f"  {axis:12} {dict(sorted(c.items()))}")
    print("feasibility factor values chosen (counts):")
    for factor in FACTORS:
        c = Counter(r["factors"][factor] for r in rows)
        print(f"  {factor:12} {dict(sorted(c.items()))}")
    print("per threat:  tid | asset | impact S/F/O/P | points -> feasibility | overall | risk")
    for r in rows:
        axes = "/".join(SHORT[r["impact"][a]] for a in AXES)
        flag = "" if r["model_used"] else "  (fallback)"
        print(
            f"  {r['tid'][-14:]:14} {r['asset']:6} {axes:8} {r['points']:3} -> "
            f"{r['feasibility']:6} {r['overall_impact']:9} {r['risk']:6}{flag}"
        )
    feas = Counter(r["feasibility"] for r in rows)
    risk = Counter(r["risk"] for r in rows)
    pts = sorted(r["points"] for r in rows)
    print(f"feasibility levels: {dict(feas)}  | distinct: {len(feas)} | points {pts[0]}-{pts[-1]}")
    print(f"risk levels:        {dict(risk)}  | distinct: {len(risk)}")
    print(
        f"same feasibility level for {max(feas.values())} of {len(rows)} threats; "
        f"same risk level for {max(risk.values())} of {len(rows)}"
    )


def show_company(runs: list[list[dict[str, Any]]]) -> None:
    from tests.risk_agent.unit.test_risk_engine import COMPANY_ROWS

    print("\n=== T1 to T6: company ratings next to the model's suggestion (check only) ===")
    runs_head = "".join(f" run {i + 1}:{'':17}|" for i in range(len(runs)))
    head = f"{'':3} | {'company':24} |" + runs_head
    print(head)
    print("    | feasibility / risk       |" + " feasibility(points) / risk |" * len(runs))
    agree_f = agree_r = total = 0
    for name, (_axes, overall, feas, risk) in COMPANY_ROWS.items():
        cells = []
        for rows in runs:
            r = next(x for x in rows if x["tid"] == name)
            cells.append(f" {r['feasibility']:6}({r['points']:2}) / {r['risk']:6}   |")
            total += 1
            agree_f += r["feasibility"] == feas
            agree_r += r["risk"] == risk
        print(f"{name:3} | {feas:6} / {risk:6} ({overall[:3]}) |" + "".join(cells))
    print(
        f"agreement over {total} model answers: feasibility {agree_f}, risk {agree_r}"
        " (company impact overall is in brackets)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="How uniform are the model's risk suggestions?")
    parser.add_argument("--scrs", type=Path, default=DEFAULT_SCRS, help="state file (read only)")
    parser.add_argument("--project", type=Path, default=DEFAULT_PROJECT)
    parser.add_argument("--use-case", help="only this use case, e.g. UC-01")
    parser.add_argument("--runs", type=int, default=3, help="repeat the measurement (default 3)")
    parser.add_argument("--t1t6", action="store_true", help="the company's six reference threats")
    parser.add_argument("--out", type=Path, help="save all runs as JSON")
    args = parser.parse_args()
    try:
        if not getattr(get_settings(), "USE_LIVE_LLM", True):
            raise SetupError("USE_LIVE_LLM is off; this measurement needs the live model")
        items = (
            company_threats()
            if args.t1t6
            else threats_from_state(args.scrs, args.project, args.use_case)
        )
    except (SetupError, OSError, ValueError) as exc:
        print(f"PROBLEM: {exc}")
        return 2
    ratings = Ratings.load()
    runs: list[list[dict[str, Any]]] = []
    for number in range(1, args.runs + 1):
        started = time.time()
        rows = one_run(items, ratings)
        runs.append(rows)
        show_run(number, rows, time.time() - started)
    if args.t1t6:
        show_company(runs)
    if args.out:
        args.out.write_text(json.dumps(runs, indent=2), encoding="utf-8")
        print(f"\nsaved: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
