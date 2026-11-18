"""Does the configured language model really work in all three agents?

    python scripts/live_agents_check.py                 # a small, fast check (about 2 assets)
    python scripts/live_agents_check.py --assets 4 --paths 8

It runs the Threat Agent, the Risk Agent and the Compliance Agent once each with the model switched
on, and counts for every agent how often the model's answer was used and how often the agent fell
back to its rule-based text. A model that is reachable but answers in a shape the agents cannot use
shows up here as "fell back", which is the failure that otherwise goes unnoticed.

Needs: the database running with the full knowledge base, and the model reachable (see
docs/Ollama_Setup_and_Test.md). Exit code: 0 all three agents used the model, 1 at least one agent
only fell back, 2 the setup is not ready (no model, wrong settings).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.compliance_agent import engine as cengine
from agents.compliance_agent import explainer
from agents.risk_agent import engine as rengine
from agents.risk_agent import suggester
from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import RiskLevel, Treatment, TreatmentDecision
from agents.threat_agent import generator
from agents.threat_agent.attack_chain import build_paths
from agents.threat_agent.orchestrator import generate_and_validate_with_retry
from agents.threat_agent.project import load_inputs
from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
from common.llm_client import LLMClientError, chat_completion
from config.settings import get_settings

DEFAULT_PROJECT = _ROOT / "projects" / "smart_door_lock_multi_use_case.json"


class Meter:
    """Counts model calls per agent without touching the agents' own code."""

    def __init__(self) -> None:
        self.stage = "setup"
        self.calls: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.fallback_paths = 0
        self.bad_answers: list[str] = []

    def wrap_chat(self, real: Any) -> Any:  # noqa: ANN401
        def call(*args: Any, **kwargs: Any) -> str:  # noqa: ANN401
            started = time.perf_counter()
            entry: dict[str, Any] = {"ok": False, "seconds": 0.0}
            self.calls[self.stage].append(entry)
            try:
                answer = real(*args, **kwargs)
                entry["ok"] = True
                return answer
            except LLMClientError as exc:
                entry["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                raise
            finally:
                entry["seconds"] = round(time.perf_counter() - started, 1)

        return call

    def summary(self, stage: str) -> dict[str, Any]:
        calls = self.calls[stage]
        seconds = [c["seconds"] for c in calls]
        return {
            "model_calls": len(calls),
            "answered": sum(1 for c in calls if c["ok"]),
            "errors": [c["error"] for c in calls if c.get("error")][:3],
            "avg_seconds": round(sum(seconds) / len(seconds), 1) if seconds else None,
            "max_seconds": max(seconds) if seconds else None,
        }


def _install(meter: Meter) -> None:
    for module in (generator, suggester, explainer):
        module.chat_completion = meter.wrap_chat(chat_completion)  # type: ignore[attr-defined]
    real_fallback = generator._deterministic_fallback_for_path
    real_parse = generator._parse_llm_response

    def fallback(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        if meter.stage == "threat":
            meter.fallback_paths += 1
        return real_fallback(*args, **kwargs)

    def parse(raw: str, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        try:
            return real_parse(raw, *args, **kwargs)
        except ValueError:
            meter.bad_answers.append(raw[:300])
            raise

    generator._deterministic_fallback_for_path = fallback  # type: ignore[assignment]
    generator._parse_llm_response = parse  # type: ignore[assignment]


def check_settings() -> list[str]:
    """Reasons the model cannot be used; empty when the settings are fine."""
    settings = get_settings()
    problems = []
    if (
        os.environ.get("USE_LIVE_LLM", "").lower() in ("false", "0", "no")
        or not settings.USE_LIVE_LLM
    ):
        problems.append(
            "USE_LIVE_LLM is off: the agents will not call the model. Set USE_LIVE_LLM=true."
        )
    base = str(settings.OPENAI_BASE_URL or "")
    if "localhost" in base or "127.0.0.1" in base:
        if settings.LLM_TIMEOUT_SECONDS < 120:
            problems.append(
                f"LLM_TIMEOUT_SECONDS is {settings.LLM_TIMEOUT_SECONDS:g}: "
                "a local model needs more (try 180)."
            )
        if "/v1" not in base:
            problems.append(
                "OPENAI_BASE_URL must end with /v1 for Ollama (http://localhost:11434/v1)."
            )
    return problems


def run_check(
    project: Path,
    use_case: str | None,
    assets: int,
    paths: int,
    risks: int,
    rationales: int,
) -> dict[str, Any]:
    """Run the three agents once with the model on and return the measurements."""
    meter = Meter()
    _install(meter)
    report: dict[str, Any] = {}

    runs = load_inputs(project, "LIVE")
    run = next((r for r in runs if r.use_case_id == use_case), runs[0])
    run = run.model_copy(update={"assets": list(run.assets)[:assets]})
    report["input"] = {"use_case": run.use_case_id, "assets": [a.asset_id for a in run.assets]}

    # --- Threat Agent
    meter.stage = "threat"
    started = time.perf_counter()
    candidates = fetch_candidates(build_retrieval_plan(run))
    ranked = sorted(build_paths(candidates, run), key=lambda p: -p.chain_confidence)[:paths]
    scenarios, retries, status = generate_and_validate_with_retry(run, paths=ranked)
    threat = meter.summary("threat")
    threat.update(
        {
            "paths": len(ranked),
            "paths_that_fell_back": min(meter.fallback_paths, len(ranked)),
            "scenarios": len(scenarios),
            "passed_checks": sum(1 for s in scenarios if s.validation_status == "passed"),
            "retries": retries,
            "status": status,
            "seconds": round(time.perf_counter() - started, 1),
            "bad_answer_samples": meter.bad_answers[:2],
        }
    )
    threat["model_used"] = len(ranked) - threat["paths_that_fell_back"]
    report["threat"] = threat

    # --- Risk Agent
    meter.stage = "risk"
    ratings = Ratings.load()
    valid = {k: list(v) for k, v in ratings.points.items()}
    by_asset = {a.asset_id: a for a in run.assets}
    assessments = []
    from_model = 0
    for scenario in scenarios[:risks]:
        suggestion = suggester.suggest(scenario, by_asset.get(scenario.asset_id), valid)
        if (suggestion.suggestion_basis or "").startswith("LLM suggestion"):
            from_model += 1
        scored = rengine.score(scenario, suggestion, ratings)
        assessments.append(
            (
                scenario,
                rengine.apply_treatment(
                    scored,
                    TreatmentDecision(
                        treatment=Treatment.REDUCE,
                        rationale="check run",
                        residual_risk=RiskLevel.LOW,
                        residual_reason="check run",
                        approver="live check",
                    ),
                ),
            )
        )
    risk = meter.summary("risk")
    risk.update({"suggestions": len(assessments), "model_used": from_model})
    report["risk"] = risk

    # --- Compliance Agent
    meter.stage = "compliance"
    rules = cengine.Rules.load()
    chunks = explainer.retrieve_standards("Resistant to Moderate attackers AVA_VAN.4")
    made = 0
    attempted = 0
    if chunks:
        for scenario, assessment in assessments[:rationales]:
            attempted += 1
            level = cengine.asset_criticality(by_asset.get(scenario.asset_id), rules)
            record = cengine.propose(assessment, rules, criticality=level)
            if explainer.explain(record, scenario.attack_vector) is not None:
                made += 1
    compliance = meter.summary("compliance")
    compliance.update(
        {
            "rationales_attempted": attempted,
            "model_used": made,
            "standards_text_available": bool(chunks),
        }
    )
    report["compliance"] = compliance
    return report


def verdict(report: dict[str, Any]) -> tuple[int, list[str]]:
    lines = []
    worst = 0
    for name, label in (
        ("threat", "Threat Agent"),
        ("risk", "Risk Agent"),
        ("compliance", "Compliance Agent"),
    ):
        part = report[name]
        if name == "compliance" and not part["standards_text_available"]:
            lines.append(
                f"{label}: NOT TESTED. The database has no standards text; load trc_engine_fullkb."
            )
            worst = max(worst, 2)
        elif part["model_used"] > 0:
            lines.append(f"{label}: OK, the model's answer was used {part['model_used']} time(s).")
        else:
            lines.append(
                f"{label}: FELL BACK every time. The model answered {part['answered']} of "
                f"{part['model_calls']} calls but nothing was usable."
            )
            worst = max(worst, 1)
    return worst, lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default=str(DEFAULT_PROJECT))
    parser.add_argument("--use-case", default="UC-01")
    parser.add_argument("--assets", type=int, default=2, help="assets to analyse (default 2)")
    parser.add_argument("--paths", type=int, default=4, help="attack paths to generate (default 4)")
    parser.add_argument("--risks", type=int, default=3, help="risk suggestions to request")
    parser.add_argument(
        "--rationales", type=int, default=2, help="resistance rationales to request"
    )
    parser.add_argument("--out", default=str(_ROOT / "demo_output" / "live_check"))
    args = parser.parse_args()

    settings = get_settings()
    print(f"Endpoint : {settings.OPENAI_BASE_URL or 'default for the API key'}")
    print(f"Model    : {settings.OPENAI_MODEL}")
    print(f"Timeout  : {settings.LLM_TIMEOUT_SECONDS:g} s per call")
    problems = check_settings()
    for problem in problems:
        print(f"PROBLEM  : {problem}")
    if problems:
        return 2

    started = time.perf_counter()
    try:
        report = run_check(
            Path(args.project), args.use_case, args.assets, args.paths, args.risks, args.rationales
        )
    except Exception as exc:  # report any failure plainly; this is a diagnostic tool
        print(f"CHECK STOPPED: {type(exc).__name__}: {str(exc)[:300]}")
        return 2
    report["total_seconds"] = round(time.perf_counter() - started, 1)

    print()
    print(
        f"{'agent':<12}{'model calls':<13}{'answered':<10}{'model used':<12}"
        f"{'avg s/call':<12}{'max s'}"
    )
    for name in ("threat", "risk", "compliance"):
        p = report[name]
        print(
            f"{name:<12}{p['model_calls']:<13}{p['answered']:<10}{p['model_used']:<12}{p['avg_seconds']!s:<12}{p['max_seconds']}"
        )
    t = report["threat"]
    print(
        f"\nThreat Agent: {t['paths']} paths, {t['paths_that_fell_back']} fell back, "
        f"{t['scenarios']} scenarios, {t['passed_checks']} passed the automatic checks, "
        f"{t['retries']} retries ({t['seconds']} s)"
    )
    for sample in t["bad_answer_samples"]:
        print(f"  unusable answer began: {sample[:120]!r}")
    for name in ("threat", "risk", "compliance"):
        for error in report[name]["errors"]:
            print(f"  {name} error: {error}")

    code, lines = verdict(report)
    print()
    print("\n".join(lines))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nTotal {report['total_seconds']} s. Report: {out / 'report.json'}")
    print(
        "RESULT: "
        + {
            0: "all three agents use the model",
            1: "an agent only fell back",
            2: "setup or environment problem",
        }[code]
    )
    return code


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    finally:
        sys.stdout.flush()
    os._exit(code)
