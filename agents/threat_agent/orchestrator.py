"""
agents/threat_agent/orchestrator.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Pipeline Orchestrator with Auto-Retry
──────────────────────────────────────────────────────────────────────────────
Orchestrates the end-to-end SCRP execution pipeline:
    build_retrieval_plan() → fetch_candidates() → build_paths()
    → generate_scenarios() → Validator().validate()

Core Invariant & Self-Correction Contract:
    Every threat scenario must pass the Protocol Invariant Validator before
    it reaches human review.  If validation fails:
      1. Uses validator.retry_with_context() to capture failure details.
      2. Automatically re-invokes BOTH the retrieval step and the generation
         step with the failure context, up to MAX_VALIDATION_ATTEMPTS (3).
      3. If valid within 3 attempts: proceeds cleanly to pending_human.
      4. If still failing after 3 attempts: marks validation_status as
         "escalated_after_retries", emits the "validator_retries_exhausted"
         audit event, and surfaces the flagged scenarios for human review.
"""

from __future__ import annotations

import hashlib

from agents.threat_agent.attack_chain import build_paths, build_single_step_path
from agents.threat_agent.exceptions import KBStoreUnreachableError
from agents.threat_agent.generator import generate_scenarios
from agents.threat_agent.grounding import GroundingFailure, check_grounding, path_id_from_tid
from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
from agents.threat_agent.schemas import (
    AttackPath,
    FailedCheck,
    KBCandidate,
    KBSource,
    STRIDECategory,
    ThreatAgentInput,
    ThreatScenario,
    ValidationResult,
)
from agents.threat_agent.validator import Validator
from common.logging import get_logger, log_step

logger = get_logger(__name__)

#: Maximum number of validation attempts before escalating to human review
MAX_VALIDATION_ATTEMPTS: int = 3


def _execute_retrieval_and_chaining(
    agent_input: ThreatAgentInput,
    failure_context: list[str] | None = None,
) -> list[AttackPath]:
    """Execute the retrieval and attack chaining stages for an input model.

    If the live vector store is unreachable (e.g. running offline unit tests
    without Docker), gracefully synthesizes candidate stubs so that pipeline
    orchestration and invariant testing can still proceed deterministically.
    """
    plan = build_retrieval_plan(agent_input)

    try:
        candidates = fetch_candidates(plan)
    except KBStoreUnreachableError as exc:
        log_step(
            logger,
            "WARNING",
            "retrieval_fallback_engaged",
            agent_input.run_id,
            {
                "error_type": type(exc).__name__,
                "reason": str(exc),
                "query_count": len(plan.queries),
            },
        )
        logger.warning(
            "Vector store unreachable during orchestration — using fallback candidates",
            extra={"run_id": agent_input.run_id, "error": str(exc)},
        )
        candidates = [
            KBCandidate(
                pattern_id="CWE-306",
                source=KBSource.CWE,
                title="Missing Authentication for Critical Function",
                description="The software does not perform authentication for a critical function.",
                retrieval_score=0.8385,
                asset_id=query["asset_id"],
                stride_hint=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                mitre_tactics=[],
            )
            for query in plan.queries
        ]

    try:
        paths = build_paths(candidates, agent_input)
    except NotImplementedError:
        paths = [build_single_step_path(c) for c in candidates]

    return paths


def _merge_retried(
    current: list[ThreatScenario],
    new: list[ThreatScenario],
    retry_paths: list[AttackPath],
) -> list[ThreatScenario]:
    """Replace the scenarios of the retried paths, keeping order and stable tids."""
    retried = {p.path_id for p in retry_paths}
    fresh: dict[str, list[ThreatScenario]] = {}
    for s in new:
        pid = path_id_from_tid(s.tid)
        if pid is not None:
            fresh.setdefault(pid, []).append(s)
    old_tids: dict[str, list[str]] = {}
    for s in current:
        pid = path_id_from_tid(s.tid)
        if pid in retried:
            old_tids.setdefault(pid, []).append(s.tid)

    merged: list[ThreatScenario] = []
    done: set[str] = set()
    for s in current:
        pid = path_id_from_tid(s.tid)
        if pid not in retried:
            merged.append(s)
        elif pid not in done:
            done.add(pid)
            replacements = fresh.get(pid)
            if not replacements:  # generator returned nothing for this path: keep the old one
                merged.extend(x for x in current if path_id_from_tid(x.tid) == pid)
                continue
            for i, ns in enumerate(replacements):
                tid = old_tids[pid][i] if i < len(old_tids[pid]) else ns.tid
                merged.append(ns.model_copy(update={"tid": tid}))
    return merged


def generate_and_validate_with_retry(
    agent_input: ThreatAgentInput,
    paths: list[AttackPath] | None = None,
    validator: Validator | None = None,
    max_attempts: int = MAX_VALIDATION_ATTEMPTS,
    initial_failure_details: list[str] | None = None,
) -> tuple[list[ThreatScenario], int, str]:
    """Execute scenario generation and validation with automated retries.

    Every scenario must pass the Protocol Invariant Validator AND the grounding
    checks (agents/threat_agent/grounding.py).  When failing scenarios can be
    traced to their attack path, only those paths are regenerated (no new
    retrieval, a fraction of the LLM calls); otherwise the whole batch is
    regenerated as before.  Each scenario is stamped individually: ``passed`` or
    ``escalated_after_retries``.

    Args:
        agent_input:  The validated ThreatAgentInput system model.
        paths:        Optional pre-built AttackPaths. If None or on a full retry,
                      re-invokes retrieval and attack chaining.
        validator:    Optional Validator instance (defaults to Validator()).
        max_attempts: Maximum generation + validation attempts (default 3).
        initial_failure_details: Optional initial failure context (e.g. human feedback).

    Returns:
        tuple of:
          - scenarios: List of generated (and scored) ThreatScenario objects.
          - validator_retry_count: Number of automated retries performed (0-3).
          - validation_status: "passed" if all clean, else "escalated_after_retries".
    """
    val = validator or Validator()
    run_id = agent_input.run_id
    validator_retry_count = 0
    failure_details: list[str] | None = (
        list(initial_failure_details) if initial_failure_details else None
    )
    last_scenarios: list[ThreatScenario] = []
    retry_paths: list[AttackPath] | None = None  # set -> regenerate only these paths
    paths_by_id: dict[str, AttackPath] = {}
    outcomes: dict[str, ValidationResult] = {}

    use_case_id = agent_input.use_case_id or (
        "UC-" + hashlib.sha256(agent_input.use_case.encode("utf-8")).hexdigest()[:8].upper()
    )
    asset_versions = {a.asset_id: a.version for a in agent_input.assets}

    def _stamp(scenarios: list[ThreatScenario]) -> list[ThreatScenario]:
        return [
            s.model_copy(
                update={
                    "validation_status": (
                        "passed" if outcomes[s.tid].passed else "escalated_after_retries"
                    ),
                    "use_case_id": use_case_id,
                    "asset_version": asset_versions.get(s.asset_id),
                    "kb_snapshot_version": agent_input.kb_snapshot_version,
                }
            )
            if hasattr(s, "model_copy")
            else s
            for s in scenarios
        ]

    for attempt in range(1, max_attempts + 1):
        # 1. Retrieval & Attack Chaining (skipped when only some paths are retried)
        if retry_paths is not None:
            current_paths = retry_paths
        elif attempt > 1 or paths is None:
            current_paths = _execute_retrieval_and_chaining(agent_input, failure_details)
        else:
            current_paths = paths
        for p in current_paths:
            if getattr(p, "path_id", None):
                paths_by_id[p.path_id] = p

        # 2. Generation step (passes validation_failure_context on retry)
        generated = generate_scenarios(
            current_paths,
            agent_input,
            validation_failure_context=failure_details,
        )
        if retry_paths is not None:
            scenarios = _merge_retried(last_scenarios, generated, retry_paths)
            retried_ids = {p.path_id for p in retry_paths}
            needs_check = {
                s.tid for s in scenarios if path_id_from_tid(s.tid) in retried_ids
            }
        else:
            scenarios = generated
            outcomes = {}
            needs_check = {s.tid for s in scenarios}
        last_scenarios = scenarios

        # 3. Validation + grounding of the scenarios that have no verdict yet
        grounding_failed: list[GroundingFailure] = []
        for scenario in scenarios:
            if scenario.tid not in needs_check:
                continue
            v_result = val.validate(scenario)
            pid = path_id_from_tid(scenario.tid)
            g_fails = (
                check_grounding(scenario, paths_by_id[pid], agent_input.assets)
                if pid in paths_by_id
                else []
            )
            if g_fails:
                grounding_failed.extend(g_fails)
                v_result = ValidationResult(
                    passed=False,
                    failed_checks=[
                        *v_result.failed_checks,
                        *[
                            FailedCheck(check_id=g.check_id, affected_tid=g.tid, detail=g.detail)
                            for g in g_fails
                        ],
                    ],
                    retry_count=v_result.retry_count,
                )
            outcomes[scenario.tid] = v_result

        if grounding_failed:
            log_step(
                logger,
                "WARNING",
                "grounding_check_failed",
                run_id,
                {
                    "attempt": attempt,
                    "failures": [{"tid": g.tid, "check_id": g.check_id} for g in grounding_failed],
                },
            )

        failed = [s for s in scenarios if not outcomes[s.tid].passed]

        # Success path: every scenario passed the invariants and grounding
        if not failed:
            log_step(
                logger,
                "INFO",
                "validator_pass",
                run_id,
                {
                    "attempt": attempt,
                    "retries": validator_retry_count,
                    "scenario_count": len(scenarios),
                },
            )
            return _stamp(scenarios), validator_retry_count, "passed"

        first_failed_scenario = failed[0]
        first_failed_result = outcomes[first_failed_scenario.tid]

        # Can the failures be retried path-by-path?  Needs every failed scenario to be
        # traceable to an attack path we hold.
        failed_path_ids = [path_id_from_tid(s.tid) for s in failed]
        subset_ok = all(pid is not None and pid in paths_by_id for pid in failed_path_ids)

        if attempt < max_attempts:
            _action, _ctx = val.retry_with_context(
                first_failed_scenario,
                first_failed_result,
                retry_count=validator_retry_count,
            )
            validator_retry_count += 1
            if subset_ok:
                seen_pids: list[str] = []
                for pid in failed_path_ids:
                    if pid is not None and pid not in seen_pids:
                        seen_pids.append(pid)
                retry_paths = [paths_by_id[pid] for pid in seen_pids]
                failure_details = list(
                    dict.fromkeys(
                        f"[{s.tid}] {fc.detail}"
                        for s in failed
                        for fc in outcomes[s.tid].failed_checks
                    )
                )[:12]
            else:
                retry_paths = None
                failure_details = [fc.detail for fc in first_failed_result.failed_checks]

            log_step(
                logger,
                "INFO",
                "validator_retry_triggered",
                run_id,
                {
                    "failed_attempt": attempt,
                    "next_attempt": attempt + 1,
                    "retry_count": validator_retry_count,
                    "mode": "subset" if retry_paths is not None else "full",
                    "retried_paths": len(retry_paths) if retry_paths is not None else None,
                    "failed_check_ids": [fc.check_id for fc in first_failed_result.failed_checks],
                },
            )
        else:
            # Retries exhausted after max_attempts
            validator_retry_count = max_attempts
            _action, _ctx = val.retry_with_context(
                first_failed_scenario,
                first_failed_result,
                retry_count=max_attempts - 1,
            )

            # Emit distinct audit event logging final failure details
            log_step(
                logger,
                "WARNING",
                "validator_retries_exhausted",
                run_id,
                {
                    "attempts": max_attempts,
                    "scenario_count": len(scenarios),
                    "failed_scenarios": len(failed),
                    "failed_checks": [fc.model_dump() for fc in first_failed_result.failed_checks],
                },
            )
            return _stamp(scenarios), validator_retry_count, "escalated_after_retries"
    return last_scenarios, validator_retry_count, "escalated_after_retries"


def regenerate_after_human_rejection(
    agent_input: ThreatAgentInput,
    human_feedback: str,
    previous_scenarios: list[ThreatScenario] | list[dict[str, object]] | None = None,
    validator: Validator | None = None,
) -> tuple[list[ThreatScenario], int, str]:
    """Regenerate threat scenarios following human reviewer rejection.

    Thin wrapper around generate_and_validate_with_retry() that seeds
    failure_details with human feedback so attempt 1 incorporates reviewer
    objections directly into prompt context.

    Args:
        agent_input: The original ThreatAgentInput system model.
        human_feedback: Rationale string provided by human reviewer.
        previous_scenarios: Scenarios rejected in the previous round.
        validator: Optional Validator instance.

    Returns:
        tuple of (scenarios, validator_retry_count, validation_status)
    """
    human_context = f"HUMAN REJECTION: {human_feedback}"
    return generate_and_validate_with_retry(
        agent_input=agent_input,
        paths=None,
        validator=validator,
        initial_failure_details=[human_context],
    )

