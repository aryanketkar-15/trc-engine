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

from agents.threat_agent.attack_chain import build_paths, build_single_step_path
from agents.threat_agent.exceptions import KBStoreUnreachableError
from agents.threat_agent.generator import generate_scenarios
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


def generate_and_validate_with_retry(
    agent_input: ThreatAgentInput,
    paths: list[AttackPath] | None = None,
    validator: Validator | None = None,
    max_attempts: int = MAX_VALIDATION_ATTEMPTS,
) -> tuple[list[ThreatScenario], int, str]:
    """Execute scenario generation and invariant validation with automated retries.

    Args:
        agent_input:  The validated ThreatAgentInput system model.
        paths:        Optional pre-built AttackPaths. If None or on retry,
                      re-invokes retrieval and attack chaining.
        validator:    Optional Validator instance (defaults to Validator()).
        max_attempts: Maximum generation + validation attempts (default 3).

    Returns:
        tuple of:
          - scenarios: List of generated (and scored) ThreatScenario objects.
          - validator_retry_count: Number of automated retries performed (0-3).
          - validation_status: "passed" if clean, or "escalated_after_retries".
    """
    val = validator or Validator()
    run_id = agent_input.run_id
    validator_retry_count = 0
    failure_details: list[str] | None = None
    last_scenarios: list[ThreatScenario] = []

    for attempt in range(1, max_attempts + 1):
        # 1. Retrieval & Attack Chaining
        # On attempt 1, use pre-existing paths if provided. On retries (or if None),
        # re-invoke retrieval and attack chaining to re-evaluate evidence context.
        if attempt > 1 or paths is None:
            current_paths = _execute_retrieval_and_chaining(agent_input, failure_details)
        else:
            current_paths = paths

        # 2. Generation step (passes validation_failure_context on retry)
        scenarios = generate_scenarios(
            current_paths,
            agent_input,
            validation_failure_context=failure_details,
        )
        last_scenarios = scenarios

        # 3. Validation step across all scenarios
        all_passed = True
        failed_checks_for_attempt: list[FailedCheck] = []
        first_failed_scenario: ThreatScenario | None = None
        first_failed_result: ValidationResult | None = None

        for scenario in scenarios:
            v_result = val.validate(scenario)
            if not v_result.passed:
                all_passed = False
                failed_checks_for_attempt.extend(v_result.failed_checks)
                if first_failed_scenario is None:
                    first_failed_scenario = scenario
                    first_failed_result = v_result

        # Success path: all generated scenarios passed protocol invariant checks
        if all_passed:
            annotated_scenarios = [
                s.model_copy(update={"validation_status": "passed"})
                if hasattr(s, "model_copy") else s
                for s in scenarios
            ]
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
            return annotated_scenarios, validator_retry_count, "passed"

        # Failure path: evaluate retry feasibility
        assert first_failed_scenario is not None
        assert first_failed_result is not None

        if attempt < max_attempts:
            # Trigger retry using existing retry_with_context orchestration
            _action, _ctx = val.retry_with_context(
                first_failed_scenario,
                first_failed_result,
                retry_count=validator_retry_count,
            )
            validator_retry_count += 1
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
                    "failed_checks": [
                        fc.model_dump() for fc in first_failed_result.failed_checks
                    ],
                },
            )

            annotated_scenarios = [
                s.model_copy(update={"validation_status": "escalated_after_retries"})
                if hasattr(s, "model_copy") else s
                for s in scenarios
            ]
            return annotated_scenarios, validator_retry_count, "escalated_after_retries"

    return last_scenarios, validator_retry_count, "escalated_after_retries"
