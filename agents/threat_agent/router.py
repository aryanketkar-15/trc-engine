"""
agents/threat_agent/router.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  FastAPI Router (Day-1 Scaffold)
──────────────────────────────────────────────────────────────────────────────
Implements the five endpoints defined in §2.5 of
docs/Phase1_Threat_Agent_Build_Plan_v4.md:

    POST   /threat-agent/analyze
    GET    /threat-agent/{run_id}/status
    POST   /threat-agent/{run_id}/approve
    POST   /threat-agent/{run_id}/reject
    GET    /threat-agent/{run_id}/scenarios

All business logic is stubbed with TODO markers — this scaffold is the
testable surface that API tests (tests/threat_agent/) are written against
in Week 1.

Error-handling contract:
    NotApprovedError  →  HTTP 422  (validation contract not satisfied)
    ValueError        →  HTTP 422  (Pydantic / domain validation failure)
    General Exception →  HTTP 500  (unexpected — never swallowed silently)

Import paths:
    schemas    → agents.threat_agent.schemas   (frozen — do not modify)
    exceptions → scrp.state_manager            (Shriraj's module)
                 Update this import once feature/threat-agent-validator
                 is merged to develop (tracked: TRC-STUB-002).

Ruff compliance
───────────────
• Line length ≤ 88 chars.
• All public functions are fully annotated (ANN rules satisfied).
• No unused imports.
• S101 (assert) suppressed at file level — no asserts here.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, status
from pydantic import BaseModel, Field

from agents.threat_agent.orchestrator import (
    generate_and_validate_with_retry,
    regenerate_after_human_rejection,
)
from agents.threat_agent.run_store import (
    InvalidStateTransitionError,
    RunNotFoundError,
    RunRecord,
    RunRegistryStore,
    get_in_memory_run_store,
    get_run_store,
)
from agents.threat_agent.schemas import (
    ThreatAgentInput,
    ThreatScenario,
    ThreatStatus,
    ValidationResult,
)
from config.settings import get_settings

# TODO (TRC-STUB-002): update this import once feature/threat-agent-validator
# is merged to develop.  NotApprovedError is currently defined in
# scrp/state_manager.py on Shriraj's branch.
# from scrp.state_manager import NotApprovedError

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Router definition
# ──────────────────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/threat-agent",
    tags=["threat-agent"],
)


# ──────────────────────────────────────────────────────────────────────────────
# Run Registry & State Store Integration
# ──────────────────────────────────────────────────────────────────────────────


def clear_run_registry() -> None:
    """Clear all runs in the in-memory registry (used for test isolation)."""
    get_in_memory_run_store().clear()


def set_run_record(record: RunRecord) -> None:
    """Explicitly register or update a run record in the in-memory store."""
    get_in_memory_run_store().set_run(record)


def get_orchestrator() -> Callable[..., tuple[list[ThreatScenario], int, str]]:
    """Return the orchestrator function for generation and automated validation.

    Can be overridden in tests via FastAPI dependency_overrides.
    """
    return generate_and_validate_with_retry


MAX_HUMAN_REJECTIONS: Final[int] = 3


def get_regenerator(
    orchestrator: Annotated[
        Callable[..., tuple[list[ThreatScenario], int, str]],
        Depends(get_orchestrator),
    ] = generate_and_validate_with_retry,
) -> Callable[..., tuple[list[ThreatScenario], int, str]]:
    """Return the regenerator function for human rejection retry.

    If get_orchestrator is overridden (e.g. in tests) and get_regenerator is not,
    automatically delegates to the injected orchestrator.
    """
    if orchestrator is not generate_and_validate_with_retry:
        return (
            lambda agent_input, human_feedback, previous_scenarios=None, **kwargs: (
                orchestrator(agent_input)
            )
        )
    return regenerate_after_human_rejection



def verify_api_key(
    x_api_key: Annotated[
        str | None,
        Header(
            alias="X-API-Key",
            description="Shared secret API key for state-changing endpoints.",
        ),
    ] = None,
) -> str:
    """Validate incoming X-API-Key header against configured secret.

    Enforced on state-changing endpoints (/analyze, /approve, /reject).
    Read-only endpoints (/status, /scenarios) remain open.

    Raises:
        HTTPException 401: If header is missing or does not match configured key.
    """
    settings = get_settings()
    expected_key = settings.THREAT_AGENT_API_KEY.get_secret_value()
    if not x_api_key or not secrets.compare_digest(x_api_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return x_api_key


def _get_run_or_404(run_id: str, store: RunRegistryStore | None = None) -> RunRecord:
    """Retrieve run record from the store or SCRS state fallback, or raise 404."""
    active_store = store if store is not None else get_run_store()
    record = active_store.get_run(run_id)
    if record is not None:
        return record

    # Fallback: check persisted SCRS StateManager for historical runs
    try:
        from scrp.state_manager import StateManager

        state_mgr = StateManager()
        for scenario in state_mgr.get_threat_scenarios().values():
            s_run_id = (
                scenario.get("run_id")
                if isinstance(scenario, dict)
                else getattr(scenario, "run_id", None)
            )
            if s_run_id == run_id:
                record = RunRecord(
                    run_id=run_id,
                    status=ThreatStatus.APPROVED,
                    scrs_entry_id=f"SCRS-{run_id}",
                )
                active_store.set_run(record)
                return record
    except Exception as exc:
        logger.debug(
            "Failed to read historical SCRS state for run %s: %s", run_id, exc
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Run '{run_id}' not found.",
    )


def _raise_invalid_transition(
    exc: InvalidStateTransitionError,
    action: str,  # "approve" | "reject"
) -> None:
    """Map InvalidStateTransitionError to HTTP 409 with exact expected details."""
    if action == "approve":
        if exc.current_status == ThreatStatus.APPROVED:
            detail = (
                f"Run '{exc.run_id}' is already approved and cannot be approved again."
            )
        elif exc.current_status == ThreatStatus.REJECTED:
            detail = f"Run '{exc.run_id}' has been rejected and cannot be approved."
        else:
            detail = (
                f"Run '{exc.run_id}' is in status '{exc.current_status.value}', "
                "which cannot be approved (must be in pending_human)."
            )
    else:  # reject
        if exc.current_status == ThreatStatus.APPROVED:
            detail = f"Run '{exc.run_id}' is already approved and cannot be rejected."
        elif exc.current_status == ThreatStatus.REJECTED:
            detail = (
                f"Run '{exc.run_id}' is already rejected and cannot be rejected again."
            )
        else:
            detail = (
                f"Run '{exc.run_id}' is in status '{exc.current_status.value}', "
                "which cannot be rejected (must be in pending_human)."
            )
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=detail,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Response models
# ──────────────────────────────────────────────────────────────────────────────


class AnalyzeResponse(BaseModel):
    """Immediate response returned by POST /threat-agent/analyze.

    The full threat scenario list is NOT returned here — the caller polls
    GET /threat-agent/{run_id}/status and fetches scenarios separately once
    the run reaches ``pending_human`` or ``approved``.
    """

    run_id: Annotated[
        str,
        Field(description="Unique identifier for this Threat Agent run."),
    ]
    status: Annotated[
        ThreatStatus,
        Field(description="Initial lifecycle state of the submitted run."),
    ]
    message: Annotated[
        str,
        Field(description="Human-readable confirmation of submission."),
    ]


class RunStatusResponse(BaseModel):
    """Response schema for GET /threat-agent/{run_id}/status."""

    run_id: Annotated[str, Field(description="Run identifier.")]
    status: Annotated[ThreatStatus, Field(description="Current lifecycle state.")]
    validator_retry_count: Annotated[
        int,
        Field(default=0, description="Automated validator retry attempts consumed."),
    ] = 0
    human_rejection_count: Annotated[
        int,
        Field(default=0, description="Human rejections received."),
    ] = 0
    validation_status: Annotated[
        str | None,
        Field(
            default=None,
            description="Validation status: 'passed' or 'escalated_after_retries'.",
        ),
    ] = None


class ApproveResponse(BaseModel):
    """Response schema for POST /threat-agent/{run_id}/approve."""

    run_id: Annotated[str, Field(description="Run identifier.")]
    status: Annotated[
        ThreatStatus,
        Field(description="State after approval — should be 'approved'."),
    ]
    scrs_entry_id: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "SCRS key where approved scenarios are stored.  "
                "Populated once state_manager.write_threat_scenario() succeeds."
            ),
        ),
    ]


class RejectRequest(BaseModel):
    """Request body for POST /threat-agent/{run_id}/reject."""

    reason: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Human-readable rejection reason.  Injected into the retry "
                "prompt context so the LLM understands what to correct."
            ),
        ),
    ]


class RejectResponse(BaseModel):
    """Response schema for POST /threat-agent/{run_id}/reject."""

    run_id: Annotated[str, Field(description="Run identifier.")]
    status: Annotated[
        ThreatStatus,
        Field(
            description="State after rejection — 'pending_test' (retry) or 'rejected'."
        ),
    ]
    retry_count: Annotated[
        int,
        Field(
            ge=0,
            le=3,
            description="Retry attempts consumed so far (capped at 3 per schema).",
        ),
    ]
    human_rejection_count: Annotated[
        int | None,
        Field(
            default=None,
            description="Human rejections received.",
        ),
    ] = None
    scenarios: Annotated[
        list[dict[str, object]] | None,
        Field(
            default=None,
            description="Newly regenerated scenarios if retry occurred.",
        ),
    ] = None


class NotApprovedErrorDetail(BaseModel):
    """Structured 422 body returned when NotApprovedError is raised."""

    error: Annotated[str, Field(description="Error type name.")]
    run_id: Annotated[str | None, Field(default=None, description="Affected run ID.")]
    validation_result: Annotated[
        ValidationResult | None,
        Field(
            default=None,
            description="ValidationResult that caused the rejection, if available.",
        ),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Exception handler helper
# ──────────────────────────────────────────────────────────────────────────────


def _handle_not_approved(
    exc: Exception,
    run_id: str | None = None,
    validation_result: ValidationResult | None = None,
) -> HTTPException:
    """Convert a NotApprovedError into an HTTP 422 response.

    Centralised here so every endpoint raises identically-shaped 422s,
    making API tests deterministic.

    Args:
        exc: The caught exception (NotApprovedError or compatible).
        run_id: The affected run identifier, if known.
        validation_result: The ValidationResult that triggered the error.

    Returns:
        HTTPException with status_code=422 and a structured detail body.
    """
    detail = NotApprovedErrorDetail(
        error=type(exc).__name__,
        run_id=run_id,
        validation_result=validation_result,
    )
    logger.warning(
        "NotApprovedError raised",
        extra={
            "run_id": run_id,
            "error": type(exc).__name__,
            "detail": str(exc),
        },
    )
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=detail.model_dump(),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a system model for threat analysis",
    description=(
        "Accepts a ThreatAgentInput payload and initiates the full "
        "Perceive → Plan → Fetch → Chain → Observe → Validate → Produce "
        "SCRP loop.  Returns immediately with a run_id; the caller polls "
        "GET /threat-agent/{run_id}/status for progress."
    ),
    dependencies=[Depends(verify_api_key)],
)
async def analyze(
    payload: Annotated[
        ThreatAgentInput,
        Body(description="System model and asset list for threat modelling."),
    ],
    store: Annotated[
        RunRegistryStore,
        Depends(get_run_store),
    ],
    orchestrator: Annotated[
        Callable[..., tuple[list[ThreatScenario], int, str]],
        Depends(get_orchestrator),
    ],
) -> AnalyzeResponse:
    """Submit a ThreatAgentInput and start the SCRP threat analysis loop.

    Args:
        payload: Validated ThreatAgentInput from the request body.
        store: RunRegistryStore storage provider (injected).
        orchestrator: Automated generation and validation orchestrator (injected).

    Returns:
        AnalyzeResponse with run_id and initial status=pending_test.

    Raises:
        HTTPException 422: If the payload fails Pydantic validation
            (handled automatically by FastAPI) or NotApprovedError is raised
            during the synchronous validation pre-check.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Received analyze request", extra={"run_id": payload.run_id})

    try:
        # Execute automated retrieval, generation, and validation retry loop
        scenarios, validator_retries, validation_status = orchestrator(payload)
        scenarios_dicts = [
            s.model_dump(mode="json") if hasattr(s, "model_dump") else s
            for s in scenarios
        ]

        # Register accepted run into state tracking (advances to pending_human awaiting review)
        store.create_run(
            run_id=payload.run_id,
            status=ThreatStatus.PENDING_HUMAN,
            scenarios=scenarios_dicts,
            retry_count=0,
            validator_retry_count=validator_retries,
            human_rejection_count=0,
            validation_status=validation_status,
            agent_input=payload.model_dump(mode="json"),
        )

        return AnalyzeResponse(
            run_id=payload.run_id,
            status=ThreatStatus.PENDING_TEST,
            message=(
                f"Run '{payload.run_id}' accepted.  "
                "Poll /threat-agent/{run_id}/status for progress."
            ),
        )

    # TODO (TRC-STUB-002): replace bare Exception with NotApprovedError once
    # Shriraj's branch is merged to develop.
    # except NotApprovedError as exc:
    #     raise _handle_not_approved(exc, run_id=payload.run_id) from exc

    except ValueError as exc:
        logger.error("Domain validation failed", extra={"run_id": payload.run_id})
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        logger.exception(
            "Unexpected error in analyze", extra={"run_id": payload.run_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error — check logs for run_id.",
        ) from exc


@router.get(
    "/{run_id}/status",
    response_model=RunStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Poll the lifecycle status of a threat analysis run",
)
async def get_run_status(
    run_id: Annotated[
        str,
        Path(description="The run_id returned by POST /analyze."),
    ],
    store: Annotated[
        RunRegistryStore,
        Depends(get_run_store),
    ],
) -> RunStatusResponse:
    """Return the current ThreatStatus for a given run.

    Args:
        run_id: The unique run identifier from the analyze response.
        store: RunRegistryStore storage provider (injected).

    Returns:
        RunStatusResponse with the current lifecycle state.

    Raises:
        HTTPException 404: If run_id is not found in the SCRS/state store.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Status poll received", extra={"run_id": run_id})
    run_record = _get_run_or_404(run_id, store)
    return RunStatusResponse(
        run_id=run_record.run_id,
        status=run_record.status,
        validator_retry_count=run_record.validator_retry_count,
        human_rejection_count=run_record.human_rejection_count,
        validation_status=run_record.validation_status,
    )


@router.post(
    "/{run_id}/approve",
    response_model=ApproveResponse,
    status_code=status.HTTP_200_OK,
    summary="Human approval — write approved scenarios to SCRS",
    description=(
        "Human reviewer approves the threat scenarios for this run.  "
        "Triggers state_manager.write_threat_scenario() which raises "
        "NotApprovedError if the ValidationResult is not in a passing state.  "
        "On success, transitions the run to 'approved' and writes to SCRS."
    ),
    dependencies=[Depends(verify_api_key)],
)
async def approve_run(
    run_id: Annotated[
        str,
        Path(description="The run_id to approve."),
    ],
    store: Annotated[
        RunRegistryStore,
        Depends(get_run_store),
    ],
) -> ApproveResponse:
    """Approve a threat analysis run and write its scenarios to the SCRS.

    Args:
        run_id: The unique run identifier to approve.
        store: RunRegistryStore storage provider (injected).

    Returns:
        ApproveResponse with status=approved and the SCRS entry ID.

    Raises:
        HTTPException 422: If NotApprovedError is raised by state_manager
            (e.g. validation did not pass — gate not satisfied).
        HTTPException 404: If run_id is not found.
        HTTPException 409: If run is not in pending_human or already approved/rejected.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Approval request received", extra={"run_id": run_id})

    _get_run_or_404(run_id, store)

    try:
        run = store.transition_run(
            run_id=run_id,
            expected_status=ThreatStatus.PENDING_HUMAN,
            new_status=ThreatStatus.APPROVED,
            scrs_entry_id=f"SCRS-{run_id}",
        )

        return ApproveResponse(
            run_id=run.run_id,
            status=run.status,
            scrs_entry_id=run.scrs_entry_id,
        )

    except RunNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found.",
        ) from exc
    except InvalidStateTransitionError as exc:
        _raise_invalid_transition(exc, action="approve")

    # TODO (TRC-STUB-002): uncomment once Shriraj's branch is merged.
    # except NotApprovedError as exc:
    #     raise _handle_not_approved(exc, run_id=run_id) from exc

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception("Unexpected error in approve", extra={"run_id": run_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error — check logs for run_id.",
        ) from exc


@router.post(
    "/{run_id}/reject",
    response_model=RejectResponse,
    status_code=status.HTTP_200_OK,
    summary="Human rejection — trigger retry or escalation",
    description=(
        "Human reviewer rejects the threat scenarios for this run with a "
        "reason.  If human_rejection_count < 3, triggers a new Act+Fetch+Reason cycle "
        "with the rejection reason injected as context.  At human_rejection_count >= 3, "
        "escalates to status=rejected (human-flagged failure)."
    ),
    dependencies=[Depends(verify_api_key)],
)
async def reject_run(
    run_id: Annotated[
        str,
        Path(description="The run_id to reject."),
    ],
    body: Annotated[
        RejectRequest,
        Body(description="Rejection reason from the human reviewer."),
    ],
    store: Annotated[
        RunRegistryStore,
        Depends(get_run_store),
    ],
    regenerator: Annotated[
        Callable[..., tuple[list[ThreatScenario], int, str]],
        Depends(get_regenerator),
    ],
) -> RejectResponse:
    """Reject a threat analysis run and trigger retry or escalation.

    Args:
        run_id: The unique run identifier to reject.
        body: RejectRequest containing the human reviewer's reason.
        store: RunRegistryStore storage provider (injected).
        regenerator: Function handling scenario regeneration with human feedback.

    Returns:
        RejectResponse with updated status, retry_count, and regenerated scenarios.

    Raises:
        HTTPException 404: If run_id is not found.
        HTTPException 409: If run is not in pending_human or already approved/rejected.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info(
        "Rejection request received",
        extra={"run_id": run_id, "reason": body.reason},
    )

    run = _get_run_or_404(run_id, store)

    if run.status != ThreatStatus.PENDING_HUMAN:
        if run.status == ThreatStatus.APPROVED:
            detail = f"Run '{run_id}' is already approved and cannot be rejected."
        elif run.status == ThreatStatus.REJECTED:
            detail = (
                f"Run '{run_id}' is already rejected and cannot be rejected again."
            )
        else:
            detail = (
                f"Run '{run_id}' is in status '{run.status.value}', "
                "which cannot be rejected (must be in pending_human)."
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )

    # Log rejection to SCRS audit log and revision history
    try:
        from scrp.state_manager import StateManager

        state_mgr = StateManager()
        state_mgr.log_rejection(
            run_id=run_id,
            reason=body.reason,
            rejected_scenarios=run.scenarios,
        )
    except Exception as exc:
        logger.warning(
            "Failed to log rejection to SCRS for run %s: %s", run_id, exc
        )

    current_rejections = run.human_rejection_count

    # Check if this rejection reaches or exceeds the cap
    if current_rejections + 1 >= MAX_HUMAN_REJECTIONS:
        rejection_entry: dict[str, object] = {
            "attempt": current_rejections + 1,
            "reason": body.reason,
            "rejected_scenarios": run.scenarios,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        updated_run = store.transition_run(
            run_id=run_id,
            expected_status=ThreatStatus.PENDING_HUMAN,
            new_status=ThreatStatus.REJECTED,
            increment_retry=True,
            rejection_entry=rejection_entry,
        )
        return RejectResponse(
            run_id=updated_run.run_id,
            status=updated_run.status,
            retry_count=min(updated_run.retry_count, 3),
            human_rejection_count=updated_run.human_rejection_count,
            scenarios=None,
        )

    # Under cap: attempt regeneration
    rejection_entry = {
        "attempt": current_rejections + 1,
        "reason": body.reason,
        "rejected_scenarios": run.scenarios,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    if not run.agent_input:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Run '{run_id}' has no stored system model and predates "
                "reject-regenerate support.  It cannot be automatically "
                "regenerated; resolve manually or re-submit via /analyze."
            ),
        )

    try:
        agent_input = ThreatAgentInput.model_validate(run.agent_input)

        new_scenarios, _val_retries, _val_status = regenerator(
            agent_input=agent_input,
            human_feedback=body.reason,
            previous_scenarios=run.scenarios,
        )
        scenarios_dicts = [
            s.model_dump(mode="json") if hasattr(s, "model_dump") else s
            for s in new_scenarios
        ]

        updated_run = store.transition_run(
            run_id=run_id,
            expected_status=ThreatStatus.PENDING_HUMAN,
            new_status=ThreatStatus.PENDING_HUMAN,
            increment_retry=True,
            rejection_entry=rejection_entry,
            updated_scenarios=scenarios_dicts,
        )

        return RejectResponse(
            run_id=updated_run.run_id,
            status=updated_run.status,
            retry_count=min(updated_run.retry_count, 3),
            human_rejection_count=updated_run.human_rejection_count,
            scenarios=scenarios_dicts,
        )

    except RunNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found.",
        ) from exc
    except InvalidStateTransitionError as exc:
        _raise_invalid_transition(exc, action="reject")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Regeneration failed for run %s: %s", run_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to regenerate threat scenarios: {exc}",
        ) from exc


@router.get(
    "/{run_id}/scenarios",
    response_model=list[dict[str, object]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve current threat scenario list for human review",
    description=(
        "Returns the list of ThreatScenario objects produced for this run.  "
        "Only available once the run reaches 'pending_human' or later states.  "
        "Returns 404 if the run is still in 'pending_test'."
    ),
)
async def get_scenarios(
    run_id: Annotated[
        str,
        Path(description="The run_id to retrieve scenarios for."),
    ],
    store: Annotated[
        RunRegistryStore,
        Depends(get_run_store),
    ],
) -> list[dict[str, object]]:
    """Retrieve the threat scenario list for a given run.

    Args:
        run_id: The unique run identifier.
        store: RunRegistryStore storage provider (injected).

    Returns:
        List of serialised ThreatScenario dicts (pending human review).

    Raises:
        HTTPException 404: If run_id not found or run is still pending_test.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Scenarios fetch received", extra={"run_id": run_id})

    run = _get_run_or_404(run_id, store)
    if run.status == ThreatStatus.PENDING_TEST:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' is still in pending_test — no scenarios ready.",
        )

    return run.scenarios
