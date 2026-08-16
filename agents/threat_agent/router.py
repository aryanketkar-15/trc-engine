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
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, status
from pydantic import BaseModel, Field

from agents.threat_agent.schemas import (
    ThreatAgentInput,
    ThreatStatus,
    ValidationResult,
)

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
)
async def analyze(
    payload: Annotated[
        ThreatAgentInput,
        Body(description="System model and asset list for threat modelling."),
    ],
) -> AnalyzeResponse:
    """Submit a ThreatAgentInput and start the SCRP threat analysis loop.

    Args:
        payload: Validated ThreatAgentInput from the request body.

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
        # TODO (Week 2): wire actual SCRP pipeline here:
        #   normalized  = perceive(payload)
        #   plan        = plan(normalized)
        #   candidates  = fetch(plan)
        #   paths       = chain(candidates)
        #   scenarios   = observe(paths)
        #   result      = validate(scenarios)
        #   if not result.passed:
        #       raise NotApprovedError(result)
        #   produce(scenarios)

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

    except Exception as exc:  # noqa: BLE001
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
) -> RunStatusResponse:
    """Return the current ThreatStatus for a given run.

    Args:
        run_id: The unique run identifier from the analyze response.

    Returns:
        RunStatusResponse with the current lifecycle state.

    Raises:
        HTTPException 404: If run_id is not found in the SCRS/state store.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Status poll received", extra={"run_id": run_id})

    # TODO (Week 2): look up run state from scrp.state_manager or an
    # in-memory run registry keyed by run_id.
    # Example:
    #   run_state = state_manager.get_run(run_id)
    #   if run_state is None:
    #       raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    #   return RunStatusResponse(run_id=run_id, status=run_state.status)

    return RunStatusResponse(
        run_id=run_id,
        status=ThreatStatus.PENDING_TEST,
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
)
async def approve_run(
    run_id: Annotated[
        str,
        Path(description="The run_id to approve."),
    ],
) -> ApproveResponse:
    """Approve a threat analysis run and write its scenarios to the SCRS.

    Args:
        run_id: The unique run identifier to approve.

    Returns:
        ApproveResponse with status=approved and the SCRS entry ID.

    Raises:
        HTTPException 422: If NotApprovedError is raised by state_manager
            (e.g. validation did not pass — gate not satisfied).
        HTTPException 404: If run_id is not found.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Approval request received", extra={"run_id": run_id})

    try:
        # TODO (Week 2): implement approval flow:
        #   run_state = state_manager.get_run(run_id)
        #   if run_state is None:
        #       raise HTTPException(status_code=404, detail=...)
        #   scrs_result = state_manager.write_threat_scenario(
        #       run_id=run_id,
        #       scenarios=run_state.scenarios,
        #       validation_result=run_state.last_validation,
        #   )  # raises NotApprovedError if gate not satisfied
        #   return ApproveResponse(
        #       run_id=run_id,
        #       status=ThreatStatus.APPROVED,
        #       scrs_entry_id=scrs_result.scrs_entry_id,
        #   )

        return ApproveResponse(
            run_id=run_id,
            status=ThreatStatus.APPROVED,
            scrs_entry_id=None,  # TODO: replace with real SCRS entry ID
        )

    # TODO (TRC-STUB-002): uncomment once Shriraj's branch is merged.
    # except NotApprovedError as exc:
    #     raise _handle_not_approved(exc, run_id=run_id) from exc

    except HTTPException:
        raise

    except Exception as exc:  # noqa: BLE001
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
        "reason.  If retry_count < 3, triggers a new Act+Fetch+Reason cycle "
        "with the rejection reason injected as context.  At retry_count == 3, "
        "escalates to status=rejected (human-flagged failure)."
    ),
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
) -> RejectResponse:
    """Reject a threat analysis run and trigger retry or escalation.

    Args:
        run_id: The unique run identifier to reject.
        body: RejectRequest containing the human reviewer's reason.

    Returns:
        RejectResponse with updated status and retry_count.

    Raises:
        HTTPException 404: If run_id is not found.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info(
        "Rejection request received",
        extra={"run_id": run_id, "reason": body.reason},
    )

    # TODO (Week 2): implement rejection + retry flow:
    #   run_state = state_manager.get_run(run_id)
    #   if run_state is None:
    #       raise HTTPException(status_code=404, detail=...)
    #   new_retry_count = run_state.last_validation.retry_count + 1
    #   if new_retry_count >= 3:
    #       # Escalate — do not invoke LLM again
    #       new_status = ThreatStatus.REJECTED
    #   else:
    #       # Re-invoke Act+Fetch with rejection reason as context
    #       new_status = ThreatStatus.PENDING_TEST
    #   return RejectResponse(
    #       run_id=run_id, status=new_status, retry_count=new_retry_count
    #   )

    return RejectResponse(
        run_id=run_id,
        status=ThreatStatus.PENDING_TEST,
        retry_count=0,  # TODO: replace with real retry_count from state
    )


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
) -> list[dict[str, object]]:
    """Retrieve the threat scenario list for a given run.

    Args:
        run_id: The unique run identifier.

    Returns:
        List of serialised ThreatScenario dicts (pending human review).

    Raises:
        HTTPException 404: If run_id not found or run is still pending_test.
        HTTPException 500: On unexpected internal errors.
    """
    logger.info("Scenarios fetch received", extra={"run_id": run_id})

    # TODO (Week 2): fetch from state:
    #   run_state = state_manager.get_run(run_id)
    #   if run_state is None:
    #       raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    #   if run_state.status == ThreatStatus.PENDING_TEST:
    #       raise HTTPException(
    #           status_code=404,
    #           detail=(
    #               f"Run '{run_id}' is still in pending_test "
    #               "— no scenarios ready."
    #           ),
    #       )
    #   return [s.model_dump() for s in run_state.scenarios]

    return []  # TODO: replace with real scenario list
