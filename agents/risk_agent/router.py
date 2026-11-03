"""Risk Agent API: /api/v1/risk-agent/*

Reads approved threats from the SCRS, suggests ratings, scores by rule, takes the human treatment
decision and stores approved risk assessments (with the approver's name) in the SCRS.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, ValidationError

from agents.risk_agent import engine, report, suggester
from agents.risk_agent.engine import Ratings, RatingsError
from agents.risk_agent.schemas import RiskAssessment, RiskInput, TreatmentDecision
from agents.risk_agent.staleness import check_risk_staleness
from agents.threat_agent.router import get_state_manager
from agents.threat_agent.schemas import AssetModel, ThreatScenario
from common.auth import Principal, decided_by, read_gate, require_approver
from scrp.state_manager import NotApprovedError, StateManager, WouldOverwriteError

router = APIRouter(prefix="/risk-agent", tags=["risk-agent"], dependencies=[Depends(read_gate)])

MAX_RISK_REJECTIONS = 3


def get_ratings() -> Ratings:
    """The rating tables in use (overridable in tests)."""
    return Ratings.load()


class SuggestRequest(BaseModel):
    project_id: str | None = None
    use_case_id: str | None = None
    assets: list[AssetModel] = Field(default_factory=list, description="Optional asset facts.")


class ScoreRequest(BaseModel):
    inputs: Annotated[list[RiskInput], Field(min_length=1)]


class RiskDecision(BaseModel):
    risk_input: RiskInput
    decision: TreatmentDecision


class RejectRequest(BaseModel):
    risk_input: RiskInput
    reason: Annotated[str, Field(min_length=5)]
    approver: Annotated[str, Field(min_length=1)]
    assets: list[AssetModel] = Field(default_factory=list)


class ApproveRequest(BaseModel):
    decisions: Annotated[list[RiskDecision], Field(min_length=1)]
    supersede_reason: str | None = Field(
        default=None, description="Needed to change an already approved risk."
    )


def _approved_threats(
    state: StateManager, project_id: str | None, use_case_id: str | None
) -> dict[str, ThreatScenario]:
    out: dict[str, ThreatScenario] = {}
    for tid, raw in state.get_threat_scenarios().items():
        scenario = ThreatScenario.model_validate(raw)
        if project_id and scenario.project_id not in (None, project_id):
            continue
        if use_case_id and scenario.use_case_id not in (None, use_case_id):
            continue
        out[str(tid)] = scenario
    return out


def _factor_values(ratings: Ratings) -> dict[str, list[str]]:
    return {name: list(table) for name, table in ratings.points.items()}


def _group(assessments: list[RiskAssessment]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for a in assessments:
        grouped.setdefault(a.asset_id, []).append(a.model_dump(mode="json"))
    return grouped


def _score_all(
    inputs: list[RiskInput],
    threats: dict[str, ThreatScenario],
    ratings: Ratings,
) -> list[RiskAssessment]:
    scored: list[RiskAssessment] = []
    for item in inputs:
        threat = threats.get(item.tid)
        if threat is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"{item.tid} is not an approved threat in the SCRS"
            )
        try:
            scored.append(engine.score(threat, item, ratings))
        except RatingsError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return engine.rank_per_asset(scored)


@router.get("/ratings")
def ratings_info(ratings: Annotated[Ratings, Depends(get_ratings)]) -> dict[str, Any]:
    """The rating tables in use."""
    return {
        "ratings_version": ratings.version,
        "impact_aggregation": ratings.aggregation,
        "factor_values": _factor_values(ratings),
        "risk_matrix": ratings.matrix,
    }


@router.post("/suggest")
def suggest_ratings(
    body: Annotated[SuggestRequest, Body()],
    state: Annotated[StateManager, Depends(get_state_manager)],
    ratings: Annotated[Ratings, Depends(get_ratings)],
) -> dict[str, Any]:
    """Suggested ratings for every approved threat (proposals, not decisions)."""
    threats = _approved_threats(state, body.project_id, body.use_case_id)
    assets = {a.asset_id: a for a in body.assets}
    suggestions = [
        suggester.suggest(t, assets.get(t.asset_id), _factor_values(ratings))
        for t in threats.values()
    ]
    return {
        "count": len(suggestions),
        "suggestions": [s.model_dump(mode="json") for s in suggestions],
    }


@router.post("/score")
def preview_score(
    body: Annotated[ScoreRequest, Body()],
    state: Annotated[StateManager, Depends(get_state_manager)],
    ratings: Annotated[Ratings, Depends(get_ratings)],
) -> dict[str, Any]:
    """Compute risk and per-asset ranking for the given ratings. Stores nothing."""
    threats = _approved_threats(state, None, None)
    ranked = _score_all(body.inputs, threats, ratings)
    return {"ratings_version": ratings.version, "by_asset": _group(ranked)}


@router.post("/approve")
def approve_risks(
    body: Annotated[ApproveRequest, Body()],
    principal: Annotated[Principal, Depends(require_approver)],
    state: Annotated[StateManager, Depends(get_state_manager)],
    ratings: Annotated[Ratings, Depends(get_ratings)],
) -> dict[str, Any]:
    """Score, apply the human treatment decision and store the approved risks in the SCRS."""
    threats = _approved_threats(state, None, None)
    ranked = _score_all([d.risk_input for d in body.decisions], threats, ratings)
    decisions = {
        d.risk_input.tid: d.decision.model_copy(
            update={"approver": decided_by(principal, d.decision.approver)}
        )
        for d in body.decisions
    }
    try:
        final = [
            engine.apply_treatment(
                a, decisions[a.tid], rejections=state.risk_rejection_count(a.tid)
            )
            for a in ranked
        ]
    except RatingsError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    try:
        stored = state.commit_risk_assessments(
            [a.model_dump(mode="json") for a in final], supersede_reason=body.supersede_reason
        )
    except NotApprovedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except WouldOverwriteError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "message": f"{exc}. Review the diff and send supersede_reason to accept it.",
                "tid": exc.tid,
                "diff": exc.diff,
            },
        ) from exc
    return {
        "stored": stored,
        "needs_requirement": [a.tid for a in final if engine.requires_requirement(a)],
        "residual": [
            {
                "tid": a.tid,
                "asset_id": a.asset_id,
                "treatment": a.treatment,
                "residual_risk": a.residual_risk,
            }
            for a in final
            if a.treatment is not None and a.treatment.value != "Reduce"
        ],
        "by_asset": _group(final),
    }


@router.post("/reject", dependencies=[Depends(require_approver)])
def reject_suggestion(
    body: Annotated[RejectRequest, Body()],
    state: Annotated[StateManager, Depends(get_state_manager)],
    ratings: Annotated[Ratings, Depends(get_ratings)],
) -> dict[str, Any]:
    """The expert rejects the suggested ratings with a reason; a new suggestion is produced.

    The rejection is audited. After MAX_RISK_REJECTIONS the agent stops suggesting and the expert
    must enter the ratings (``escalated``). Nothing is stored in the risk set by this call.
    """
    threats = _approved_threats(state, None, None)
    threat = threats.get(body.risk_input.tid)
    if threat is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"{body.risk_input.tid} is not an approved threat"
        )
    used = state.log_risk_rejection(threat.tid, threat.run_id, body.reason, body.approver)
    if used >= MAX_RISK_REJECTIONS:
        return {
            "tid": threat.tid,
            "rejections_used": used,
            "escalated": True,
            "message": (
                f"Rejected {used} times: the agent stops suggesting. Enter the ratings yourself "
                "and send them to /approve."
            ),
        }
    assets = {a.asset_id: a for a in body.assets}
    new = suggester.suggest(
        threat,
        assets.get(threat.asset_id),
        _factor_values(ratings),
        feedback=body.reason,
        previous=body.risk_input,
    )
    return {
        "tid": threat.tid,
        "rejections_used": used,
        "escalated": False,
        "suggestion": new.model_dump(mode="json"),
    }


@router.get("/assessments")
def list_assessments(
    state: Annotated[StateManager, Depends(get_state_manager)],
    project_id: Annotated[str | None, Query()] = None,
    use_case_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Approved risk assessments, grouped per asset and ranked."""
    items: list[RiskAssessment] = []
    for raw in state.get_risk_assessments().values():
        try:
            a = RiskAssessment.model_validate(raw)
        except ValidationError:
            continue
        if project_id and a.project_id not in (None, project_id):
            continue
        if use_case_id and a.use_case_id not in (None, use_case_id):
            continue
        items.append(a)
    return {"count": len(items), "by_asset": _group(engine.rank_per_asset(items))}


@router.get("/report", response_model=None)
def tara_report(
    state: Annotated[StateManager, Depends(get_state_manager)],
    project_id: Annotated[str | None, Query()] = None,
    use_case_id: Annotated[str | None, Query()] = None,
    fmt: Annotated[str, Query(alias="format", pattern="^(json|markdown|csv)$")] = "json",
) -> dict[str, Any] | Response:
    """Per-asset TARA report: ranked threats with risk, treatment, residual risk and resistance."""
    data = report.build_report(state, project_id, use_case_id)
    if fmt == "markdown":
        return Response(report.to_markdown(data), media_type="text/markdown")
    if fmt == "csv":
        return Response(report.to_csv(data), media_type="text/csv")
    return data


@router.post("/staleness")
def risk_staleness(
    state: Annotated[StateManager, Depends(get_state_manager)],
    project_id: Annotated[str | None, Query()] = None,
    use_case_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Which stored risks no longer match an approved threat, and which threats have no risk yet."""
    rep = check_risk_staleness(
        state.get_risk_assessments(), state.get_threat_scenarios(), project_id, use_case_id
    )
    return {
        "stale": [{"tid": t, "reason": r} for t, r in rep.stale],
        "fresh": rep.fresh,
        "unscored_threats": rep.unscored,
    }


@router.post("/retire-stale", dependencies=[Depends(require_approver)])
def retire_stale_risks(
    state: Annotated[StateManager, Depends(get_state_manager)],
    project_id: Annotated[str | None, Query()] = None,
    use_case_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Move out-of-date risks to the history so they can be scored again."""
    rep = check_risk_staleness(
        state.get_risk_assessments(), state.get_threat_scenarios(), project_id, use_case_id
    )
    retired = state.retire_risk_assessments(
        [t for t, _ in rep.stale], "; ".join(sorted({r for _, r in rep.stale})) or "stale"
    )
    return {"retired": retired, "tids": [t for t, _ in rep.stale]}
