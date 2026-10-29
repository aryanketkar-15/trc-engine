"""Risk Agent API: /api/v1/risk-agent/*

Reads approved threats from the SCRS, suggests ratings, scores by rule, takes the human treatment
decision and stores approved risk assessments (with the approver's name) in the SCRS.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError

from agents.risk_agent import engine, suggester
from agents.risk_agent.engine import Ratings, RatingsError
from agents.risk_agent.schemas import RiskAssessment, RiskInput, TreatmentDecision
from agents.risk_agent.staleness import check_risk_staleness
from agents.threat_agent.router import get_state_manager, verify_api_key
from agents.threat_agent.schemas import AssetModel, ThreatScenario
from scrp.state_manager import NotApprovedError, StateManager

router = APIRouter(prefix="/risk-agent", tags=["risk-agent"])


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


class ApproveRequest(BaseModel):
    decisions: Annotated[list[RiskDecision], Field(min_length=1)]


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
    """The rating tables in use, with the source of every matrix cell."""
    return {
        "ratings_version": ratings.version,
        "impact_aggregation": ratings.aggregation,
        "factor_values": _factor_values(ratings),
        "risk_matrix": ratings.matrix,
        "provisional": any(
            c["source"] == "provisional" for row in ratings.matrix.values() for c in row.values()
        ),
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


@router.post("/approve", dependencies=[Depends(verify_api_key)])
def approve_risks(
    body: Annotated[ApproveRequest, Body()],
    state: Annotated[StateManager, Depends(get_state_manager)],
    ratings: Annotated[Ratings, Depends(get_ratings)],
) -> dict[str, Any]:
    """Score, apply the human treatment decision and store the approved risks in the SCRS."""
    threats = _approved_threats(state, None, None)
    ranked = _score_all([d.risk_input for d in body.decisions], threats, ratings)
    decisions = {d.risk_input.tid: d.decision for d in body.decisions}
    try:
        final = [engine.apply_treatment(a, decisions[a.tid]) for a in ranked]
    except RatingsError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    try:
        stored = state.commit_risk_assessments([a.model_dump(mode="json") for a in final])
    except NotApprovedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
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


@router.post("/retire-stale", dependencies=[Depends(verify_api_key)])
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
