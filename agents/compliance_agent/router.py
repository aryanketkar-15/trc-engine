"""Compliance agent API: /api/v1/compliance-agent/* (attack resistance, expert-confirmed)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError

from agents.compliance_agent import engine, explainer
from agents.compliance_agent.engine import (
    ComplianceDecision,
    ComplianceRecord,
    Rules,
    RulesError,
)
from agents.compliance_agent.explainer import AiRationale
from agents.risk_agent.schemas import RiskAssessment
from agents.threat_agent.router import get_state_manager, verify_api_key
from agents.threat_agent.schemas import AssetModel
from scrp.state_manager import NotApprovedError, StateManager

router = APIRouter(prefix="/compliance-agent", tags=["compliance-agent"])


def get_rules() -> Rules:
    """The rule base in use (overridable in tests)."""
    return Rules.load()


class ProposeRequest(BaseModel):
    assets: list[AssetModel] = Field(
        default_factory=list, description="Asset facts; they set the asset criticality."
    )
    explain: bool = Field(default=False, description="Also ask the LLM for a written rationale.")


class ConfirmItem(BaseModel):
    tid: str
    decision: ComplianceDecision
    ai: AiRationale | None = Field(
        default=None, description="The rationale the expert saw in /propose, kept with the record."
    )


class ConfirmRequest(BaseModel):
    items: Annotated[list[ConfirmItem], Field(min_length=1)]
    assets: list[AssetModel] = Field(default_factory=list)


class RejectRequest(BaseModel):
    tid: str
    reason: Annotated[str, Field(min_length=5)]
    approver: Annotated[str, Field(min_length=1)]


def _criticality(assets: list[AssetModel], asset_id: str, rules: Rules) -> str:
    match = next((a for a in assets if a.asset_id == asset_id), None)
    return engine.asset_criticality(match, rules)


def _threat_text(state: StateManager, tid: str) -> str:
    threat = state.get_threat_scenarios().get(tid)
    return str(threat.get("attack_vector", "")) if isinstance(threat, dict) else ""


def _risks(state: StateManager) -> dict[str, RiskAssessment]:
    out: dict[str, RiskAssessment] = {}
    for tid, raw in state.get_risk_assessments().items():
        try:
            out[str(tid)] = RiskAssessment.model_validate(raw)
        except ValidationError:
            continue
    return out


@router.get("/rules")
def rules_info(rules: Annotated[Rules, Depends(get_rules)]) -> dict[str, Any]:
    return {
        "rules_version": rules.version,
        "attacker_classes": rules.classes,
        "class_table": rules.table,
        "risk_to_class": list(rules.risk_to_class.values()),
        "feasibility_floor": rules.floors,
        "criticality_floor": rules.criticality_floors,
        "citations": rules.citations,
    }


@router.post("/propose")
def propose_mappings(
    state: Annotated[StateManager, Depends(get_state_manager)],
    rules: Annotated[Rules, Depends(get_rules)],
    include_all: Annotated[bool, Query()] = False,
    body: Annotated[ProposeRequest | None, Body()] = None,
) -> dict[str, Any]:
    """Suggested mapping for every approved risk that has none yet (default: Reduce only)."""
    request = body or ProposeRequest()
    have = state.get_compliance_records()
    proposals = []
    for tid, risk in _risks(state).items():
        if tid in have or not engine.applies(risk, include_all=include_all):
            continue
        criticality = _criticality(request.assets, risk.asset_id, rules)
        record = engine.propose(risk, rules, criticality=criticality)
        if request.explain:
            ai = explainer.explain(record, _threat_text(state, tid))
            record = explainer.attach(record, ai)
        proposals.append(record.model_dump(mode="json"))
    return {"count": len(proposals), "proposals": proposals}


@router.post("/confirm", dependencies=[Depends(verify_api_key)])
def confirm_mappings(
    body: Annotated[ConfirmRequest, Body()],
    state: Annotated[StateManager, Depends(get_state_manager)],
    rules: Annotated[Rules, Depends(get_rules)],
) -> dict[str, Any]:
    """The expert confirms (or overrides, with a reason) the mapping; confirmed ones are stored."""
    risks = _risks(state)
    records: list[ComplianceRecord] = []
    dropped: list[str] = []
    for item in body.items:
        risk = risks.get(item.tid)
        if risk is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"{item.tid} has no approved risk assessment"
            )
        criticality = _criticality(body.assets, risk.asset_id, rules)
        try:
            record = engine.confirm(risk, rules, item.decision, criticality=criticality)
        except RulesError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        final = explainer.attach(record, item.ai)
        if item.ai is not None and final.ai_rationale is None:
            dropped.append(item.tid)
        records.append(final)
    try:
        stored = state.commit_compliance_records([r.model_dump(mode="json") for r in records])
    except NotApprovedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {
        "stored": stored,
        "records": [r.model_dump(mode="json") for r in records],
        "rationale_dropped": dropped,
    }


@router.get("/targets")
def protection_targets(
    state: Annotated[StateManager, Depends(get_state_manager)],
    rules: Annotated[Rules, Depends(get_rules)],
) -> dict[str, Any]:
    """Required protection level per asset and for the product, from the confirmed records."""
    return engine.protection_targets(engine.load_records(state.get_compliance_records()), rules)


@router.post("/reject", dependencies=[Depends(verify_api_key)])
def reject_mapping(
    body: Annotated[RejectRequest, Body()],
    state: Annotated[StateManager, Depends(get_state_manager)],
) -> dict[str, Any]:
    """The expert rejects a proposed mapping with a reason. Audited; nothing is stored."""
    risk = _risks(state).get(body.tid)
    if risk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{body.tid} has no approved risk")
    state.log_compliance_rejection(body.tid, risk.run_id or "unknown", body.reason, body.approver)
    return {"tid": body.tid, "rejected": True, "next": "choose an attacker class via /confirm"}


@router.get("/records")
def list_records(
    state: Annotated[StateManager, Depends(get_state_manager)],
    project_id: Annotated[str | None, Query()] = None,
    use_case_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    items = []
    for raw in state.get_compliance_records().values():
        try:
            rec = ComplianceRecord.model_validate(raw)
        except ValidationError:
            continue
        if project_id and rec.project_id not in (None, project_id):
            continue
        if use_case_id and rec.use_case_id not in (None, use_case_id):
            continue
        items.append(rec.model_dump(mode="json"))
    return {"count": len(items), "records": items}


@router.post("/staleness")
def compliance_staleness(
    state: Annotated[StateManager, Depends(get_state_manager)],
) -> dict[str, Any]:
    stale, unmapped = engine.check_compliance_staleness(
        state.get_compliance_records(), state.get_risk_assessments()
    )
    return {"stale": [{"tid": t, "reason": r} for t, r in stale], "unmapped_risks": unmapped}


@router.post("/retire-stale", dependencies=[Depends(verify_api_key)])
def retire_stale(
    state: Annotated[StateManager, Depends(get_state_manager)],
) -> dict[str, Any]:
    stale, _ = engine.check_compliance_staleness(
        state.get_compliance_records(), state.get_risk_assessments()
    )
    retired = state.retire_compliance_records(
        [t for t, _ in stale], "; ".join(sorted({r for _, r in stale})) or "stale"
    )
    return {"retired": retired, "tids": [t for t, _ in stale]}
