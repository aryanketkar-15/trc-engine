"""Compliance agent API: /api/v1/compliance-agent/* (attack resistance, expert-confirmed)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError

from agents.compliance_agent import engine
from agents.compliance_agent.engine import (
    ComplianceDecision,
    ComplianceRecord,
    Rules,
    RulesError,
)
from agents.risk_agent.schemas import RiskAssessment
from agents.threat_agent.router import get_state_manager, verify_api_key
from scrp.state_manager import NotApprovedError, StateManager

router = APIRouter(prefix="/compliance-agent", tags=["compliance-agent"])


def get_rules() -> Rules:
    """The rule base in use (overridable in tests)."""
    return Rules.load()


class ConfirmItem(BaseModel):
    tid: str
    decision: ComplianceDecision


class ConfirmRequest(BaseModel):
    items: Annotated[list[ConfirmItem], Field(min_length=1)]


class RejectRequest(BaseModel):
    tid: str
    reason: Annotated[str, Field(min_length=5)]
    approver: Annotated[str, Field(min_length=1)]


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
        "provisional": True,
    }


@router.post("/propose")
def propose_mappings(
    state: Annotated[StateManager, Depends(get_state_manager)],
    rules: Annotated[Rules, Depends(get_rules)],
    include_all: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """Suggested mapping for every approved risk that has none yet (default: Reduce only)."""
    have = state.get_compliance_records()
    proposals = [
        engine.propose(r, rules).model_dump(mode="json")
        for tid, r in _risks(state).items()
        if tid not in have and engine.applies(r, include_all=include_all)
    ]
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
    for item in body.items:
        risk = risks.get(item.tid)
        if risk is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"{item.tid} has no approved risk assessment"
            )
        try:
            records.append(engine.confirm(risk, rules, item.decision))
        except RulesError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    try:
        stored = state.commit_compliance_records([r.model_dump(mode="json") for r in records])
    except NotApprovedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {
        "stored": stored,
        "records": [r.model_dump(mode="json") for r in records],
        "incomplete": [
            r.tid
            for r in records
            if "needs company value" in (r.jil_attack_potential, r.sesip_level, r.cc_eal)
        ],
    }


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
