"""Shared-state API: /api/v1/scrs/* (audit integrity, decision log, trace links, attack chains)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from agents.threat_agent.chains import propose_chains
from agents.threat_agent.router import get_state_manager
from agents.threat_agent.schemas import AssetModel
from common.auth import read_gate
from scrp.state_manager import StateManager
from scrp.trace import build_trace

router = APIRouter(prefix="/scrs", tags=["shared-state"], dependencies=[Depends(read_gate)])


class ChainsRequest(BaseModel):
    assets: list[AssetModel] = Field(
        default_factory=list, description="Asset facts; needed to link threats across assets."
    )


@router.get("/audit/verify")
def verify_audit(state: Annotated[StateManager, Depends(get_state_manager)]) -> dict[str, Any]:
    """Check the hash chain, and that approved content still matches what was approved."""
    return state.verify_integrity()


@router.get("/audit/log")
def decision_log(
    state: Annotated[StateManager, Depends(get_state_manager)],
    tid: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
) -> dict[str, Any]:
    """Who decided what, when and why (newest last)."""
    entries = [e for e in state.get_audit_log() if tid is None or e.tid == tid]
    return {"count": len(entries), "entries": [e.model_dump(mode="json") for e in entries[-limit:]]}


@router.get("/trace")
def trace_matrix(state: Annotated[StateManager, Depends(get_state_manager)]) -> dict[str, Any]:
    """Backward and forward links of every approved threat, and any gaps."""
    return build_trace(state)


@router.get("/trace/{tid}")
def trace_one(
    tid: str, state: Annotated[StateManager, Depends(get_state_manager)]
) -> dict[str, Any]:
    for row in build_trace(state)["links"]:
        if row["tid"] == tid:
            return row
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"{tid} is not an approved threat")


@router.post("/chains")
def attack_chains(
    state: Annotated[StateManager, Depends(get_state_manager)],
    body: Annotated[ChainsRequest | None, Body()] = None,
) -> dict[str, Any]:
    """Multi-step attack chains proposed from approved threats, for an expert to review."""
    threats = [t for t in state.get_threat_scenarios().values() if isinstance(t, dict)]
    chains = propose_chains(threats, (body or ChainsRequest()).assets)
    return {"count": len(chains), "chains": chains}
