"""
scrp/schemas.py
───────────────
Shared Cybersecurity Reasoning State (SCRS) schemas.

These models define the on-disk / in-memory representation of the SCRS
that *all* agents read from and write to.  Only the models each agent
directly depends on live here; agent-internal shapes stay in each agent's
own schemas.py.

Phase 1 adds: ThreatScenarioRecord (the SCRS representation of an approved
              threat scenario) and AuditLogEntry.
Phase 2+ will add: RiskRecord, ComplianceRecord, etc.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    """
    Immutable record of a write action into the SCRS.

    WHY THIS EXISTS:
    Every write to the SCRS must be auditable.  Capturing run_id, tid,
    timestamp, and action gives reviewers a queryable history of what was
    written, when, and by which pipeline run — without relying on external
    logging infrastructure being available.
    """

    run_id: str = Field(..., description="Unique identifier for the pipeline run.")
    tid: str = Field(..., description="Threat ID that was acted upon.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the write action.",
    )
    action: Literal["write"] = Field(
        default="write",
        description="Action performed.  Only 'write' is valid for Phase 1.",
    )


class SCRSState(BaseModel):
    """
    Top-level SCRS state object persisted to SCRS_state.json.

    Intentionally simple for Phase 1.  Real versioning and DB persistence
    come in a later phase; the interface (read/write methods on StateManager)
    is what matters now.
    """

    threat_scenarios: dict[str, object] = Field(
        default_factory=dict,
        description="Keyed by tid.  Value is the approved ThreatScenario dict.",
    )
    audit_log: list[AuditLogEntry] = Field(
        default_factory=list,
        description="Append-only audit log of all SCRS write actions.",
    )
