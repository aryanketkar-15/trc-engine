"""Risk Agent schemas (Phase 2): one RiskAssessment per approved threat.

The numbers (overall impact, feasibility, risk, rank) are computed by fixed rules in engine.py.
People and the AI only supply the ratings, the treatment decision and the residual risk.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ImpactLevel(StrEnum):
    NEGLIGIBLE = "Negligible"
    MODERATE = "Moderate"
    MAJOR = "Major"
    SEVERE = "Severe"


class Feasibility(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class RiskLevel(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Treatment(StrEnum):
    REDUCE = "Reduce"
    SHARE = "Share"
    RETAIN = "Retain"
    AVOID = "Avoid"


class RiskStatus(StrEnum):
    PENDING_HUMAN = "pending_human"
    APPROVED = "approved"
    REJECTED = "rejected"
    STALE = "stale"


class ImpactRatings(BaseModel):
    """Impact per axis; ``None`` means the axis does not apply (shown as '-')."""

    model_config = ConfigDict(frozen=True)

    safety: ImpactLevel | None = None
    financial: ImpactLevel | None = None
    operational: ImpactLevel | None = None
    privacy: ImpactLevel | None = None

    def levels(self) -> list[ImpactLevel]:
        return [v for v in (self.safety, self.financial, self.operational, self.privacy) if v]


class FeasibilityFactors(BaseModel):
    """The five ISO/SAE 21434 §15.5 factors, as keys of the points table in the ratings file."""

    model_config = ConfigDict(frozen=True)

    elapsed_time: str
    expertise: str
    knowledge: str
    window: str
    equipment: str


class RiskInput(BaseModel):
    """What the expert (or the AI suggestion) supplies for one threat."""

    model_config = ConfigDict(frozen=True)

    tid: Annotated[str, Field(min_length=1)]
    impact: ImpactRatings
    feasibility_factors: FeasibilityFactors | None = None
    attack_feasibility: Feasibility | None = Field(
        default=None,
        description="Direct expert rating; used when the five factors are not given.",
    )
    ai_suggested: bool = False
    suggestion_basis: str | None = None

    @model_validator(mode="after")
    def _needs_feasibility(self) -> RiskInput:
        if self.feasibility_factors is None and self.attack_feasibility is None:
            raise ValueError("give either feasibility_factors or attack_feasibility")
        return self


class RiskAssessment(BaseModel):
    """The scored risk of one approved threat, with the treatment decision and residual risk."""

    model_config = ConfigDict(populate_by_name=True)

    risk_id: str
    tid: str
    project_id: str | None = None
    use_case_id: str | None = None
    asset_id: str
    impact: ImpactRatings
    overall_impact: ImpactLevel
    feasibility_factors: FeasibilityFactors | None = None
    feasibility_points: int | None = None
    attack_feasibility: Feasibility
    risk: RiskLevel
    risk_basis: Literal["company", "derived", "provisional"]
    rank_in_asset: int | None = None
    treatment: Treatment | None = None
    treatment_rationale: str | None = None
    residual_risk: RiskLevel | None = None
    residual_basis: str | None = None
    ai_suggested: bool = False
    suggestion_basis: str | None = None
    status: RiskStatus = RiskStatus.PENDING_HUMAN
    approved_by: str | None = None
    threat_fingerprint: str | None = None
    ratings_version: str
    run_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TreatmentDecision(BaseModel):
    """The human treatment decision for one risk."""

    model_config = ConfigDict(frozen=True)

    treatment: Treatment
    rationale: Annotated[str, Field(min_length=5)]
    residual_risk: RiskLevel
    residual_reason: str | None = None
    approver: Annotated[str, Field(min_length=1)]

    @model_validator(mode="after")
    def _reduce_needs_reason(self) -> TreatmentDecision:
        if self.treatment in (Treatment.REDUCE, Treatment.SHARE) and not self.residual_reason:
            raise ValueError("Reduce and Share need a residual_reason (why this risk remains)")
        return self
