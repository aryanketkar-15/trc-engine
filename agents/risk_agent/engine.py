"""Risk rule engine: the same ratings always give the same risk (no AI in here)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.risk_agent.schemas import (
    Feasibility,
    FeasibilityFactors,
    ImpactLevel,
    ImpactRatings,
    RiskAssessment,
    RiskInput,
    RiskLevel,
    RiskStatus,
    TreatmentDecision,
)
from agents.threat_agent.schemas import ThreatScenario

DEFAULT_RATINGS_PATH = Path(__file__).with_name("ratings_placeholder.json")

_RISK_ORDER = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
_IMPACT_ORDER = {
    ImpactLevel.SEVERE: 0,
    ImpactLevel.MAJOR: 1,
    ImpactLevel.MODERATE: 2,
    ImpactLevel.NEGLIGIBLE: 3,
}
_FEAS_ORDER = {Feasibility.HIGH: 0, Feasibility.MEDIUM: 1, Feasibility.LOW: 2}


class RatingsError(ValueError):
    """The ratings table is incomplete or an input value is not in it."""


@dataclass(frozen=True)
class Ratings:
    """The rating tables (impact scale, feasibility points, risk matrix) as loaded from a file."""

    version: str
    aggregation: str
    points: dict[str, dict[str, int]]
    thresholds: list[tuple[int, Feasibility]]
    matrix: dict[str, dict[str, dict[str, str]]]

    @classmethod
    def load(cls, path: Path | None = None) -> Ratings:
        data: dict[str, Any] = json.loads(
            (path or DEFAULT_RATINGS_PATH).read_text(encoding="utf-8")
        )
        thresholds = sorted(
            (
                (int(t["max_points"]), Feasibility(t["feasibility"]))
                for t in data["feasibility_thresholds"]
            ),
            key=lambda t: t[0],
        )
        ratings = cls(
            version=str(data["ratings_version"]),
            aggregation=str(data.get("impact_aggregation", "max")),
            points=data["feasibility_points"],
            thresholds=thresholds,
            matrix=data["risk_matrix"],
        )
        ratings._check_complete()
        return ratings

    def _check_complete(self) -> None:
        for impact in ImpactLevel:
            for feas in Feasibility:
                cell = self.matrix.get(impact.value, {}).get(feas.value)
                if not cell or "risk" not in cell:
                    raise RatingsError(
                        f"risk matrix has no value for {impact.value} x {feas.value}"
                    )
                RiskLevel(cell["risk"])
                if cell.get("source") not in ("company", "derived", "provisional"):
                    raise RatingsError(
                        f"risk matrix cell {impact.value} x {feas.value} has no source"
                    )
        if self.aggregation not in ("max",):
            raise RatingsError(f"unknown impact aggregation '{self.aggregation}'")


def overall_impact(impact: ImpactRatings, ratings: Ratings) -> ImpactLevel:
    """Aggregate the four axes (default rule: the highest axis)."""
    levels = impact.levels()
    if not levels:
        raise RatingsError("at least one impact axis must be rated")
    return min(levels, key=lambda lv: _IMPACT_ORDER[lv])


def feasibility_from_factors(
    factors: FeasibilityFactors, ratings: Ratings
) -> tuple[int, Feasibility]:
    """Add up the points of the five factors and map the sum to Low, Medium or High."""
    total = 0
    for name, value in factors.model_dump().items():
        table = ratings.points[name]
        if value not in table:
            raise RatingsError(f"{name}='{value}' is not one of {sorted(table)}")
        total += table[value]
    for max_points, level in ratings.thresholds:
        if total <= max_points:
            return total, level
    raise RatingsError("no feasibility threshold covers the point total")


def risk_from_matrix(
    impact: ImpactLevel, feasibility: Feasibility, ratings: Ratings
) -> tuple[RiskLevel, str]:
    cell = ratings.matrix[impact.value][feasibility.value]
    return RiskLevel(cell["risk"]), str(cell["source"])


def risk_id_for(tid: str) -> str:
    return f"RISK-{tid}"


def score(
    scenario: ThreatScenario,
    risk_input: RiskInput,
    ratings: Ratings,
    *,
    threat_fingerprint: str | None = None,
) -> RiskAssessment:
    """Score one approved threat. Raises RatingsError for values outside the tables."""
    if risk_input.tid != scenario.tid:
        raise RatingsError(f"risk input is for {risk_input.tid}, threat is {scenario.tid}")
    overall = overall_impact(risk_input.impact, ratings)
    points: int | None = None
    if risk_input.feasibility_factors is not None:
        points, feasibility = feasibility_from_factors(risk_input.feasibility_factors, ratings)
    else:
        assert risk_input.attack_feasibility is not None
        feasibility = risk_input.attack_feasibility
    level, basis = risk_from_matrix(overall, feasibility, ratings)
    return RiskAssessment(
        risk_id=risk_id_for(scenario.tid),
        tid=scenario.tid,
        project_id=scenario.project_id,
        use_case_id=scenario.use_case_id,
        asset_id=scenario.asset_id,
        impact=risk_input.impact,
        overall_impact=overall,
        feasibility_factors=risk_input.feasibility_factors,
        feasibility_points=points,
        attack_feasibility=feasibility,
        risk=level,
        risk_basis=basis,  # type: ignore[arg-type]
        ai_suggested=risk_input.ai_suggested,
        suggestion_basis=risk_input.suggestion_basis,
        threat_fingerprint=threat_fingerprint
        or f"{scenario.asset_fingerprint or ''}|{scenario.context_fingerprint or ''}",
        ratings_version=ratings.version,
        run_id=scenario.run_id,
    )


def rank_per_asset(assessments: list[RiskAssessment]) -> list[RiskAssessment]:
    """Number the risks 1..n inside each asset: High risk first, then impact, then feasibility.

    Ties are broken by tid so repeated runs give the same order.
    """
    grouped: dict[tuple[str | None, str | None, str], list[RiskAssessment]] = {}
    for a in assessments:
        grouped.setdefault((a.project_id, a.use_case_id, a.asset_id), []).append(a)
    ranked: list[RiskAssessment] = []
    for key in sorted(grouped, key=lambda k: tuple(x or "" for x in k)):
        ordered = sorted(
            grouped[key],
            key=lambda a: (
                _RISK_ORDER[a.risk],
                _IMPACT_ORDER[a.overall_impact],
                _FEAS_ORDER[a.attack_feasibility],
                a.tid,
            ),
        )
        ranked.extend(a.model_copy(update={"rank_in_asset": i}) for i, a in enumerate(ordered, 1))
    return ranked


def apply_treatment(assessment: RiskAssessment, decision: TreatmentDecision) -> RiskAssessment:
    """Record the human decision. The assessment becomes approved with the approver's name."""
    basis = "expert judgement"
    if decision.treatment.value == "Retain":
        # accepting a risk means the residual risk is the current risk
        if decision.residual_risk != assessment.risk:
            raise RatingsError(
                "Retain keeps the risk as it is: residual risk must equal the current risk "
                f"({assessment.risk.value})"
            )
        basis = "accepted as is"
    return assessment.model_copy(
        update={
            "treatment": decision.treatment,
            "treatment_rationale": decision.rationale,
            "residual_risk": decision.residual_risk,
            "residual_basis": basis
            if not decision.residual_reason
            else f"{basis}: {decision.residual_reason}",
            "status": RiskStatus.APPROVED,
            "approved_by": decision.approver,
        }
    )


def requires_requirement(assessment: RiskAssessment) -> bool:
    """Reduce means Team 3 must derive a security requirement; Retain means residual risk."""
    return assessment.treatment is not None and assessment.treatment.value == "Reduce"
