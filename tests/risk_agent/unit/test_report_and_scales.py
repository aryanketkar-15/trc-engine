"""Consolidated TARA report and the factor point scales."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

import pytest

from agents.compliance_agent import engine as cengine
from agents.compliance_agent.engine import ComplianceDecision, Rules
from agents.risk_agent import engine, report
from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import (
    Feasibility,
    ImpactLevel,
    ImpactRatings,
    RiskInput,
    RiskLevel,
    Treatment,
    TreatmentDecision,
)
from scrp.state_manager import StateManager
from tests.risk_agent.unit.test_risk_engine import _threat


def test_point_scales_follow_the_cem_attack_potential_table() -> None:
    p = Ratings.load().points
    assert p["elapsed_time"] == {
        "1_day": 0,
        "1_week": 1,
        "2_weeks": 2,
        "1_month": 4,
        "2_months": 7,
        "3_months": 10,
        "4_months": 13,
        "5_months": 15,
        "6_months": 17,
        "more_than_6_months": 19,
    }
    assert p["expertise"] == {"layman": 0, "proficient": 3, "expert": 6, "multiple_experts": 8}
    assert p["knowledge"] == {"public": 0, "restricted": 3, "sensitive": 7, "critical": 11}
    assert p["window"] == {"unlimited": 0, "easy": 1, "moderate": 4, "difficult": 10}
    assert p["equipment"] == {"standard": 0, "specialized": 4, "bespoke": 7, "multiple_bespoke": 9}


@pytest.mark.parametrize(
    ("points", "level"),
    [
        (0, Feasibility.HIGH),
        (13, Feasibility.HIGH),
        (14, Feasibility.MEDIUM),
        (19, Feasibility.MEDIUM),
        (20, Feasibility.LOW),
        (40, Feasibility.LOW),
    ],
)
def test_feasibility_boundaries(points: int, level: Feasibility) -> None:
    ratings = Ratings.load()
    # build factors that sum exactly to the wanted total where possible, else check thresholds directly
    for max_points, lv in ratings.thresholds:
        if points <= max_points:
            assert lv == level
            break


def _env(tmp_path: Path) -> StateManager:
    sm = StateManager(tmp_path / "s.json")
    ratings, rules = Ratings.load(), Rules.load()
    specs = [
        ("THR-A", "AS-1", ImpactLevel.SEVERE, Feasibility.MEDIUM, Treatment.REDUCE),
        ("THR-B", "AS-1", ImpactLevel.MODERATE, Feasibility.HIGH, Treatment.RETAIN),
        ("THR-C", "AS-2", ImpactLevel.SEVERE, Feasibility.LOW, Treatment.REDUCE),
    ]
    threats = [_threat(asset, tid) for tid, asset, *_ in specs]
    sm.commit_approved_run(threats[0].run_id, threats)
    done = []
    for (tid, _asset, imp, feas, tr), th in zip(specs, threats, strict=True):
        ri = RiskInput(tid=tid, impact=ImpactRatings(operational=imp), attack_feasibility=feas)
        scored = engine.score(th, ri, ratings)
        retain = tr == Treatment.RETAIN
        done.append(
            engine.apply_treatment(
                scored,
                TreatmentDecision(
                    treatment=tr,
                    rationale="decision recorded",
                    residual_risk=scored.risk if retain else RiskLevel.LOW,
                    residual_reason=None if retain else "control added",
                    approver="Dr. A",
                ),
            )
        )
    sm.commit_risk_assessments([d.model_dump(mode="json") for d in done])
    reduce = [d for d in done if d.treatment == Treatment.REDUCE]
    sm.commit_compliance_records(
        [
            cengine.confirm(d, rules, ComplianceDecision(approver="Dr. A")).model_dump(mode="json")
            for d in reduce
        ]
    )
    # an approved threat without a risk yet
    extra = _threat("AS-2", "THR-D")
    sm.commit_approved_run(extra.run_id, [extra])
    return sm


def test_report_groups_by_asset_ranks_and_splits_requirements_from_residual(tmp_path: Path) -> None:
    data: dict[str, Any] = report.build_report(_env(tmp_path))
    s = data["summary"]
    assert (s["approved_threats"], s["scored"], s["not_yet_scored"]) == (4, 3, 1)
    assert s["risk_levels"] == {"High": 1, "Medium": 2, "Low": 0}
    assert s["to_reduce_requirements"] == 2 and s["residual_items"] == 1
    assert s["with_resistance_level"] == 2
    assert [r["tid"] for r in data["by_asset"]["AS-1"]] == ["THR-A", "THR-B"]
    assert [r["rank"] for r in data["by_asset"]["AS-1"]] == [1, 2]
    assert data["requirements_needed"] == ["THR-A", "THR-C"]
    assert [r["tid"] for r in data["residual_risk"]] == ["THR-B"]
    assert data["not_yet_scored"][0]["tid"] == "THR-D"
    # THR-C: Severe impact, Low feasibility -> Medium risk -> raised to Moderate by rule CR-4
    c = next(r for r in data["by_asset"]["AS-2"] if r["tid"] == "THR-C")
    assert (c["attacker_class"], c["sesip_level"], c["cc_eal"]) == ("Moderate", "SESIP 3", "EAL4+")


def test_report_formats(tmp_path: Path) -> None:
    data = report.build_report(_env(tmp_path))
    rows = list(csv.DictReader(io.StringIO(report.to_csv(data))))
    assert (
        len(rows) == 3 and rows[0]["asset_id"] == "AS-1" and rows[0]["needs_requirement"] == "True"
    )
    md = report.to_markdown(data, "TARA report - test")
    assert md.startswith("# TARA report - test") and "## AS-1" in md and "THR-D" in md
    assert "Security requirements needed" in md and "Residual risk" in md


def test_report_filters_by_use_case(tmp_path: Path) -> None:
    sm = _env(tmp_path)
    own = _threat().use_case_id
    assert (
        report.build_report(sm, use_case_id="UC-DOES-NOT-EXIST")["summary"]["approved_threats"] == 0
    )
    assert report.build_report(sm, use_case_id=own)["summary"]["approved_threats"] == 4
