"""Risk rule engine: the company's six worked rows, ranking, treatment and staleness."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.risk_agent import engine, suggester
from agents.risk_agent.engine import Ratings, RatingsError
from agents.risk_agent.schemas import (
    Feasibility,
    FeasibilityFactors,
    ImpactLevel,
    ImpactRatings,
    RiskInput,
    RiskLevel,
    Treatment,
    TreatmentDecision,
)
from agents.risk_agent.staleness import check_risk_staleness
from agents.threat_agent.schemas import ThreatAgentInput, ThreatScenario
from agents.threat_agent.staleness import traceability_stamp
from scrp.state_manager import NotApprovedError, StateManager

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests/threat_agent/e2e/fixtures/smart_door_lock/input.json"
N, M, J, S = "Negligible", "Moderate", "Major", "Severe"

# Company document section 2.6: (S, F, O, P) impact, overall impact as written, feasibility, risk.
COMPANY_ROWS = {
    "T1": ((None, M, S, M), S, "Medium", "High"),
    "T2": ((None, S, S, S), S, "Medium", "High"),
    "T3": ((M, S, S, S), S, "Medium", "High"),
    "T4": ((None, N, M, S), M, "Low", "Medium"),
    "T5": ((None, M, S, None), M, "High", "Medium"),
    "T6": ((None, S, S, S), S, "Low", "Medium"),
}


@pytest.fixture(scope="module")
def ratings() -> Ratings:
    return Ratings.load()


def _inp() -> ThreatAgentInput:
    return ThreatAgentInput(**json.loads(FIXTURE.read_text(encoding="utf-8")))


def _threat(asset: str = "AS-1", tid: str = "THR-1", stride: str = "Tampering") -> ThreatScenario:
    inp = _inp()
    return ThreatScenario.model_validate(
        {
            "tid": tid,
            "run_id": inp.run_id,
            "asset_id": asset,
            "stride_category": stride,
            "attack_vector": "Replaying a captured BLE unlock command.",
            "kb_reference": "CAPEC-94",
            "evidence_chain": {
                "exposure": "BLE channel",
                "matched_pattern": "CAPEC-94",
                "applicability_reason": "The command has no freshness check.",
                "citation": "CAPEC-94: Adversary in the Middle",
            },
            "confidence_score": 0.7,
            "status": "approved",
            "validation_status": "passed",
            **traceability_stamp(inp, asset),
        }
    )


def _impact(row: tuple[Any, ...]) -> ImpactRatings:
    s, f, o, p = row
    return ImpactRatings(safety=s, financial=f, operational=o, privacy=p)


class TestCompanyRows:
    @pytest.mark.parametrize("name", list(COMPANY_ROWS))
    def test_matrix_reproduces_the_company_risk(self, ratings: Ratings, name: str) -> None:
        _axes, overall, feas, risk = COMPANY_ROWS[name]
        level, basis = engine.risk_from_matrix(ImpactLevel(overall), Feasibility(feas), ratings)
        assert level.value == risk
        assert basis in ("company", "derived")

    @pytest.mark.parametrize("name", ["T1", "T2", "T3", "T6"])
    def test_highest_axis_rule_matches_the_company_overall_impact(
        self, ratings: Ratings, name: str
    ) -> None:
        axes, overall, _f, _r = COMPANY_ROWS[name]
        assert engine.overall_impact(_impact(axes), ratings).value == overall

    @pytest.mark.parametrize("name", ["T4", "T5"])
    def test_known_discrepancy_company_rows_t4_t5_are_not_the_highest_axis(
        self, ratings: Ratings, name: str
    ) -> None:
        """The company lists a Severe axis but Moderate overall: a question for the company."""
        axes, overall, _f, _r = COMPANY_ROWS[name]
        assert engine.overall_impact(_impact(axes), ratings).value == S
        assert overall == M

    def test_cells_are_marked_with_their_source(self, ratings: Ratings) -> None:
        sources = [c["source"] for row in ratings.matrix.values() for c in row.values()]
        assert sources.count("company") == 4
        assert sources.count("derived") == 2
        assert sources.count("provisional") == 6

    def test_matrix_is_monotonic(self, ratings: Ratings) -> None:
        order = {"Low": 0, "Medium": 1, "High": 2}
        impacts = [
            ImpactLevel.NEGLIGIBLE,
            ImpactLevel.MODERATE,
            ImpactLevel.MAJOR,
            ImpactLevel.SEVERE,
        ]
        feas = [Feasibility.LOW, Feasibility.MEDIUM, Feasibility.HIGH]

        def val(i: ImpactLevel, f: Feasibility) -> int:
            return order[engine.risk_from_matrix(i, f, ratings)[0].value]

        for i, imp in enumerate(impacts):
            for j, fe in enumerate(feas):
                if j:
                    assert val(imp, fe) >= val(imp, feas[j - 1])
                if i:
                    assert val(imp, fe) >= val(impacts[i - 1], fe)


class TestFeasibility:
    def test_points_add_up_and_map_to_levels(self, ratings: Ratings) -> None:
        easy = FeasibilityFactors(
            elapsed_time="1_day",
            expertise="layman",
            knowledge="public",
            window="unlimited",
            equipment="standard",
        )
        hard = FeasibilityFactors(
            elapsed_time="6_months",
            expertise="expert",
            knowledge="confidential",
            window="difficult",
            equipment="bespoke",
        )
        assert engine.feasibility_from_factors(easy, ratings) == (0, Feasibility.HIGH)
        pts, level = engine.feasibility_from_factors(hard, ratings)
        assert pts == 17 + 6 + 7 + 10 + 7 and level == Feasibility.LOW

    def test_unknown_factor_value_is_rejected(self, ratings: Ratings) -> None:
        bad = FeasibilityFactors(
            elapsed_time="soon",
            expertise="layman",
            knowledge="public",
            window="unlimited",
            equipment="standard",
        )
        with pytest.raises(RatingsError):
            engine.feasibility_from_factors(bad, ratings)

    def test_input_needs_factors_or_direct_rating(self) -> None:
        with pytest.raises(ValueError, match="feasibility"):
            RiskInput(tid="x", impact=ImpactRatings(financial=ImpactLevel.MODERATE))

    def test_no_impact_axis_is_rejected(self, ratings: Ratings) -> None:
        with pytest.raises(RatingsError):
            engine.overall_impact(ImpactRatings(), ratings)


class TestScoreRankTreat:
    def _scored(self, ratings: Ratings, tid: str, asset: str, axes: Any, feas: str) -> Any:
        ri = RiskInput(tid=tid, impact=_impact(axes), attack_feasibility=Feasibility(feas))
        return engine.score(_threat(asset, tid), ri, ratings)

    def test_score_is_deterministic(self, ratings: Ratings) -> None:
        a = self._scored(ratings, "THR-1", "AS-1", (None, M, S, M), "Medium")
        b = self._scored(ratings, "THR-1", "AS-1", (None, M, S, M), "Medium")
        assert (a.overall_impact, a.attack_feasibility, a.risk) == (
            S,
            Feasibility.MEDIUM,
            RiskLevel.HIGH,
        )
        assert a.risk == b.risk and a.ratings_version == "placeholder-v0"
        assert a.risk_id == "RISK-THR-1" and a.project_id == _threat().project_id

    def test_threat_mismatch_is_rejected(self, ratings: Ratings) -> None:
        ri = RiskInput(
            tid="OTHER", impact=_impact((None, M, M, None)), attack_feasibility=Feasibility.LOW
        )
        with pytest.raises(RatingsError):
            engine.score(_threat(), ri, ratings)

    def test_ranking_is_per_asset_high_risk_first_and_stable(self, ratings: Ratings) -> None:
        items = [
            self._scored(ratings, "THR-C", "AS-1", (None, M, M, None), "High"),  # Medium
            self._scored(ratings, "THR-A", "AS-1", (None, S, S, S), "Medium"),  # High
            self._scored(ratings, "THR-B", "AS-1", (None, S, S, S), "Low"),  # Medium, Severe
            self._scored(ratings, "THR-D", "AS-2", (None, N, N, None), "Low"),  # Low
        ]
        ranked = engine.rank_per_asset(items)
        by_tid = {a.tid: a.rank_in_asset for a in ranked}
        assert by_tid == {"THR-A": 1, "THR-B": 2, "THR-C": 3, "THR-D": 1}
        again = engine.rank_per_asset(list(reversed(items)))
        assert [a.tid for a in again] == [a.tid for a in ranked]

    def test_reduce_needs_a_reason_and_creates_a_requirement(self, ratings: Ratings) -> None:
        a = self._scored(ratings, "THR-1", "AS-1", (None, M, S, M), "Medium")
        with pytest.raises(ValueError, match="residual_reason"):
            TreatmentDecision(
                treatment=Treatment.REDUCE,
                rationale="add a nonce",
                residual_risk=RiskLevel.LOW,
                approver="X",
            )
        done = engine.apply_treatment(
            a,
            TreatmentDecision(
                treatment=Treatment.REDUCE,
                rationale="add a nonce",
                residual_risk=RiskLevel.LOW,
                residual_reason="replay no longer possible",
                approver="Dr. A",
            ),
        )
        assert done.status.value == "approved" and done.approved_by == "Dr. A"
        assert done.residual_risk == RiskLevel.LOW and engine.requires_requirement(done)

    def test_retain_keeps_the_current_risk(self, ratings: Ratings) -> None:
        a = self._scored(ratings, "THR-1", "AS-1", (None, M, S, M), "Medium")
        low = TreatmentDecision(
            treatment=Treatment.RETAIN,
            rationale="accepted by owner",
            residual_risk=RiskLevel.LOW,
            approver="X",
        )
        with pytest.raises(RatingsError, match="Retain"):
            engine.apply_treatment(a, low)
        ok = engine.apply_treatment(a, low.model_copy(update={"residual_risk": RiskLevel.HIGH}))
        assert ok.residual_basis == "accepted as is" and not engine.requires_requirement(ok)


class TestIncompleteRatings:
    def test_a_matrix_with_a_missing_cell_is_refused(self, tmp_path: Path) -> None:
        data = json.loads(engine.DEFAULT_RATINGS_PATH.read_text(encoding="utf-8"))
        del data["risk_matrix"]["Major"]["Low"]
        p = tmp_path / "r.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(RatingsError, match="Major"):
            Ratings.load(p)


class TestSuggester:
    def test_rule_based_suggestion_follows_the_attacked_property(self) -> None:
        asset = next(a for a in _inp().assets if a.asset_id == "AS-3")
        s = suggester.deterministic_suggestion(
            _threat("AS-3", "THR-9", "InformationDisclosure"), asset
        )
        assert s.ai_suggested and s.impact.privacy is not None
        assert "rule-based" in (s.suggestion_basis or "")

    def test_live_llm_off_uses_the_rules(
        self, monkeypatch: pytest.MonkeyPatch, ratings: Ratings
    ) -> None:
        monkeypatch.setenv("USE_LIVE_LLM", "false")
        s = suggester.suggest(_threat(), None, {k: list(v) for k, v in ratings.points.items()})
        assert s.feasibility_factors is not None

    def test_llm_answer_is_parsed_and_bad_values_fall_back(
        self, monkeypatch: pytest.MonkeyPatch, ratings: Ratings
    ) -> None:
        monkeypatch.setenv("USE_LIVE_LLM", "true")
        monkeypatch.setattr(
            suggester, "get_settings", lambda: type("S", (), {"USE_LIVE_LLM": True})()
        )
        valid = {k: list(v) for k, v in ratings.points.items()}
        good = json.dumps(
            {
                "impact": {
                    "safety": None,
                    "financial": "Major",
                    "operational": "Severe",
                    "privacy": None,
                },
                "feasibility": {
                    "elapsed_time": "1_week",
                    "expertise": "proficient",
                    "knowledge": "public",
                    "window": "easy",
                    "equipment": "standard",
                },
                "reason": "Remote and cheap.",
            }
        )
        monkeypatch.setattr(suggester, "chat_completion", lambda **_: good)
        s = suggester.suggest(_threat(), None, valid)
        assert (s.suggestion_basis or "").startswith("LLM suggestion")
        assert s.impact.operational == ImpactLevel.SEVERE
        monkeypatch.setattr(
            suggester, "chat_completion", lambda **_: good.replace("1_week", "tomorrow")
        )
        assert "rule-based" in (suggester.suggest(_threat(), None, valid).suggestion_basis or "")
        monkeypatch.setattr(suggester, "chat_completion", lambda **_: "not json")
        assert "rule-based" in (suggester.suggest(_threat(), None, valid).suggestion_basis or "")


class TestStorageAndStaleness:
    def _approved_risk(self, ratings: Ratings, threat: ThreatScenario) -> dict[str, Any]:
        ri = RiskInput(
            tid=threat.tid, impact=_impact((None, M, S, M)), attack_feasibility=Feasibility.MEDIUM
        )
        a = engine.apply_treatment(
            engine.score(threat, ri, ratings),
            TreatmentDecision(
                treatment=Treatment.RETAIN,
                rationale="accepted by owner",
                residual_risk=RiskLevel.HIGH,
                approver="Dr. A",
            ),
        )
        return a.model_dump(mode="json")

    def test_commit_requires_a_named_approver_and_is_audited(
        self, tmp_path: Path, ratings: Ratings
    ) -> None:
        sm = StateManager(tmp_path / "s.json")
        t = _threat()
        item = self._approved_risk(ratings, t)
        with pytest.raises(NotApprovedError):
            sm.commit_risk_assessments([{**item, "approved_by": None}])
        assert sm.commit_risk_assessments([item]) == 1
        assert list(StateManager(tmp_path / "s.json").get_risk_assessments()) == [t.tid]
        last = sm.get_audit_log()[-1]
        assert last.action == "risk_approve" and "Dr. A" in (last.reason or "")

    def test_risk_goes_stale_when_its_threat_is_retired_or_regenerated(
        self, tmp_path: Path, ratings: Ratings
    ) -> None:
        sm = StateManager(tmp_path / "s.json")
        t = _threat()
        sm.commit_approved_run(t.run_id, [t])
        sm.commit_risk_assessments([self._approved_risk(ratings, t)])
        rep = check_risk_staleness(sm.get_risk_assessments(), sm.get_threat_scenarios())
        assert rep.fresh == [t.tid] and not rep.has_changes
        changed = t.model_copy(update={"context_fingerprint": "different"})
        rep2 = check_risk_staleness(
            sm.get_risk_assessments(), {t.tid: changed.model_dump(mode="json")}
        )
        assert rep2.stale and "re-generated" in rep2.stale[0][1]
        sm.retire_scenarios([t.tid], "upstream changed")
        rep3 = check_risk_staleness(sm.get_risk_assessments(), sm.get_threat_scenarios())
        assert rep3.stale == [(t.tid, "threat was retired or removed")]
        assert sm.retire_risk_assessments([t.tid], "threat was retired or removed") == 1
        assert sm.get_risk_assessments() == {}
        assert sm.get_audit_log()[-1].action == "risk_stale"

    def test_unscored_threats_are_reported(self, tmp_path: Path) -> None:
        sm = StateManager(tmp_path / "s.json")
        t = _threat()
        sm.commit_approved_run(t.run_id, [t])
        rep = check_risk_staleness(sm.get_risk_assessments(), sm.get_threat_scenarios())
        assert rep.unscored == [t.tid]
