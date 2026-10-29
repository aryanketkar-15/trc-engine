"""Human-in-the-loop for risk, risk justification, and the attack-resistance mapping."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.compliance_agent import engine as cengine
from agents.compliance_agent.engine import ComplianceDecision, Rules, RulesError
from agents.risk_agent import engine, suggester
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
from scrp.state_manager import NotApprovedError, StateManager
from tests.risk_agent.unit.test_risk_engine import _threat

M, S = ImpactLevel.MODERATE, ImpactLevel.SEVERE


@pytest.fixture(scope="module")
def ratings() -> Ratings:
    return Ratings.load()


@pytest.fixture(scope="module")
def rules() -> Rules:
    return Rules.load()


def _scored(ratings: Ratings, tid: str = "THR-1", feas: Feasibility = Feasibility.MEDIUM) -> Any:
    ri = RiskInput(
        tid=tid, impact=ImpactRatings(financial=M, operational=S), attack_feasibility=feas
    )
    return engine.score(_threat("AS-1", tid), ri, ratings)


def _reduce(approver: str = "Dr. A", **kw: Any) -> TreatmentDecision:
    return TreatmentDecision(
        treatment=Treatment.REDUCE,
        rationale="add a nonce",
        residual_risk=RiskLevel.LOW,
        residual_reason="replay no longer possible",
        approver=approver,
        **kw,
    )


class TestJustification:
    def test_explains_impact_feasibility_and_matrix_cell(self, ratings: Ratings) -> None:
        a = _scored(ratings)
        text = a.justification
        assert "Overall impact is Severe" in text and "Operational" in text
        assert "Medium" in text and "company" in text and "High risk" in text

    def test_points_and_provisional_cells_are_stated(self, ratings: Ratings) -> None:
        from agents.risk_agent.schemas import FeasibilityFactors

        ri = RiskInput(
            tid="THR-1",
            impact=ImpactRatings(operational=ImpactLevel.MAJOR),
            feasibility_factors=FeasibilityFactors(
                elapsed_time="1_week",
                expertise="layman",
                knowledge="public",
                window="easy",
                equipment="standard",
            ),
        )
        a = engine.score(_threat(), ri, ratings)
        assert "add up to 2 points" in a.justification and "PROVISIONAL" in a.justification


class TestRiskAdjustment:
    def test_expert_adjustment_needs_a_reason(self) -> None:
        with pytest.raises(ValueError, match="adjustment_reason"):
            _reduce(adjusted_risk=RiskLevel.MEDIUM)

    def test_adjustment_changes_effective_risk_ranking_and_retain_rule(
        self, ratings: Ratings
    ) -> None:
        a = _scored(ratings)  # computed High
        adj = engine.apply_treatment(
            a,
            _reduce(adjusted_risk=RiskLevel.MEDIUM, adjustment_reason="already mitigated by lock"),
        )
        assert adj.risk == RiskLevel.HIGH and adj.effective_risk == RiskLevel.MEDIUM
        assert adj.adjustment_reason == "already mitigated by lock"
        retain = TreatmentDecision(
            treatment=Treatment.RETAIN,
            rationale="accepted by owner",
            residual_risk=RiskLevel.MEDIUM,
            approver="Dr. A",
            adjusted_risk=RiskLevel.MEDIUM,
            adjustment_reason="owner assessment",
        )
        assert engine.apply_treatment(a, retain).residual_risk == RiskLevel.MEDIUM
        high = _scored(ratings, "THR-2")
        ranked = engine.rank_per_asset([adj.model_copy(update={"rank_in_asset": None}), high])
        assert [r.tid for r in ranked] == ["THR-2", "THR-1"]

    def test_adjusting_to_the_same_value_is_ignored(self, ratings: Ratings) -> None:
        a = engine.apply_treatment(
            _scored(ratings), _reduce(adjusted_risk=RiskLevel.HIGH, adjustment_reason="same value")
        )
        assert a.adjusted_risk is None and a.adjustment_reason is None


class TestAuditOfHumanDecisions:
    def test_rejections_edits_and_adjustments_are_audited(
        self, tmp_path: Path, ratings: Ratings
    ) -> None:
        sm = StateManager(tmp_path / "s.json")
        assert sm.log_risk_rejection("THR-1", "R1", "feasibility too low", "Dr. A") == 1
        assert sm.log_risk_rejection("THR-1", "R1", "still wrong", "Dr. A") == 2
        assert sm.risk_rejection_count("THR-1") == 2 and sm.risk_rejection_count("X") == 0
        edited = RiskInput(
            tid="THR-1",
            impact=ImpactRatings(operational=S),
            attack_feasibility=Feasibility.MEDIUM,
            ai_suggested=False,
            suggestion_basis="entered by expert",
        )
        a = engine.apply_treatment(
            engine.score(_threat(), edited, ratings),
            _reduce(adjusted_risk=RiskLevel.MEDIUM, adjustment_reason="owner view"),
            rejections=sm.risk_rejection_count("THR-1"),
        )
        sm.commit_risk_assessments([a.model_dump(mode="json")])
        actions = [e.action for e in sm.get_audit_log()]
        assert actions == ["risk_reject", "risk_reject", "risk_edit", "risk_adjust", "risk_approve"]
        stored = StateManager(tmp_path / "s.json").get_risk_assessments()["THR-1"]
        assert stored["rejections_before_approval"] == 2  # type: ignore[index]
        assert stored["justification"] and stored["effective_risk"] == "Medium"  # type: ignore[index]


class TestRegenerateAfterRejection:
    def test_feedback_reaches_the_llm_and_a_new_suggestion_comes_back(
        self, monkeypatch: pytest.MonkeyPatch, ratings: Ratings
    ) -> None:
        monkeypatch.setattr(
            suggester, "get_settings", lambda: type("S", (), {"USE_LIVE_LLM": True})()
        )
        monkeypatch.delenv("USE_LIVE_LLM", raising=False)
        seen: dict[str, str] = {}
        answer = json.dumps(
            {
                "impact": {
                    "safety": None,
                    "financial": "Major",
                    "operational": "Major",
                    "privacy": None,
                },
                "feasibility": {
                    "elapsed_time": "1_week",
                    "expertise": "layman",
                    "knowledge": "public",
                    "window": "easy",
                    "equipment": "standard",
                },
                "reason": "Cheap remote attack.",
            }
        )

        def fake(**kw: Any) -> str:
            seen["user"] = kw["user_prompt"]
            return answer

        monkeypatch.setattr(suggester, "chat_completion", fake)
        valid = {k: list(v) for k, v in ratings.points.items()}
        prev = suggester.deterministic_suggestion(_threat(), None)
        new = suggester.suggest(
            _threat(), None, valid, feedback="attack is cheaper than you think", previous=prev
        )
        assert "attack is cheaper than you think" in seen["user"]
        assert "previous_suggestion" in seen["user"]
        assert (new.suggestion_basis or "").startswith("LLM suggestion")

    def test_without_llm_the_expert_is_told_to_enter_ratings(
        self, monkeypatch: pytest.MonkeyPatch, ratings: Ratings
    ) -> None:
        monkeypatch.setenv("USE_LIVE_LLM", "false")
        valid = {k: list(v) for k, v in ratings.points.items()}
        prev = suggester.deterministic_suggestion(_threat(), None)
        new = suggester.suggest(_threat(), None, valid, feedback="too low", previous=prev)
        assert (new.suggestion_basis or "").startswith("could not produce a new suggestion")
        assert new.impact == prev.impact


class TestComplianceMapping:
    def _risk(
        self, ratings: Ratings, feas: Feasibility = Feasibility.MEDIUM, tid: str = "THR-1"
    ) -> Any:
        return engine.apply_treatment(_scored(ratings, tid, feas), _reduce())

    def test_company_rows_are_reproduced_by_class(self, rules: Rules) -> None:
        eb = rules.table["Enhanced-Basic"]
        mod = rules.table["Moderate"]
        # company section 2.7: T1 and T3/T6
        assert (eb["jil_attack_potential"], eb["sesip_level"], eb["cc_eal"]) == (
            "Moderate",
            "SESIP 2",
            "EAL2+",
        )
        assert (mod["jil_attack_potential"], mod["sesip_level"], mod["cc_eal"]) == (
            "High",
            "SESIP 3",
            "EAL4+",
        )
        assert eb["required_resistance"].endswith("Enhanced-Basic attackers")

    def test_high_risk_maps_to_moderate_by_rule_cr1(self, ratings: Ratings, rules: Rules) -> None:
        rec = cengine.propose(self._risk(ratings), rules)  # High risk
        assert (rec.attacker_class, rec.rule_id, rec.sesip_level, rec.cc_eal) == (
            "Moderate",
            "CR-1",
            "SESIP 3",
            "EAL4+",
        )
        assert rec.status.value == "pending_human" and rec.rule_basis == "company"
        assert "rule CR-1" in rec.justification

    def test_default_rule_does_not_reproduce_company_t1_and_t6_expert_overrides(
        self, ratings: Ratings, rules: Rules
    ) -> None:
        """T1 is High risk but the company maps it to Enhanced-Basic; the expert overrides."""
        risk = self._risk(ratings)
        assert cengine.propose(risk, rules).attacker_class != "Enhanced-Basic"
        rec = cengine.confirm(
            risk,
            rules,
            ComplianceDecision(
                approver="Dr. A",
                attacker_class="Enhanced-Basic",
                override_reason="BLE proximity attacker only",
            ),
        )
        assert rec.overridden and rec.rule_id == "EXPERT-OVERRIDE" and rec.cc_eal == "EAL2+"
        assert rec.status.value == "confirmed" and rec.confirmed_by == "Dr. A"
        assert "BLE proximity attacker only" in rec.justification

    def test_override_needs_a_reason_and_a_known_class(
        self, ratings: Ratings, rules: Rules
    ) -> None:
        with pytest.raises(ValueError, match="override_reason"):
            ComplianceDecision(approver="X", attacker_class="High")
        with pytest.raises(RulesError):
            cengine.confirm(
                self._risk(ratings),
                rules,
                ComplianceDecision(approver="X", attacker_class="Godlike", override_reason="no"),
            )

    def test_classes_without_company_values_say_so(self, ratings: Ratings, rules: Rules) -> None:
        low = engine.apply_treatment(_scored(ratings, "THR-3", Feasibility.LOW), _reduce())
        rec = cengine.confirm(
            low,
            rules,
            ComplianceDecision(approver="X", attacker_class="High", override_reason="critical key"),
        )
        assert cengine.NEEDS_VALUE in (rec.sesip_level, rec.cc_eal, rec.jil_attack_potential)
        assert "Missing company values" in rec.justification

    def test_only_reduce_is_mapped_by_default(self, ratings: Ratings) -> None:
        retain = engine.apply_treatment(
            _scored(ratings, "THR-4"),
            TreatmentDecision(
                treatment=Treatment.RETAIN,
                rationale="accepted",
                residual_risk=RiskLevel.HIGH,
                approver="X",
            ),
        )
        assert cengine.applies(self._risk(ratings)) and not cengine.applies(retain)
        assert cengine.applies(retain, include_all=True)

    def test_store_requires_confirmation_and_audits_override(
        self, tmp_path: Path, ratings: Ratings, rules: Rules
    ) -> None:
        sm = StateManager(tmp_path / "s.json")
        risk = self._risk(ratings)
        pending = cengine.propose(risk, rules).model_dump(mode="json")
        with pytest.raises(NotApprovedError):
            sm.commit_compliance_records([pending])
        rec = cengine.confirm(
            risk,
            rules,
            ComplianceDecision(
                approver="Dr. A", attacker_class="Enhanced-Basic", override_reason="proximity only"
            ),
        )
        assert sm.commit_compliance_records([rec.model_dump(mode="json")]) == 1
        last = sm.get_audit_log()[-1]
        assert last.action == "compliance_override" and "proximity only" in (last.reason or "")
        sm.log_compliance_rejection("THR-1", "R", "needs lab check", "Dr. A")
        assert sm.get_audit_log()[-1].action == "compliance_reject"

    def test_staleness_when_risk_or_treatment_changes(self, ratings: Ratings, rules: Rules) -> None:
        risk = self._risk(ratings)
        rec = cengine.confirm(risk, rules, ComplianceDecision(approver="X"))
        records = {risk.tid: rec.model_dump(mode="json")}
        risks = {risk.tid: risk.model_dump(mode="json")}
        assert cengine.check_compliance_staleness(records, risks) == ([], [])
        changed = engine.apply_treatment(
            _scored(ratings),
            _reduce(adjusted_risk=RiskLevel.MEDIUM, adjustment_reason="re-assessed"),
        )
        stale, _ = cengine.check_compliance_staleness(
            records, {risk.tid: changed.model_dump(mode="json")}
        )
        assert stale and "changed" in stale[0][1]
        stale2, _ = cengine.check_compliance_staleness(records, {})
        assert stale2 == [(risk.tid, "risk assessment was retired or removed")]
        new_risk = self._risk(ratings, tid="THR-9")
        _, unmapped = cengine.check_compliance_staleness(
            records, {**risks, "THR-9": new_risk.model_dump(mode="json")}
        )
        assert unmapped == ["THR-9"]

    def test_incomplete_rule_base_is_refused(self, tmp_path: Path) -> None:
        data = json.loads(cengine.DEFAULT_RULES_PATH.read_text(encoding="utf-8"))
        data["risk_to_class"] = data["risk_to_class"][:2]
        p = tmp_path / "r.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(RulesError):
            Rules.load(p)
