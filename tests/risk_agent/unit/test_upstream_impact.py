"""Impact starts from the severity and categories of the upstream team's approved asset table."""

from __future__ import annotations

import json
from typing import Any

import pytest

from agents.risk_agent import suggester
from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import ImpactLevel
from agents.threat_agent.schemas import AssetModel, DFDContext
from agents.threat_agent.team1_import import _damage_rating
from tests.risk_agent.unit.test_risk_engine import _threat


def _asset(**over: Any) -> AssetModel:
    base: dict[str, Any] = {
        "asset_id": "AS-1",
        "name": "E-key credential",
        "dfd_context": DFDContext(interfaces=["BLE"], trust_zone="device"),
    }
    base.update(over)
    return AssetModel(**base)


class TestReadingTheApprovedTable:
    def test_highest_severity_and_all_named_categories(self) -> None:
        asset = {
            "damage_scenarios": [
                {"scenario": "a", "severity": "Moderate", "impact_categories": ["Privacy"]},
                {
                    "scenario": "b",
                    "severity": "severe",
                    "impact_categories": ["financial", "Operational", "Privacy"],
                },
            ]
        }
        assert _damage_rating(asset) == ("Severe", ["Financial", "Operational", "Privacy"])

    def test_nothing_stated_gives_nothing(self) -> None:
        assert _damage_rating({"damage_scenarios": [{"scenario": "x"}]}) == ("", [])
        assert _damage_rating({}) == ("", [])

    def test_unknown_words_are_ignored_not_guessed(self) -> None:
        asset = {"damage_scenarios": [{"severity": "Catastrophic", "impact_categories": ["Fame"]}]}
        assert _damage_rating(asset) == ("", [])


class TestRuleBasedStart:
    def test_impact_follows_the_approved_categories_and_severity(self) -> None:
        asset = _asset(damage_severity="Severe", damage_impact_categories=["Financial", "Privacy"])
        s = suggester.deterministic_suggestion(_threat(), asset)
        assert s.impact.financial == ImpactLevel.SEVERE
        assert s.impact.privacy == ImpactLevel.SEVERE
        assert s.impact.operational is None and s.impact.safety is None
        assert "approved asset table" in (s.suggestion_basis or "")

    def test_without_an_approved_rating_the_old_rule_is_used(self) -> None:
        s = suggester.deterministic_suggestion(_threat(), _asset())
        assert "approved asset table" not in (s.suggestion_basis or "")
        assert s.impact.operational is not None

    def test_a_severity_without_categories_is_not_used(self) -> None:
        asset = _asset(damage_severity="Major")
        s = suggester.deterministic_suggestion(_threat(), asset)
        assert "approved asset table" not in (s.suggestion_basis or "")


class TestPromptCarriesTheApprovedRating:
    def test_facts_and_instruction_are_given_to_the_model(self) -> None:
        asset = _asset(damage_severity="Major", damage_impact_categories=["Operational"])
        user = json.loads(suggester._user_prompt(_threat(), asset))
        assert user["approved_damage_severity"] == "Major"
        assert user["approved_damage_impact_categories"] == ["Operational"]
        valid = {k: list(v) for k, v in Ratings.load().points.items()}
        system = suggester._system_prompt(valid)
        assert "approved_damage_severity" in system
        assert "Do not rate an axis above the approved severity" in system

    def test_no_rating_means_empty_facts(self) -> None:
        user = json.loads(suggester._user_prompt(_threat(), _asset()))
        assert user["approved_damage_severity"] is None
        assert user["approved_damage_impact_categories"] is None


@pytest.mark.parametrize("severity", ["Negligible", "Moderate", "Major", "Severe"])
def test_every_severity_word_is_a_valid_impact_level(severity: str) -> None:
    asset = _asset(damage_severity=severity, damage_impact_categories=["Safety"])
    assert suggester.deterministic_suggestion(_threat(), asset).impact.safety == ImpactLevel(
        severity
    )
