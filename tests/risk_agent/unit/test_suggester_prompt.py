"""The Risk Agent's prompt: what the model is told, and that bad answers still fall back.

No model is called. The prompt is checked as text, and the answer path is checked with a fake
model reply.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

import pytest

from agents.risk_agent import suggester
from agents.risk_agent.engine import Ratings
from config.settings import get_settings
from tests.risk_agent.unit.test_risk_engine import _inp, _threat


@pytest.fixture(scope="module")
def valid() -> dict[str, list[str]]:
    return {k: list(v) for k, v in Ratings.load().points.items()}


@pytest.fixture(scope="module")
def prompt(valid: dict[str, list[str]]) -> str:
    return suggester._system_prompt(valid)


class TestSystemPrompt:
    def test_every_value_is_shown_with_its_points_from_the_rule_table(
        self, prompt: str, valid: dict[str, list[str]]
    ) -> None:
        table = Ratings.load().points
        for factor, values in valid.items():
            for value in values:
                assert f"{value} = {table[factor][value]} points" in prompt

    def test_it_says_a_higher_total_means_a_harder_attack_and_gives_the_level_bands(
        self, prompt: str
    ) -> None:
        assert "HIGHER total means a HARDER attack" in prompt
        assert "0-13 points = High feasibility" in prompt
        assert "14-19 points = Medium feasibility" in prompt
        assert "20 or more points = Low feasibility" in prompt

    def test_it_tells_the_model_to_use_where_the_attacker_must_be_and_what_is_needed(
        self, prompt: str
    ) -> None:
        for fact in (
            "remote over the internet",
            "Bluetooth",
            "physical access to the device",
            "special equipment",
            "insider knowledge",
            "window",
        ):
            assert fact in prompt

    def test_three_worked_examples_of_different_difficulty_are_other_products(
        self, prompt: str
    ) -> None:
        assert all(label in prompt for label in ("EASY:", "MEDIUM:", "HARD:"))
        for banned in ("door", "unlock", "e-key", "firmware image"):
            assert banned not in prompt.lower()
        assert not re.search(r"BLE", prompt)

    def test_the_examples_use_only_allowed_values_and_really_differ(
        self, prompt: str, valid: dict[str, list[str]]
    ) -> None:
        shown = [json.loads(m) for m in re.findall(r"feasibility (\{[^}]*\})", prompt)]
        assert len(shown) == 3
        ratings = Ratings.load()
        points = []
        for factors in shown:
            assert all(value in valid[name] for name, value in factors.items())
            points.append(sum(ratings.points[name][value] for name, value in factors.items()))
        assert points[0] < points[1] < points[2]

    def test_the_model_still_never_decides_the_risk_level(self, prompt: str) -> None:
        assert "risk level" not in prompt.lower()
        assert "a human will review" in prompt


class TestUserPrompt:
    def test_the_asset_interfaces_and_trust_zone_are_given_as_facts(self) -> None:
        asset = _inp().assets[0]
        facts = json.loads(suggester._user_prompt(_threat(), asset))
        assert facts["asset_interfaces"] == asset.dfd_context.interfaces
        assert facts["asset_interfaces"]
        assert facts["asset_trust_zone"] == asset.dfd_context.trust_zone

    def test_without_an_asset_they_are_marked_unknown(self) -> None:
        facts = json.loads(suggester._user_prompt(_threat(), None))
        assert facts["asset_interfaces"] == "unknown"
        assert facts["asset_trust_zone"] == "unknown"


class TestAnswersAreStillChecked:
    @staticmethod
    def _answer(valid: dict[str, list[str]], **feasibility: str) -> str:
        feas = {k: v[0] for k, v in valid.items()} | feasibility
        return json.dumps({"impact": {"operational": "Severe"}, "feasibility": feas, "reason": "r"})

    @pytest.fixture(autouse=True)
    def _live(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        monkeypatch.setenv("USE_LIVE_LLM", "true")
        monkeypatch.setenv("OPENAI_API_KEY", "ollama")
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()

    def test_an_allowed_answer_is_used(
        self, monkeypatch: pytest.MonkeyPatch, valid: dict[str, list[str]]
    ) -> None:
        monkeypatch.setattr(suggester, "chat_completion", lambda **_: self._answer(valid))
        result = suggester.suggest(_threat(), None, valid)
        assert (result.suggestion_basis or "").startswith("LLM suggestion")

    @pytest.mark.parametrize("bad", ["very hard", "Null", "2_months_ish"])
    def test_a_value_outside_the_allowed_list_falls_back_to_the_rule_default(
        self, monkeypatch: pytest.MonkeyPatch, valid: dict[str, list[str]], bad: str
    ) -> None:
        answer = self._answer(valid, equipment=bad)
        monkeypatch.setattr(suggester, "chat_completion", lambda **_: answer)
        result = suggester.suggest(_threat(), None, valid)
        assert "rule-based default" in (result.suggestion_basis or "")
