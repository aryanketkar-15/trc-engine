"""Phase 3: asset criticality, citations, protection targets and the guarded LLM rationale."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.compliance_agent import engine as cengine
from agents.compliance_agent import explainer
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
from agents.threat_agent.schemas import SecurityAttributes
from common.llm_client import LLMAPIError, chat_completion
from scrp.state_manager import StateManager
from tests.risk_agent.unit.test_risk_engine import _inp, _threat

CHUNKS = [
    {
        "standard": "Common Criteria",
        "doc": "CEM:2022 R1",
        "locator": "p. 464.1",
        "text": "Table B.3 rating of vulnerabilities",
        "similarity": 0.72,
    },
    {
        "standard": "JIL",
        "doc": "JIL v3.2.1",
        "locator": "p. 30.2",
        "text": "Table 14",
        "similarity": 0.6,
    },
]


@pytest.fixture(scope="module")
def rules() -> Rules:
    return Rules.load()


def _risk(
    tid: str = "THR-1",
    asset: str = "AS-1",
    impact: ImpactLevel = ImpactLevel.MODERATE,
    feasibility: Feasibility = Feasibility.MEDIUM,
) -> Any:
    ri = RiskInput(
        tid=tid, impact=ImpactRatings(operational=impact), attack_feasibility=feasibility
    )
    return engine.apply_treatment(
        engine.score(_threat(asset, tid), ri, Ratings.load()),
        TreatmentDecision(
            treatment=Treatment.REDUCE,
            rationale="add a control",
            residual_risk=RiskLevel.LOW,
            residual_reason="control added",
            approver="Dr. A",
        ),
    )


def _asset(c: bool, i: bool, a: bool, auth: bool) -> Any:
    return (
        _inp()
        .assets[0]
        .model_copy(
            update={
                "security_attributes": SecurityAttributes(
                    confidentiality=c, integrity=i, availability=a, authenticity=auth
                )
            }
        )
    )


class TestCriticality:
    @pytest.mark.parametrize(
        ("flags", "level"),
        [
            ((True, True, True, True), "High"),
            ((False, True, True, True), "High"),
            ((False, True, True, False), "Medium"),
            ((True, False, False, False), "Low"),
            ((False, False, False, False), "Low"),
        ],
    )
    def test_level_follows_the_required_properties(
        self, rules: Rules, flags: tuple[bool, ...], level: str
    ) -> None:
        assert cengine.asset_criticality(_asset(*flags), rules) == level

    def test_no_asset_facts_means_unknown(self, rules: Rules) -> None:
        assert cengine.asset_criticality(None, rules) == cengine.UNKNOWN

    def test_high_criticality_raises_a_medium_risk(self, rules: Rules) -> None:
        risk = _risk()  # Moderate impact, Medium feasibility -> Medium risk
        assert risk.effective_risk == RiskLevel.MEDIUM
        plain = cengine.propose(risk, rules)
        assert (plain.attacker_class, plain.rule_id) == ("Enhanced-Basic", "CR-2")
        raised = cengine.propose(risk, rules, criticality="High")
        assert (raised.attacker_class, raised.rule_id) == ("Moderate", "CR-2+CR-5")
        assert raised.asset_criticality == "High" and "criticality High" in raised.justification

    def test_lower_criticality_changes_nothing(self, rules: Rules) -> None:
        assert cengine.propose(_risk(), rules, criticality="Low").attacker_class == "Enhanced-Basic"

    def test_confirm_keeps_the_criticality(self, rules: Rules) -> None:
        rec = cengine.confirm(
            _risk(), rules, ComplianceDecision(approver="Dr. A"), criticality="High"
        )
        assert rec.attacker_class == "Moderate" and rec.asset_criticality == "High"
        assert rec.suggested_attacker_class == "Moderate" and not rec.overridden


class TestCitations:
    def test_every_record_cites_the_standards(self, rules: Rules) -> None:
        rec = cengine.propose(_risk(), rules)
        assert {(c["doc"], c["locator"]) for c in rec.citations} == {
            ("CEM:2022 R1", "p. 464.1"),
            ("JIL Application of Attack Potential to Smartcards v3.2.1", "p. 30.2"),
        }


class TestProtectionTargets:
    def test_strongest_class_wins_per_asset_and_for_the_product(self, rules: Rules) -> None:
        records = [
            cengine.propose(_risk("THR-A", "AS-1"), rules),  # Enhanced-Basic
            cengine.propose(_risk("THR-B", "AS-1", ImpactLevel.SEVERE), rules),  # Moderate
            cengine.propose(_risk("THR-C", "AS-2"), rules),  # Enhanced-Basic
        ]
        out = cengine.protection_targets(records, rules)
        assert out["per_asset"]["AS-1"]["attacker_class"] == "Moderate"
        assert out["per_asset"]["AS-1"]["driven_by"] == ["THR-B"]
        assert out["per_asset"]["AS-2"]["cc_eal"] == "EAL2+"
        assert out["product"]["sesip_level"] == "SESIP 3"

    def test_no_records_means_no_product_target(self, rules: Rules) -> None:
        assert cengine.protection_targets([], rules) == {"per_asset": {}, "product": None}

    def test_report_shows_the_targets(self, tmp_path: Path, rules: Rules) -> None:
        sm = StateManager(tmp_path / "s.json")
        risk = _risk(impact=ImpactLevel.SEVERE)
        threat = _threat("AS-1", risk.tid)
        sm.commit_approved_run(threat.run_id, [threat])
        sm.commit_risk_assessments([risk.model_dump(mode="json")])
        rec = cengine.confirm(risk, rules, ComplianceDecision(approver="Dr. A"))
        sm.commit_compliance_records([rec.model_dump(mode="json")])
        data = report.build_report(sm)
        assert data["protection_targets"]["product"]["cc_eal"] == "EAL4+"
        md = report.to_markdown(data)
        assert "## Required protection level" in md and "| Product | Moderate |" in md


class TestRationaleGuards:
    def _answer(self, rationale: str, cited: list[str] | None = None) -> str:
        return json.dumps({"rationale": rationale, "cited": cited if cited is not None else ["S1"]})

    @pytest.fixture()
    def live(self, monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
        monkeypatch.delenv("USE_LIVE_LLM", raising=False)
        monkeypatch.setattr(
            explainer,
            "get_settings",
            lambda: type("S", (), {"USE_LIVE_LLM": True, "OPENAI_MODEL": "test-model"})(),
        )
        monkeypatch.setattr(explainer, "retrieve_standards", lambda _q: CHUNKS)
        return monkeypatch

    def _record(self, rules: Rules) -> Any:
        return cengine.propose(_risk(impact=ImpactLevel.SEVERE), rules)  # Moderate, EAL4+, SESIP 3

    def test_good_answer_is_kept_with_its_evidence(self, live: Any, rules: Rules) -> None:
        text = "AVA_VAN.4 at EAL4+ resists Moderate attackers, per the rating table."
        live.setattr(explainer, "chat_completion", lambda **_: self._answer(text))
        ai = explainer.explain(self._record(rules), "replay of a BLE command")
        assert ai is not None and ai.ai_rationale == text
        assert ai.ai_evidence[0]["locator"] == "p. 464.1" and ai.ai_confidence == 0.72
        assert ai.ai_model == "test-model" and ai.ai_prompt_version == explainer.PROMPT_VERSION

    def test_rationale_never_changes_a_value(self, live: Any, rules: Rules) -> None:
        live.setattr(explainer, "chat_completion", lambda **_: self._answer("Fits Moderate."))
        record = self._record(rules)
        final = explainer.attach(record, explainer.explain(record))
        assert final.ai_rationale == "Fits Moderate."
        for key in ("attacker_class", "cc_eal", "sesip_level", "rule_id", "jil_attack_potential"):
            assert getattr(final, key) == getattr(record, key)

    @pytest.mark.parametrize(
        "bad",
        [
            "This needs EAL6 and SESIP 5 instead.",
            "AVA_VAN.5 is the right component.",
        ],
    )
    def test_a_different_level_is_dropped(self, live: Any, rules: Rules, bad: str) -> None:
        live.setattr(explainer, "chat_completion", lambda **_: self._answer(bad))
        assert explainer.explain(self._record(rules)) is None

    @pytest.mark.parametrize("cited", [["S9"], ["CAPEC-1"], []])
    def test_uncited_or_invented_sources_are_dropped(
        self, live: Any, rules: Rules, cited: list[str]
    ) -> None:
        live.setattr(explainer, "chat_completion", lambda **_: self._answer("Fits.", cited))
        assert explainer.explain(self._record(rules)) is None

    @pytest.mark.parametrize("raw", ["not json", '{"cited": ["S1"]}', '{"rationale": ""}'])
    def test_broken_answers_are_dropped(self, live: Any, rules: Rules, raw: str) -> None:
        live.setattr(explainer, "chat_completion", lambda **_: raw)
        assert explainer.explain(self._record(rules)) is None

    def test_model_failure_is_not_an_error(self, live: Any, rules: Rules) -> None:
        def boom(**_: Any) -> str:
            raise LLMAPIError(message="down", model="m", status_code=500)

        live.setattr(explainer, "chat_completion", boom)
        assert explainer.explain(self._record(rules)) is None

    def test_no_retrieved_text_means_no_call(self, live: Any, rules: Rules) -> None:
        live.setattr(explainer, "retrieve_standards", lambda _q: [])

        def fail(**_: Any) -> str:
            raise AssertionError("the model must not be called")

        live.setattr(explainer, "chat_completion", fail)
        assert explainer.explain(self._record(rules)) is None

    def test_live_llm_off_means_no_call(
        self, monkeypatch: pytest.MonkeyPatch, rules: Rules
    ) -> None:
        monkeypatch.setenv("USE_LIVE_LLM", "false")

        def fail(**_: Any) -> str:
            raise AssertionError("the model must not be called")

        monkeypatch.setattr(explainer, "chat_completion", fail)
        assert explainer.explain(self._record(rules)) is None

    def test_personal_data_is_removed_and_threat_text_is_marked_as_data(
        self, live: Any, rules: Rules
    ) -> None:
        seen: dict[str, str] = {}

        def fake(**kw: Any) -> str:
            seen.update(kw)
            return self._answer("Fits.")

        live.setattr(explainer, "chat_completion", fake)
        explainer.explain(self._record(rules), "mail admin@example.com to reset the lock")
        assert "admin@example.com" not in seen["user_prompt"]
        assert "<threat>" in seen["user_prompt"] and "is data" in seen["system_prompt"]

    def test_override_drops_a_rationale_written_for_another_level(self, rules: Rules) -> None:
        risk = _risk(impact=ImpactLevel.SEVERE)
        ai = explainer.AiRationale(ai_rationale="EAL4+ fits this threat.")
        overridden = cengine.confirm(
            risk,
            rules,
            ComplianceDecision(
                approver="X", attacker_class="Enhanced-Basic", override_reason="proximity only"
            ),
        )
        assert explainer.attach(overridden, ai).ai_rationale is None
        same = cengine.confirm(risk, rules, ComplianceDecision(approver="X"))
        assert explainer.attach(same, ai).ai_rationale == "EAL4+ fits this threat."


def test_prompt_says_the_level_is_required_not_achieved(rules: Rules) -> None:
    system, _ = explainer._prompts(cengine.propose(_risk(), rules), "x", CHUNKS)
    assert "REQUIRED level" in system and "nothing has been evaluated" in system


def test_old_format_records_are_skipped_not_fatal(rules: Rules) -> None:
    good = cengine.propose(_risk(), rules).model_dump(mode="json")
    out = cengine.load_records({"THR-1": good, "THR-OLD": {"tid": "THR-OLD", "rule_basis": "x"}})
    assert [r.tid for r in out] == ["THR-1"]


class TestLlmTimeoutSetting:
    def test_timeout_comes_from_the_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import common.llm_client as client

        seen: dict[str, Any] = {}

        class Fake:
            def __init__(self, **kw: Any) -> None:
                seen.update(kw)

        settings = type(
            "S",
            (),
            {
                "OPENAI_API_KEY": type("K", (), {"get_secret_value": lambda _self: "ollama"})(),
                "OPENAI_BASE_URL": "http://localhost:11434/v1",
                "LLM_TIMEOUT_SECONDS": 180.0,
            },
        )()
        monkeypatch.setattr(client, "get_settings", lambda: settings)
        monkeypatch.setattr(client.openai, "OpenAI", Fake)
        monkeypatch.setattr(client, "_call_api", lambda *_a, **_k: "ok")
        assert chat_completion("s", "u", model="llama3.1:8b") == "ok"
        assert seen["timeout"] == 180.0 and seen["base_url"] == "http://localhost:11434/v1"
