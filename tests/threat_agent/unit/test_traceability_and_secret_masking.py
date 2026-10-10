"""Traceability stamping, retrieval logging inputs and secret masking."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agents.threat_agent.orchestrator import generate_and_validate_with_retry
from agents.threat_agent.schemas import ThreatAgentInput
from agents.threat_agent.validator import Validator
from common.pii_redaction import redact_pii, redact_pii_with_count
from tests.threat_agent.unit.test_grounding_and_subset_retry import _ok, _path, _sc

_FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "e2e" / "fixtures" / "smart_door_lock" / "input.json"
)


@pytest.fixture()
def agent_input() -> ThreatAgentInput:
    return ThreatAgentInput(**json.loads(_FIXTURE.read_text(encoding="utf-8")))


def _run(agent_input: ThreatAgentInput):
    gen = MagicMock(return_value=[_sc("AAAA1111")])
    val = MagicMock(spec=Validator)
    val.validate.return_value = _ok()
    with (
        patch("agents.threat_agent.orchestrator.generate_scenarios", gen),
        patch("agents.threat_agent.orchestrator.log_step"),
    ):
        return generate_and_validate_with_retry(
            agent_input, paths=[_path("AAAA1111")], validator=val
        )[0]


class TestTraceability:
    def test_scenarios_carry_use_case_asset_version_and_kb_snapshot(
        self, agent_input: ThreatAgentInput
    ) -> None:
        sc = _run(agent_input)[0]
        assert sc.use_case_id and sc.use_case_id.startswith("UC-")
        assert sc.asset_version == "1.0"
        assert sc.kb_snapshot_version == agent_input.kb_snapshot_version

    def test_explicit_use_case_id_is_kept(self, agent_input: ThreatAgentInput) -> None:
        explicit = agent_input.model_copy(update={"use_case_id": "UC-LOCK-7"})
        assert _run(explicit)[0].use_case_id == "UC-LOCK-7"

    def test_derived_use_case_id_is_stable(self, agent_input: ThreatAgentInput) -> None:
        assert _run(agent_input)[0].use_case_id == _run(agent_input)[0].use_case_id


class TestSecretMasking:
    @pytest.mark.parametrize(
        "text",
        [
            "api_key=abcd1234efgh",
            "password: hunter22",
            "Authorization: Bearer abcdefghijkl123456",
            "key gsk_abcdefghijklmnopqrstuvwx1234",
            "AKIAABCDEFGHIJKLMNOP",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----",
            "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefghijklmnop",
        ],
    )
    def test_secret_values_are_masked(self, text: str) -> None:
        out, count = redact_pii_with_count(text)
        assert "[REDACTED_SECRET]" in out and count >= 1
        assert "hunter22" not in out and "abcd1234efgh" not in out

    def test_descriptive_text_without_a_value_is_untouched(self) -> None:
        text = "The lock uses a hard-coded password and a static API key in firmware."
        assert redact_pii(text) == text

    def test_name_of_the_setting_is_kept(self) -> None:
        assert redact_pii("token=abcdef123456") == "token=[REDACTED_SECRET]"


class TestConnectionRetry:
    def test_dropped_connection_is_retried_then_succeeds(self) -> None:
        import httpx
        import openai

        from common import llm_client

        req = httpx.Request("POST", "https://example.invalid/v1/chat/completions")
        calls = {"n": 0}

        def flaky(*_a: object, **_k: object) -> str:
            calls["n"] += 1
            if calls["n"] < 3:
                raise openai.APIConnectionError(request=req)
            return "ok"

        with (
            patch.object(llm_client, "_call_api", side_effect=flaky),
            patch.object(llm_client.time, "sleep"),
        ):
            out = llm_client.chat_completion("s", "u", model="m", run_id="R", prompt_version="v")
        assert out == "ok" and calls["n"] == 3

    def test_rate_limit_waits_out_the_limit_instead_of_failing(self) -> None:
        import httpx
        import openai

        from common import llm_client

        resp = httpx.Response(
            429, headers={"retry-after": "7"},
            request=httpx.Request("POST", "https://example.invalid/x"),
        )
        calls = {"n": 0}

        def throttled(*_a: object, **_k: object) -> str:
            calls["n"] += 1
            if calls["n"] <= 5:  # more than the 3 ordinary attempts
                raise openai.RateLimitError("slow down", response=resp, body=None)
            return "ok"

        with (
            patch.object(llm_client, "_call_api", side_effect=throttled),
            patch.object(llm_client.time, "sleep") as sleep,
        ):
            out = llm_client.chat_completion("s", "u", model="m", run_id="R", prompt_version="v")
        assert out == "ok" and calls["n"] == 6
        assert all(c.args[0] == 7.0 for c in sleep.call_args_list)
