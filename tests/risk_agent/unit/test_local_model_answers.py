"""Answers shaped the way local models (Ollama) really write them, end to end over HTTP.

A fake server speaks the OpenAI chat protocol, so the real client, the real parser and the real
Risk Agent fallback are all exercised without a GPU. The modes mirror what Llama, Qwen and
DeepSeek do in practice: bare JSON, a Markdown fence, a thinking block, chatty prose around the
JSON, and an answer that is not JSON at all.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from agents.risk_agent import suggester
from agents.risk_agent.engine import Ratings
from agents.risk_agent.schemas import ImpactLevel
from common.llm_json import extract_json_text
from config.settings import get_settings
from tests.risk_agent.unit.test_risk_engine import _threat

# --- extract_json_text ------------------------------------------------------------------------

BARE = '{"a": 1, "b": [1, 2]}'


@pytest.mark.parametrize(
    "raw",
    [
        BARE,
        f"```json\n{BARE}\n```",
        f"```\n{BARE}\n```",
        f"<think>hmm {{not json}}</think>\n{BARE}",
        f"<thinking>x</thinking>{BARE}",
        f"Sure! Here is the JSON:\n{BARE}\nHope that helps.",
        f"<think>plan</think>\nAnswer:\n```json\n{BARE}\n```\nDone.",
        f"  \n{BARE}\n  ",
    ],
)
def test_every_wrapping_is_removed(raw: str) -> None:
    assert json.loads(extract_json_text(raw)) == {"a": 1, "b": [1, 2]}


def test_braces_inside_strings_do_not_end_the_object_early() -> None:
    raw = 'Here: {"reason": "uses } and { and \\" quotes", "n": 2} trailing'
    assert json.loads(extract_json_text(raw)) == {"reason": 'uses } and { and " quotes', "n": 2}


def test_a_list_answer_is_kept() -> None:
    assert json.loads(extract_json_text('Result: [{"x": 1}] ok')) == [{"x": 1}]


@pytest.mark.parametrize("raw", ["", "no json here", '<think>never finished {"a": 1}', None])
def test_nothing_usable_stays_unparseable(raw: str | None) -> None:
    with pytest.raises(json.JSONDecodeError):
        json.loads(extract_json_text(raw or ""))


def test_a_truncated_answer_is_not_repaired() -> None:
    with pytest.raises(json.JSONDecodeError):
        json.loads(extract_json_text('{"a": 1, "b": '))


# --- a fake Ollama ----------------------------------------------------------------------------


class _Fake(BaseHTTPRequestHandler):
    mode = "plain"
    answer = "{}"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        text = {
            "plain": self.answer,
            "fenced": f"```json\n{self.answer}\n```",
            "think": f"<think>The user wants JSON; I will think.</think>\n{self.answer}",
            "prose": f"Certainly! Here is my proposal:\n{self.answer}\nLet me know if you need more.",
            "garbage": "I am sorry, I cannot do that.",
        }[self.mode]
        body = json.dumps(
            {
                "id": "x",
                "object": "chat.completion",
                "created": 0,
                "model": "fake",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: Any) -> None:  # keep the test output quiet
        pass


@pytest.fixture
def fake_ollama(monkeypatch: pytest.MonkeyPatch):
    server = HTTPServer(("127.0.0.1", 0), _Fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OPENAI_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    monkeypatch.setenv("USE_LIVE_LLM", "true")
    get_settings.cache_clear()
    yield _Fake
    server.shutdown()
    server.server_close()
    get_settings.cache_clear()


def _good_answer(valid: dict[str, list[str]]) -> str:
    return json.dumps(
        {
            "impact": {
                "safety": None,
                "financial": "Moderate",
                "operational": "Severe",
                "privacy": None,
            },
            "feasibility": {k: v[0] for k, v in valid.items()},
            "reason": "Remote and cheap.",
        }
    )


@pytest.mark.parametrize("mode", ["plain", "fenced", "think", "prose"])
def test_risk_agent_uses_the_model_whatever_the_wrapping(fake_ollama, mode: str) -> None:
    valid = {k: list(v) for k, v in Ratings.load().points.items()}
    fake_ollama.mode = mode
    fake_ollama.answer = _good_answer(valid)
    result = suggester.suggest(_threat(), None, valid)
    assert (result.suggestion_basis or "").startswith("LLM suggestion"), mode
    assert result.impact.operational == ImpactLevel.SEVERE


def test_risk_agent_falls_back_when_the_model_does_not_answer_in_json(fake_ollama) -> None:
    valid = {k: list(v) for k, v in Ratings.load().points.items()}
    fake_ollama.mode = "garbage"
    fake_ollama.answer = "{}"
    result = suggester.suggest(_threat(), None, valid)
    assert "rule-based" in (result.suggestion_basis or "")
