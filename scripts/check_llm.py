"""Check that the configured LLM answers, and how fast. Works for hosted models and for Ollama.

python scripts/check_llm.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.llm_client import LLMClientError, chat_completion
from config.settings import get_settings

_SYSTEM = 'Answer with JSON only, in exactly this shape: {"status": "ok", "colour": "<one word>"}.'
_USER = "Name one colour."


def main() -> int:
    settings = get_settings()
    print(f"Endpoint : {settings.OPENAI_BASE_URL or 'default for the API key'}")
    print(f"Model    : {settings.OPENAI_MODEL}")
    print(f"Timeout  : {settings.LLM_TIMEOUT_SECONDS} s per call")
    if not settings.USE_LIVE_LLM:
        print("USE_LIVE_LLM is false: the agents will not call this model. Set it to true.")
    started = time.perf_counter()
    try:
        raw = chat_completion(
            system_prompt=_SYSTEM,
            user_prompt=_USER,
            model=settings.OPENAI_MODEL,
            prompt_version="check-llm",
            run_id="check-llm",
            max_tokens=60,
        )
    except LLMClientError as exc:
        print(f"FAILED: {exc}")
        return 1
    seconds = time.perf_counter() - started
    print(f"Answer   : {raw.strip()[:120]}")
    print(f"Time     : {seconds:.1f} s (the first call to a local model also loads it)")
    try:
        json.loads(raw.strip().strip("`").removeprefix("json").strip())
        print("JSON     : ok")
    except ValueError:
        print("JSON     : not clean JSON. The agents retry, but expect more fallbacks.")
    print("RESULT   : the LLM is reachable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
