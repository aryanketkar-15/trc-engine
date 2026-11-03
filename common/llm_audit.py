"""Append-only record of every LLM call: prompts, answer, model and prompt-template version.

The retrieved knowledge-base text the model saw is inside the prompt, so this file shows exactly
what evidence each answer was based on. Text is redacted before it is written, and a logging
problem never breaks the call it describes.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from common.pii_redaction import redact_pii
from config.settings import get_settings

logger = logging.getLogger(__name__)


def record_call(
    *,
    run_id: str,
    model: str,
    prompt_version: str,
    system_prompt: str,
    user_prompt: str,
    response: str | None,
    latency_ms: int,
    error: str | None = None,
) -> None:
    path = getattr(get_settings(), "LLM_AUDIT_PATH", None)
    if not path:
        return
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "model": model,
        "prompt_version": prompt_version,
        "latency_ms": latency_ms,
        "system_prompt": redact_pii(system_prompt),
        "user_prompt": redact_pii(user_prompt),
        "response": redact_pii(response) if response else None,
        "error": error,
    }
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("could not write the LLM audit log: %s", exc)
