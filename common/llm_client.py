"""common/llm_client.py
==============================================================================
TRC Engine -- Phase 1  |  OpenAI LLM Client (Day-2)
------------------------------------------------------------------------------
Thin, hardened wrapper around the OpenAI chat completions API.
Implements the three §2.8 hardening requirements:

    1. Request timeout       — configurable, raises LLMTimeoutError on expiry.
    2. Retry with backoff    — exponential backoff on transient 429 / 5xx.
    3. Per-run cost ceiling  — future hook (tracked as TODO Week 2).

Design constraints
──────────────────
    • API key pulled exclusively from get_settings().OPENAI_API_KEY
      (SecretStr) — never hardcoded, never logged.
    • log_step() from common.logging used for "llm_call" audit events.
      Payload contains model + prompt_version only — NEVER prompt text
      or response content (these can contain PII / sensitive context).
    • Typed exceptions (LLMTimeoutError, LLMAPIError) importable by callers
      so router.py and generator.py can catch specific failure modes.
    • stdlib + openai only — no additional dependencies.

Usage
─────
    from common.llm_client import chat_completion

    text = chat_completion(
        system_prompt="You are a threat modelling expert.",
        user_prompt="Analyse this asset...",
        model="gpt-4o",
        prompt_version="v1.2",
        run_id="RUN-001",
    )
"""

from __future__ import annotations

import time
from typing import Any

import openai

from common.logging import get_logger, log_step
from config.settings import get_settings

logger = get_logger(__name__)

# ── Typed exception hierarchy ─────────────────────────────────────────────────


class LLMClientError(Exception):
    """Base class for all LLM client exceptions.

    Catch this to handle any LLM failure generically; catch a subclass
    for specific handling (timeout vs. API error).
    """


class LLMTimeoutError(LLMClientError):
    """Raised when the OpenAI API does not respond within the timeout window.

    Distinct from LLMAPIError so callers can apply different retry policies:
    timeouts may warrant a longer backoff than rate-limit errors.

    Attributes:
        timeout_seconds: The timeout that was exceeded.
        model: The model that was being called.
    """

    def __init__(self, timeout_seconds: float, model: str) -> None:
        self.timeout_seconds = timeout_seconds
        self.model = model
        super().__init__(
            f"OpenAI request to model '{model}' timed out after "
            f"{timeout_seconds}s.  Check network connectivity and consider "
            "increasing OPENAI_REQUEST_TIMEOUT_SECONDS."
        )


class LLMAPIError(LLMClientError):
    """Raised when OpenAI returns a non-transient API error.

    Transient errors (429, 500, 503) are retried internally before this
    is raised.  This exception surfaces only when retries are exhausted
    or the error is clearly non-transient (e.g. 400 invalid request,
    401 invalid key, 404 model not found).

    Attributes:
        status_code: HTTP status code from the API response (if available).
        openai_error: The underlying openai.APIError instance.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        openai_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.openai_error = openai_error
        super().__init__(message)


# ── Internal constants ────────────────────────────────────────────────────────

_DEFAULT_MODEL = "gpt-4o"
_DEFAULT_TIMEOUT_SECONDS = 30.0
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 1.0  # doubles on each retry: 1s, 2s, 4s

# HTTP status codes that warrant a retry (transient failures)
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})


# ── Public API ────────────────────────────────────────────────────────────────


def chat_completion(
    system_prompt: str,
    user_prompt: str,
    model: str | None = None,
    prompt_version: str = "unversioned",
    run_id: str = "",
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Call OpenAI chat completions and return the raw text response.

    Retries up to _MAX_ATTEMPTS times with exponential backoff on transient
    failures (429, 5xx).  Raises typed exceptions on timeout or exhausted
    retries.

    Args:
        system_prompt:   The system-role message content.
        user_prompt:     The user-role message content.
        model:           OpenAI model identifier.  Defaults to "gpt-4o".
                         Pass None to use the default.
        prompt_version:  Optional version tag for the prompt template, e.g.
                         "v1.2".  Logged in the audit event for reproducibility
                         (§2.7) — never contains prompt text itself.
        run_id:          The current ThreatAgent run_id, propagated for audit
                         log correlation.
        timeout_seconds: Per-request wall-clock timeout.  Raises
                         LLMTimeoutError if exceeded.

    Returns:
        Raw text content of the first choice's message.

    Raises:
        LLMTimeoutError: Request exceeded *timeout_seconds*.
        LLMAPIError:     API returned a non-transient error, or all retry
                         attempts were exhausted on transient errors.

    Note:
        The API key is read from settings and passed directly to the OpenAI
        client.  It is never logged — log_step() payload contains only
        model and prompt_version.
    """
    resolved_model = model or _DEFAULT_MODEL
    settings = get_settings()
    # SecretStr.get_secret_value() — only call site; never stored in a var
    # that could be logged or serialised.
    client = openai.OpenAI(
        api_key=settings.OPENAI_API_KEY.get_secret_value(),
        timeout=timeout_seconds,
    )

    log_step(
        logger,
        "INFO",
        "llm_call_start",
        run_id,
        {"model": resolved_model, "prompt_version": prompt_version},
    )

    last_exc: Exception | None = None

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            response = _call_api(client, resolved_model, system_prompt, user_prompt)

            log_step(
                logger,
                "INFO",
                "llm_call_complete",
                run_id,
                {
                    "model": resolved_model,
                    "prompt_version": prompt_version,
                    "attempt": attempt,
                },
            )

            return response

        except openai.APITimeoutError as exc:
            log_step(
                logger,
                "WARNING",
                "llm_call_timeout",
                run_id,
                {
                    "model": resolved_model,
                    "attempt": attempt,
                    "timeout_seconds": timeout_seconds,
                },
            )
            raise LLMTimeoutError(
                timeout_seconds=timeout_seconds, model=resolved_model
            ) from exc

        except openai.APIStatusError as exc:
            status_code: int = exc.status_code
            if status_code not in _RETRYABLE_STATUS_CODES or attempt == _MAX_ATTEMPTS:
                log_step(
                    logger,
                    "ERROR",
                    "llm_call_failed",
                    run_id,
                    {
                        "model": resolved_model,
                        "attempt": attempt,
                        "status_code": status_code,
                    },
                )
                raise LLMAPIError(
                    message=(
                        f"OpenAI API error (HTTP {status_code}) on model "
                        f"'{resolved_model}' after {attempt} attempt(s): {exc}"
                    ),
                    status_code=status_code,
                    openai_error=exc,
                ) from exc

            # Transient — back off and retry
            backoff = _BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            log_step(
                logger,
                "WARNING",
                "llm_call_retry",
                run_id,
                {
                    "model": resolved_model,
                    "attempt": attempt,
                    "status_code": status_code,
                    "backoff_seconds": backoff,
                },
            )
            last_exc = exc
            time.sleep(backoff)

        except openai.APIError as exc:
            # Non-status API errors (connection error, malformed response, etc.)
            log_step(
                logger,
                "ERROR",
                "llm_call_failed",
                run_id,
                {
                    "model": resolved_model,
                    "attempt": attempt,
                    "error": type(exc).__name__,
                },
            )
            raise LLMAPIError(
                message=(
                    f"OpenAI API error on model '{resolved_model}' "
                    f"after {attempt} attempt(s): {exc}"
                ),
                openai_error=exc,
            ) from exc

    # Should not be reachable — the loop always raises or returns.
    # Included for type-checker completeness.
    raise LLMAPIError(  # pragma: no cover
        message=(
            f"All {_MAX_ATTEMPTS} attempts exhausted for model '{resolved_model}'."
        ),
        openai_error=last_exc,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _call_api(
    client: openai.OpenAI,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    """Execute the raw OpenAI chat completions call.

    Extracted into its own function so tests can mock it cleanly without
    patching the full chat_completion() retry logic.

    Args:
        client:        Configured openai.OpenAI instance.
        model:         Model identifier string.
        system_prompt: System-role message content.
        user_prompt:   User-role message content.

    Returns:
        Raw text of the first choice's message content.

    Raises:
        openai.APIError subclasses — callers handle these.
        ValueError: If the API returns an empty or null content field.
    """
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    completion = client.chat.completions.create(model=model, messages=messages)
    content = completion.choices[0].message.content
    if not content:
        raise ValueError(
            f"OpenAI returned empty content for model '{model}'.  "
            "This may indicate a content-filter refusal or a malformed response."
        )
    return content
