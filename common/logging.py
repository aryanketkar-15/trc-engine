"""common/logging.py
==============================================================================
TRC Engine -- Phase 1  |  Structured JSON Logging Helper (Day-2)
------------------------------------------------------------------------------
Single shared logging helper used by every module in the pipeline.
Implements the §2.9 structured log format — one JSON object per line:

    {
        "timestamp": "2026-08-14T17:26:30.123456+00:00",
        "level":     "INFO",
        "logger":    "agents.threat_agent.attack_chain",
        "step":      "chain_start",
        "run_id":    "RUN-001",
        "payload":   {"candidate_count": 12}
    }

Fields added automatically by TRCJsonFormatter (never pass these):
    timestamp, level, logger

Fields passed by the caller via log_step():
    step, run_id, payload

Security — automatic redaction:
    Any payload key whose name contains "key", "token", or "secret"
    (case-insensitive) is replaced with "***REDACTED***" before emission.
    This prevents accidental credential leakage in log pipelines.

Stdlib only — no third-party dependencies.

Usage
─────
    from common.logging import get_logger, log_step

    logger = get_logger(__name__)
    log_step(logger, "INFO", "chain_start", run_id, {"candidate_count": 12})

Smoke test (run from repo root):
    python -c "
    from common.logging import get_logger, log_step
    lg = get_logger('smoke.test')
    log_step(lg, 'INFO', 'chain_start', 'RUN-001', {'candidate_count': 12})
    "
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import UTC, datetime
from typing import Any

# ── Redaction ─────────────────────────────────────────────────────────────────

_REDACT_SUBSTRINGS: frozenset[str] = frozenset({"key", "token", "secret"})
_REDACTED_VALUE = "***REDACTED***"


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of *payload* with sensitive values replaced.

    A key is considered sensitive if its lowercase representation contains
    any of the substrings in _REDACT_SUBSTRINGS ("key", "token", "secret").
    Only top-level keys are checked — nested dicts are not recursed into
    (by design: callers must not pass nested secrets in the first place).

    Args:
        payload: Arbitrary key-value dict to redact.

    Returns:
        New dict with sensitive values replaced by ``_REDACTED_VALUE``.
    """
    return {
        k: _REDACTED_VALUE if any(s in k.lower() for s in _REDACT_SUBSTRINGS) else v
        for k, v in payload.items()
    }


# ── Formatter ─────────────────────────────────────────────────────────────────


class TRCJsonFormatter(logging.Formatter):
    """Emit one JSON object per log record in the §2.9 format.

    Automatically injects:
        timestamp  — UTC ISO-8601 with microseconds
        level      — Python level name (INFO / WARNING / ERROR / etc.)
        logger     — logger.name (usually ``__name__`` of the calling module)

    Extra fields (step, run_id, payload) must be supplied via LogRecord.extra,
    which log_step() sets automatically.  Direct logger calls that omit extra
    will still emit valid JSON — step and run_id default to empty strings,
    payload to {}.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Serialise *record* to a single-line JSON string.

        Args:
            record: The LogRecord produced by a logging call.

        Returns:
            A single JSON line with no trailing newline.
        """
        step: str = getattr(record, "step", "")
        run_id: str = getattr(record, "run_id", "")
        raw_payload: dict[str, Any] = getattr(record, "payload", {}) or {}

        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "step": step,
            "run_id": run_id,
            "payload": _redact_payload(raw_payload),
        }

        # Append exception info when present (e.g. logger.exception() calls)
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str)


# ── Handler / Logger factory ───────────────────────────────────────────────────

_configured_loggers: set[str] = set()


def get_logger(name: str) -> logging.Logger:
    """Return a logger with TRCJsonFormatter attached exactly once.

    Idempotent — calling get_logger("foo") multiple times returns the same
    Logger instance with the handler added only on the first call, preventing
    duplicate log lines when modules are imported repeatedly in tests.

    Args:
        name: Logger name, typically ``__name__`` of the calling module.
              e.g. "agents.threat_agent.attack_chain"

    Returns:
        A ``logging.Logger`` configured with a StreamHandler that emits
        structured JSON to stderr.

    Example::

        from common.logging import get_logger
        logger = get_logger(__name__)
        logger.info("plain message — avoid; prefer log_step()")
    """
    logger = logging.getLogger(name)

    if name not in _configured_loggers:
        handler = logging.StreamHandler()
        handler.setFormatter(TRCJsonFormatter())
        logger.addHandler(handler)
        # Propagate=False prevents double-emission if the root logger also
        # has handlers (common in test environments with caplog).
        logger.propagate = False
        _configured_loggers.add(name)

    return logger


# ── Public step-logging API ────────────────────────────────────────────────────


def log_step(
    logger: logging.Logger,
    level: str,
    step: str,
    run_id: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Emit a structured §2.9 log entry at the specified level.

    This is the **only** logging API that pipeline modules should use.
    Direct calls to logger.info() / logger.debug() are permitted for
    ad-hoc debugging but must not be used for pipeline audit events.

    Args:
        logger:  A Logger obtained from get_logger().
        level:   Logging level string — "DEBUG", "INFO", "WARNING",
                 "ERROR", or "CRITICAL".  Case-insensitive.
        step:    Machine-readable step identifier, e.g. "chain_start",
                 "llm_call", "validate_begin", "scrs_write".  This is
                 the ONLY step-identifier field — do not add an "event"
                 key to payload; it will be ignored by downstream queries.
        run_id:  The ThreatAgent run identifier propagated through the
                 pipeline from ThreatAgentInput.run_id.
        payload: Optional dict of structured metadata specific to this
                 step.  Keys containing "key" / "token" / "secret"
                 (case-insensitive) are automatically redacted.

    Returns:
        None

    Example::

        from common.logging import get_logger, log_step

        logger = get_logger(__name__)
        log_step(logger, "INFO", "chain_start", run_id, {"candidate_count": 12})
        # emits:
        # {"timestamp": "...", "level": "INFO",
        #  "logger": "agents.threat_agent.attack_chain",
        #  "step": "chain_start", "run_id": "RUN-001",
        #  "payload": {"candidate_count": 12}}
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.log(
        numeric_level,
        step,  # msg field — not surfaced in JSON output, but required by logging API
        extra={
            "step": step,
            "run_id": run_id,
            "payload": payload or {},
        },
    )
