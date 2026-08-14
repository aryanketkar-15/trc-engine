"""
common/logging.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Shared Structured Logger  (Aryan branch stub)
──────────────────────────────────────────────────────────────────────────────
STUB for Aryan's branch — mirrors the interface Manthan implemented in
feature/threat-agent-api-tests so attack_chain.py and retrieval.py
can import ``get_logger`` and ``log_step`` without depending on his branch.

When feature/threat-agent-api-tests merges to develop, this file is DELETED
and replaced by Manthan's real implementation.  No other change needed in
attack_chain.py or retrieval.py — same import, same call signature.

Interface contract (must match Manthan's implementation exactly):
    get_logger(name: str) -> logging.Logger
    log_step(logger, level, step, run_id, payload) -> None

Agreed JSON log shape (from Aryan's team message, 14-Aug-2026):
    {"timestamp": "...", "level": "INFO", "logger": "...",
     "step": "chain_start", "run_id": "...", "payload": {...}}
"""

from __future__ import annotations

import json
import logging
from typing import Any


def get_logger(name: str) -> logging.Logger:
    """Return a standard library logger configured for structured JSON output.

    Args:
        name: Logger name — callers pass ``__name__``.

    Returns:
        A ``logging.Logger`` instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_step(
    logger: logging.Logger,
    level: str,
    step: str,
    run_id: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Emit one structured JSON log line for a SCRP pipeline step.

    Args:
        logger:  Logger returned by ``get_logger()``.
        level:   Log level string — "INFO", "WARNING", or "ERROR".
        step:    Canonical step name (e.g. "chain_start", "fetch_end").
        run_id:  ThreatAgent run identifier for log correlation.
        payload: Step-specific fields (never include prompt text or secrets).
    """
    record = {
        "step": step,
        "run_id": run_id,
        "payload": payload or {},
    }
    getattr(logger, level.lower())(json.dumps(record))
