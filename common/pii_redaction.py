"""common/pii_redaction.py
==============================================================================
TRC Engine -- Phase 1  |  Outbound PII Redaction
------------------------------------------------------------------------------
Detects and masks sensitive Personally Identifiable Information (PII)
before user-supplied free text is forwarded to external LLM providers.

Implements conservative pattern masking for:
    - Email addresses       -> [REDACTED_EMAIL]
    - Phone numbers         -> [REDACTED_PHONE]
    - Government IDs (SSN)  -> [REDACTED_GOV_ID]
    - IPv4 addresses        -> [REDACTED_IP]

Design constraints:
    • Operates exclusively on outbound request payloads before dispatch
      (independent of common/logging.py post-hoc log redaction).
    • Pure Python (stdlib re only).
    • False-positive preference over false-negative: conservative masking
      ensures sensitive data does not exit the security perimeter.
"""

from __future__ import annotations

import re
from typing import Any

# ─── PII Matching Regex Patterns ──────────────────────────────────────────────

# Standard email pattern (conservative, RFC 5322 subset)
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Phone number patterns:
# - North American & international punctuated formats: e.g. 555-123-4567, (555) 123-4567, +1-555-123-4567, +44 20 7123 4567
# - Raw 10-to-12 digit strings: e.g. 5551234567, +15551234567
_PHONE_PATTERN = re.compile(
    r"(?:(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b)|"
    r"(?:\b\+?\d{10,12}\b)"
)

# Government ID / Social Security Number pattern:
# Standard US SSN: 3 digits - 2 digits - 4 digits
_GOV_ID_PATTERN = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b"
)

# IPv4 address pattern (4 octets 0-255 separated by periods)
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Replacement tokens
TOKEN_EMAIL = "[REDACTED_EMAIL]"
TOKEN_PHONE = "[REDACTED_PHONE]"
TOKEN_GOV_ID = "[REDACTED_GOV_ID]"
TOKEN_IP = "[REDACTED_IP]"

_ORDERED_RULES: list[tuple[re.Pattern[str], str]] = [
    (_EMAIL_PATTERN, TOKEN_EMAIL),
    (_GOV_ID_PATTERN, TOKEN_GOV_ID),
    (_PHONE_PATTERN, TOKEN_PHONE),
    (_IPV4_PATTERN, TOKEN_IP),
]


def redact_pii_with_count(text: str) -> tuple[str, int]:
    """Detect and mask PII patterns in *text*, returning sanitized text and match count.

    Args:
        text: Input string potentially containing PII.

    Returns:
        tuple of (sanitized_string, total_redaction_count).
    """
    if not text:
        return text, 0

    sanitized = text
    total_matches = 0

    for pattern, replacement in _ORDERED_RULES:
        sanitized, count = pattern.subn(replacement, sanitized)
        total_matches += count

    return sanitized, total_matches


def redact_pii(text: str) -> str:
    """Mask common PII patterns in *text*.

    Args:
        text: Raw text string.

    Returns:
        String with all detected PII tokens replaced by sentinel masks.
    """
    sanitized, _ = redact_pii_with_count(text)
    return sanitized


def redact_structure(data: Any) -> tuple[Any, int]:
    """Recursively redact string values inside dicts, lists, or primitive values.

    Structured keys (e.g. dict keys, object IDs) are preserved; only free-form
    string values are masked.

    Args:
        data: Arbitrary data structure.

    Returns:
        tuple of (sanitized_data, total_redactions).
    """
    if isinstance(data, str):
        return redact_pii_with_count(data)
    elif isinstance(data, dict):
        total = 0
        new_dict: dict[str, Any] = {}
        for k, v in data.items():
            cleaned_val, count = redact_structure(v)
            new_dict[k] = cleaned_val
            total += count
        return new_dict, total
    elif isinstance(data, (list, tuple)):
        total = 0
        new_list: list[Any] = []
        for item in data:
            cleaned_item, count = redact_structure(item)
            new_list.append(cleaned_item)
            total += count
        return (new_list if isinstance(data, list) else tuple(new_list)), total
    return data, 0
