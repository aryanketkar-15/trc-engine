"""Get the JSON out of a model's answer, whatever it wraps around it.

Hosted models usually answer with bare JSON. Local models (Ollama) often add a Markdown fence, a
sentence before or after it, or, for "thinking" models, a ``<think>...</think>`` block first.
The agents ask for JSON only; this removes the wrapping and nothing else, so a damaged answer
still fails to parse and the agent's own fallback or retry handles it.
"""

from __future__ import annotations

import re

_THINK_CLOSED = re.compile(r"<think(?:ing)?>.*?</think(?:ing)?>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN = re.compile(r"^\s*<think(?:ing)?>.*", re.DOTALL | re.IGNORECASE)
_FENCE = re.compile(r"^```[A-Za-z0-9_-]*\s*\n?(.*?)\n?```\s*$", re.DOTALL)


def _balanced_slice(text: str) -> str:
    """From the first ``{`` or ``[`` to its matching closer, ignoring brackets inside strings."""
    starts = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not starts:
        return text
    begin = min(starts)
    depth = 0
    in_string = False
    escaped = False
    for index in range(begin, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
        elif char in "}]":
            depth -= 1
            if depth == 0:
                return text[begin : index + 1]
    return text[begin:]


def extract_json_text(raw: str) -> str:
    """The JSON part of a model answer: no thinking block, no code fence, no surrounding prose."""
    text = _THINK_CLOSED.sub("", raw or "").strip()
    if _THINK_OPEN.match(text):  # an unfinished thinking block means there is no answer in it
        return ""
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    if text[:1] in ("{", "[") and text[-1:] in ("}", "]"):
        return text
    return _balanced_slice(text).strip()
