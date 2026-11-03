"""Tamper evidence for the shared state: hash-chained audit log and content digests.

Each audit entry stores the hash of the previous one, so changing, removing or reordering an entry
breaks every hash after it. With ``AUDIT_HMAC_KEY`` set the hashes are keyed, so someone who can
edit the file but does not hold the key cannot recompute them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from scrp.schemas import AuditLogEntry


def canonical(obj: Any) -> bytes:  # noqa: ANN401
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def digest(obj: Any, key: str | None = None) -> str:  # noqa: ANN401
    data = canonical(obj)
    if key:
        return hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _entry_hash(entry: AuditLogEntry, key: str | None) -> str:
    return digest(entry.model_dump(mode="json", exclude={"entry_hash"}), key)


def seal(entries: list[AuditLogEntry], actor: str, key: str | None) -> None:
    """Give every new entry its actor and its place in the chain. Sealed entries are not touched."""
    previous: str | None = None
    for entry in entries:
        if entry.entry_hash is None:
            entry.actor = entry.actor or actor
            entry.prev_hash = previous
            entry.entry_hash = _entry_hash(entry, key)
        previous = entry.entry_hash


def verify_chain(entries: list[AuditLogEntry], key: str | None) -> dict[str, Any]:
    """Recompute the chain. ``broken_at`` is the index of the first entry that does not match."""
    previous: str | None = None
    unsealed = 0
    for index, entry in enumerate(entries):
        if entry.entry_hash is None:
            unsealed += 1
            continue
        if entry.prev_hash != previous or entry.entry_hash != _entry_hash(entry, key):
            return {
                "ok": False,
                "entries": len(entries),
                "unsealed": unsealed,
                "broken_at": index,
                "tid": entry.tid,
            }
        previous = entry.entry_hash
    return {"ok": True, "entries": len(entries), "unsealed": unsealed, "broken_at": None}


def field_diff(
    old: dict[str, Any], new: dict[str, Any], ignore: frozenset[str] = frozenset()
) -> list[dict[str, Any]]:
    """Field-by-field difference between two records, for a human to review before merging."""
    changes = []
    for field in sorted((old.keys() | new.keys()) - ignore):
        if old.get(field) != new.get(field):
            changes.append({"field": field, "current": old.get(field), "proposed": new.get(field)})
    return changes


_THREAT_FIELDS = ("stride_category", "attack_vector", "evidence_chain", "confidence_score")


def diff_threats(current: list[dict[str, Any]], proposed: list[dict[str, Any]]) -> dict[str, Any]:
    """Added, removed and changed threats, matched by asset and catalogue reference."""

    def key(threat: dict[str, Any]) -> tuple[Any, Any]:
        return threat.get("asset_id"), threat.get("kb_reference")

    def summary(threat: dict[str, Any]) -> dict[str, Any]:
        return {
            "tid": threat.get("tid"),
            "asset_id": threat.get("asset_id"),
            "kb_reference": threat.get("kb_reference"),
            "attack_vector": threat.get("attack_vector"),
        }

    old = {key(t): t for t in current}
    new = {key(t): t for t in proposed}
    changed = []
    for shared in sorted(old.keys() & new.keys(), key=str):
        before = {f: old[shared].get(f) for f in _THREAT_FIELDS}
        after = {f: new[shared].get(f) for f in _THREAT_FIELDS}
        diff = field_diff(before, after)
        if diff:
            changed.append(
                {**summary(new[shared]), "replaces": old[shared].get("tid"), "diff": diff}
            )
    return {
        "added": [summary(new[k]) for k in sorted(new.keys() - old.keys(), key=str)],
        "removed": [summary(old[k]) for k in sorted(old.keys() - new.keys(), key=str)],
        "changed": changed,
        "unchanged": len(old.keys() & new.keys()) - len(changed),
    }
