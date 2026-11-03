"""Multi-step attack chains built from approved threats, for an expert to review.

Each approved threat rests on one catalogue pattern. This module links them with a fixed rule table
(chain_links.json): one threat can enable another in the same asset, or in an asset that shares a
data flow or interface. No LLM is involved, and chains are proposals, never approved results.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_LINKS_PATH = Path(__file__).with_name("chain_links.json")


@lru_cache(maxsize=1)
def _load_links() -> dict[str, Any]:
    return json.loads(_LINKS_PATH.read_text(encoding="utf-8"))


def _connected(a: str, b: str, surfaces: dict[str, set[str]]) -> list[str] | None:
    """How two assets connect: [] for the same asset, shared names, or None if unconnected."""
    if a == b:
        return []
    shared = surfaces.get(a, set()) & surfaces.get(b, set())
    return sorted(shared) if shared else None


def asset_surfaces(assets: list[Any]) -> dict[str, set[str]]:
    """Data flows and interfaces per asset; AssetModel objects with a dfd_context."""
    out: dict[str, set[str]] = {}
    for asset in assets:
        context = asset.dfd_context
        out[asset.asset_id] = {*context.data_flows, *context.interfaces}
    return out


def propose_chains(
    threats: list[dict[str, Any]], assets: list[Any] | None = None
) -> list[dict[str, Any]]:
    """All maximal chains of two or more steps, strongest evidence first."""
    rules = _load_links()
    surfaces = asset_surfaces(assets or [])
    because = {(r["from"], r["to"]): r["because"] for r in rules["links"]}
    ordered = sorted(threats, key=lambda t: str(t["tid"]))

    following: dict[str, list[tuple[dict[str, Any], str, list[str]]]] = {}
    for first in ordered:
        for second in ordered:
            if first["tid"] == second["tid"]:
                continue
            reason = because.get((first["stride_category"], second["stride_category"]))
            via = _connected(first["asset_id"], second["asset_id"], surfaces)
            if reason is not None and via is not None:
                following.setdefault(str(first["tid"]), []).append((second, reason, via))

    results: list[dict[str, Any]] = []

    def walk(path: list[dict[str, Any]], notes: list[dict[str, Any]]) -> None:
        options = [
            o
            for o in following.get(str(path[-1]["tid"]), [])
            if all(o[0]["tid"] != p["tid"] for p in path)
        ]
        if len(path) >= int(rules["max_steps"]) or not options:
            if len(path) >= 2:
                results.append(_chain(path, notes))
            return
        for step, reason, via in options:
            walk([*path, step], [*notes, {"because": reason, "via": via}])

    for start in ordered:
        walk([start], [])

    results = _drop_contained(results)
    results.sort(key=lambda c: (-c["evidence_strength"], c["chain_id"]))
    return results


def _chain(path: list[dict[str, Any]], notes: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [float(t.get("confidence_score") or 0.0) for t in path]
    product = 1.0
    for score in scores:
        product *= score
    return {
        "chain_id": "CHAIN-" + "+".join(str(t["tid"]) for t in path),
        "steps": [
            {
                "tid": t["tid"],
                "asset_id": t["asset_id"],
                "stride": t["stride_category"],
                "attack": t.get("attack_vector", ""),
                "kb_reference": t.get("kb_reference", ""),
            }
            for t in path
        ],
        "links": notes,
        "assets": sorted({str(t["asset_id"]) for t in path}),
        "evidence_strength": round(product ** (1 / len(scores)), 3) if scores else 0.0,
        "status": "proposed",
        "needs_review": True,
    }


def _drop_contained(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove a chain whose steps are the start of a longer one."""
    keys = [tuple(s["tid"] for s in c["steps"]) for c in chains]
    kept = []
    for chain, key in zip(chains, keys, strict=True):
        contained = any(len(o) > len(key) and o[: len(key)] == key for o in keys)
        if not contained:
            kept.append(chain)
    return kept
