"""Detect approved threats that no longer match their upstream data.

The company asked that we can go back one step, change the upstream data (the asset table or
the system model), and re-run what depends on it.  This module answers the first half: *which
approved threat scenarios are now out of date, and why?*

Every scenario is stamped, when it is produced, with
    asset_fingerprint    a short hash of the asset facts the threat was derived from
    context_fingerprint  a short hash of the use-case text and system model it was derived from
Comparing those stamps with the current input gives a deterministic answer (no AI involved).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agents.threat_agent.schemas import AssetModel, ThreatAgentInput, ThreatScenario


def _digest(payload: object) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def asset_fingerprint(asset: AssetModel) -> str:
    """Hash of the facts about an asset that influence its threats."""
    ctx = asset.dfd_context
    return _digest(
        {
            "asset_id": asset.asset_id,
            "name": asset.name,
            "asset_type": asset.asset_type,
            "location": asset.location,
            "security": asset.security_attributes.model_dump(mode="json"),
            "damage": asset.damage_scenario,
            "interfaces": sorted(ctx.interfaces),
            "trust_zone": ctx.trust_zone,
            "data_flows": sorted(ctx.data_flows),
            "config": dict(sorted((asset.device_config or {}).items())),
            "version": asset.version,
        }
    )


def context_fingerprint(use_case: str, system_model: str) -> str:
    """Hash of the use-case description and system model text."""
    return _digest({"use_case": use_case.strip(), "system_model": system_model.strip()})


def use_case_key(agent_input: ThreatAgentInput) -> str:
    """The identifier that groups all runs and results of one use case."""
    return str(
        agent_input.use_case_id
        or "UC-" + hashlib.sha256(agent_input.use_case.encode("utf-8")).hexdigest()[:8].upper()
    )


def traceability_stamp(agent_input: ThreatAgentInput, asset_id: str) -> dict[str, Any]:
    """The traceability fields every scenario of this input carries (AI-made or expert-added)."""
    asset = next((a for a in agent_input.assets if a.asset_id == asset_id), None)
    return {
        "project_id": agent_input.project_id,
        "use_case_id": use_case_key(agent_input),
        "asset_version": asset.version if asset else None,
        "asset_fingerprint": asset_fingerprint(asset) if asset else None,
        "context_fingerprint": context_fingerprint(agent_input.use_case, agent_input.system_model),
        "kb_snapshot_version": agent_input.kb_snapshot_version,
    }


@dataclass(frozen=True)
class StaleItem:
    tid: str
    asset_id: str
    reason: str


@dataclass
class StalenessReport:
    use_case_id: str
    stale: list[StaleItem] = field(default_factory=list)
    fresh_tids: list[str] = field(default_factory=list)
    changed_assets: list[str] = field(default_factory=list)
    removed_assets: list[str] = field(default_factory=list)
    uncovered_assets: list[str] = field(default_factory=list)
    context_changed: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(self.stale)

    @property
    def affected_assets(self) -> list[str]:
        """Assets that need new threats: changed ones plus assets with no approved threat."""
        return sorted(set(self.changed_assets) | set(self.uncovered_assets))

    def summary(self) -> dict[str, Any]:
        return {
            "use_case_id": self.use_case_id,
            "stale": [vars(s) for s in self.stale],
            "fresh": len(self.fresh_tids),
            "changed_assets": self.changed_assets,
            "removed_assets": self.removed_assets,
            "uncovered_assets": self.uncovered_assets,
            "context_changed": self.context_changed,
            "affected_assets": self.affected_assets,
        }


def _as_dict(s: ThreatScenario | dict[str, Any]) -> dict[str, Any]:
    return s.model_dump(mode="json") if isinstance(s, ThreatScenario) else dict(s)


def check_staleness(
    agent_input: ThreatAgentInput,
    approved: Iterable[ThreatScenario | dict[str, Any]],
) -> StalenessReport:
    """Compare approved scenarios of this use case with the current input.

    Only scenarios of the same use case are considered.  A scenario is stale when its asset was
    removed, the asset facts changed, or the use-case/system-model text changed.  Scenarios from
    before fingerprints existed are compared by asset version only.
    """
    key = use_case_key(agent_input)
    assets = {a.asset_id: a for a in agent_input.assets}
    now_ctx = context_fingerprint(agent_input.use_case, agent_input.system_model)
    report = StalenessReport(use_case_id=key)
    changed: set[str] = set()
    removed: set[str] = set()
    covered: set[str] = set()

    for raw in approved:
        s = _as_dict(raw)
        if s.get("use_case_id") != key or s.get("project_id") != agent_input.project_id:
            continue
        tid, aid = str(s["tid"]), str(s["asset_id"])
        asset = assets.get(aid)
        reason: str | None = None
        if asset is None:
            reason = "asset removed from the input"
            removed.add(aid)
        elif s.get("context_fingerprint") and s["context_fingerprint"] != now_ctx:
            reason = "use case or system model changed"
            report.context_changed = True
            changed.add(aid)
        elif s.get("asset_fingerprint"):
            if s["asset_fingerprint"] != asset_fingerprint(asset):
                reason = "asset facts changed"
                changed.add(aid)
        elif s.get("asset_version") and s["asset_version"] != asset.version:
            reason = "asset version changed"
            changed.add(aid)
        if reason:
            report.stale.append(StaleItem(tid=tid, asset_id=aid, reason=reason))
        else:
            report.fresh_tids.append(tid)
            covered.add(aid)

    if report.context_changed:
        # A changed system model can affect every asset of the use case.
        changed |= set(assets)
    report.changed_assets = sorted(a for a in changed if a in assets)
    report.removed_assets = sorted(removed)
    if report.stale or report.fresh_tids:
        report.uncovered_assets = sorted(a for a in assets if a not in covered and a not in changed)
    return report
