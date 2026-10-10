"""Deterministic grounding checks: a scenario may only rest on what retrieval gave it.

The company spec requires every recommendation to cite a KB item and carry its
evidence.  These rules make invented citations impossible (they cannot guarantee
that the *narrative* is technically right, which is why a human still approves):

    CITATION_NOT_RETRIEVED  kb_reference is not one of the patterns on the attack
                            path this scenario was generated from
    ASSET_NOT_IN_INPUT      asset_id is not an asset of the input system model
    CITATION_MISMATCH       citation text / matched_pattern do not agree with kb_reference
    EXPOSURE_NOT_GROUNDED   the exposure shares no meaningful word with the asset's
                            name, type, location, interfaces or configuration

Kept separate from validator.py so the validator's four frozen invariants (and
their measured FAR/FRR) are unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agents.threat_agent.schemas import AssetModel, AttackPath, ThreatScenario

_STOP = frozenset(
    "the and for with that this from into over via are was were not any all can may use "
    "uses used using trust zone interface interfaces device system data".split()
)
_TID_PATH = re.compile(r"^THR-(PATH-[A-Z0-9-]+?)-\d{3}$")


@dataclass(frozen=True)
class GroundingFailure:
    check_id: str
    tid: str
    detail: str


def path_id_from_tid(tid: str) -> str | None:
    """Recover the attack-path id from a generated tid ``THR-PATH-XXXX-001``."""
    m = _TID_PATH.match(tid)
    return m.group(1) if m else None


def _norm(ref: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", ref.upper())


def _ref_matches(a: str, b: str) -> bool:
    """ID equality tolerant of prefixes: 'ATT&CK-T1078' ~ 'T1078' ~ 'ATT&CK T1078'."""
    na, nb = _norm(a), _norm(b)
    return bool(na and nb and (na == nb or na.endswith(nb) or nb.endswith(na)))


def _core(ref: str) -> str:
    """The distinguishing part of an id: 'CAPEC-186' -> '186', 'ATT&CK-T1078' -> 'T1078'."""
    return ref.strip().split("-")[-1].upper()


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) >= 3 and w not in _STOP}


def _asset_vocabulary(asset: AssetModel) -> set[str]:
    parts = [asset.name, asset.asset_type, asset.location, asset.dfd_context.trust_zone,
             *asset.dfd_context.interfaces, *asset.dfd_context.data_flows]
    for key, value in asset.device_config.items():
        parts.extend((key.replace("_", " "), value))
    return _words(" ".join(parts))


def check_grounding(
    scenario: ThreatScenario,
    path: AttackPath | None,
    assets: list[AssetModel],
) -> list[GroundingFailure]:
    """Run all grounding checks on one scenario; empty list means grounded.

    ``path`` is the attack path the scenario came from; when it is unknown the
    path-dependent check is skipped (the others still run).
    """
    fails: list[GroundingFailure] = []
    tid = scenario.tid

    if path is not None and not any(
        _ref_matches(scenario.kb_reference, step.pattern_id) for step in path.steps
    ):
        fails.append(GroundingFailure(
            "CITATION_NOT_RETRIEVED", tid,
            f"kb_reference '{scenario.kb_reference}' is not one of the retrieved patterns "
            f"for this attack path ({', '.join(s.pattern_id for s in path.steps)}). "
            "Cite only a pattern you were given.",
        ))

    by_id = {a.asset_id: a for a in assets}
    asset = by_id.get(scenario.asset_id)
    if assets and asset is None:
        fails.append(GroundingFailure(
            "ASSET_NOT_IN_INPUT", tid,
            f"asset_id '{scenario.asset_id}' is not an asset of the system model "
            f"({', '.join(sorted(by_id))}).",
        ))

    ev = scenario.evidence_chain
    core = _core(scenario.kb_reference)
    citation_has_id = re.search(rf"(?<![A-Z0-9]){re.escape(core)}(?![A-Z0-9])",
                                ev.citation.upper()) is not None
    if not _ref_matches(ev.matched_pattern, scenario.kb_reference) or not citation_has_id:
        fails.append(GroundingFailure(
            "CITATION_MISMATCH", tid,
            f"matched_pattern '{ev.matched_pattern}' and citation must name the same pattern "
            f"as kb_reference '{scenario.kb_reference}'.",
        ))

    if asset is not None:
        vocab = _asset_vocabulary(asset)
        if vocab and not (_words(ev.exposure) & vocab):
            fails.append(GroundingFailure(
                "EXPOSURE_NOT_GROUNDED", tid,
                "exposure must reference a real property of the asset (its interfaces, "
                "configuration or role); it shares no term with the asset description.",
            ))
    return fails
