"""Deterministic, domain-aware reranking of KB candidates.

Why: with the full MITRE catalogues loaded, plain cosine similarity lets
hardware-design weaknesses crowd into results for software/network assets.
Each KB entry carries ``domain_tags`` (keyword rules in ``common/domain_tags``)
and each asset gets tags from the same rules, so:

    score = cosine + tag_boost * min(|asset_tags & pattern_tags|, 2)
                   - hardware_penalty   (pattern tagged 'hardware' but the asset
                                         has no hardware/firmware/physical tag)

Pure function, no model call.  Inactive on a KB without tags, so the 24-entry
baseline behaves exactly as before.  The weights are chosen on the dev split of
``retrieval_eval_fullkb.json`` only (see docs/research/full_kb_retrieval_results.md).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from agents.threat_agent.schemas import AssetModel
from common.domain_tags import tags_for_text

_HARDWARE_ASSET_TAGS = frozenset({"hardware", "firmware", "physical"})


@dataclass(frozen=True)
class RerankParams:
    tag_boost: float = 0.0
    hardware_penalty: float = 0.0
    max_overlap: int = 2

    @property
    def is_noop(self) -> bool:
        return self.tag_boost == 0.0 and self.hardware_penalty == 0.0


def infer_asset_tags(asset: AssetModel) -> frozenset[str]:
    """Domain tags for an asset from its name, type, location, interfaces and config."""
    parts: list[str] = [asset.name, asset.asset_type, asset.location, *asset.dfd_context.interfaces]
    for key, value in asset.device_config.items():
        parts.extend((key.replace("_", " "), value))
    return tags_for_text(" ".join(parts))


def rerank_score(
    similarity: float,
    asset_tags: Iterable[str],
    pattern_tags: Iterable[str],
    params: RerankParams,
) -> float:
    """Adjusted ranking score for one candidate (similarity is raw cosine)."""
    a, p = frozenset(asset_tags), frozenset(pattern_tags)
    score = similarity + params.tag_boost * min(len(a & p), params.max_overlap)
    if "hardware" in p and not (a & _HARDWARE_ASSET_TAGS):
        score -= params.hardware_penalty
    return score


# STRIDE types implied by each security attribute the asset must protect
# (company document 2.4: C/I/A/Authenticity).  Deterministic, no model.
_STRIDE_FOR_ATTRIBUTE: tuple[tuple[str, str], ...] = (
    ("authenticity", "Spoofing"),
    ("integrity", "Tampering"),
    ("confidentiality", "InformationDisclosure"),
    ("availability", "DenialOfService"),
)


def implied_stride(asset: AssetModel) -> list[str]:
    """STRIDE categories an asset's required security attributes make applicable."""
    attrs = asset.security_attributes
    return [cat for attr, cat in _STRIDE_FOR_ATTRIBUTE if getattr(attrs, attr, False)]


@dataclass(frozen=True)
class Cand:
    """Minimal candidate view used for selection (pattern id, cosine, tags, STRIDE hint)."""

    pid: str
    sim: float
    tags: tuple[str, ...] = ()
    stride: str | None = None


def select_top(
    cands: Sequence[Cand],
    asset_tags: Iterable[str],
    params: RerankParams,
    categories: Sequence[str],
    slots: int,
    k: int,
) -> list[str]:
    """Pick the top-k pattern ids, guaranteeing STRIDE coverage.

    Candidates are scored with ``rerank_score``.  When ``slots`` > 0, the best
    ``slots`` candidates for each implied STRIDE category are reserved first
    (round-robin, so every category gets its best match before any gets a
    second), then the remaining places are filled by score.  The result is
    ordered by score.
    """
    a_tags = frozenset(asset_tags)
    score = {c.pid: rerank_score(c.sim, a_tags, c.tags, params) for c in cands}
    ordered = sorted(cands, key=lambda c: score[c.pid], reverse=True)
    chosen: list[str] = []
    if slots > 0 and categories:
        per_cat = {cat: [c for c in ordered if c.stride == cat][:slots] for cat in categories}
        for rank in range(slots):
            for cat in categories:
                if rank < len(per_cat[cat]) and len(chosen) < k:
                    pid = per_cat[cat][rank].pid
                    if pid not in chosen:
                        chosen.append(pid)
    for c in ordered:
        if len(chosen) >= k:
            break
        if c.pid not in chosen:
            chosen.append(c.pid)
    return sorted(chosen, key=lambda pid: score[pid], reverse=True)
