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

from collections.abc import Iterable
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
