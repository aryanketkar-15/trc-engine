"""
agents/threat_agent/retrieval.py
════════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  KB Retrieval Layer  (Aryan)
────────────────────────────────────────────────────────────────────────────────
Week 2 real implementation:
  - fetch_candidates() — FAISS IndexFlatIP cosine search, per-query dedup,
    top_k enforcement, score normalisation, and typed error guards.
  - get_kb_entry() — direct KB metadata lookup by pattern_id + source.

Index loading is lazy and cached per process via module-level singletons
(_INDEX, _METADATA) so the FAISS binary is mmapped only once across all
calls in a single ThreatAgent run.

Pipeline position:
    plan() → RetrievalPlan → fetch_candidates() → list[KBCandidate]
                                                        │
                                          attack_chain.build_paths()

STRIDE_VECTOR_VOCABULARY (TRC-STUB-001 resolution):
    Exported for Shriraj's consistency_check in validator.py.
    Expand after each Week 3 KB ingestion pass.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from agents.threat_agent.exceptions import (
    EmptyKBMatchError,
    KBEntryNotFoundError,
    KBStoreUnreachableError,
    MalformedAssetInputError,
)
from agents.threat_agent.schemas import (
    KBCandidate,
    KBSource,
    RetrievalPlan,
    STRIDECategory,
)
from common.logging import get_logger, log_step

logger = get_logger(__name__)

# ─── STRIDE ↔ attack-vector vocabulary (TRC-STUB-001 resolution) ─────────────
# Shriraj's validator loads this at startup for consistency_check().
STRIDE_VECTOR_VOCABULARY: dict[STRIDECategory, frozenset[str]] = {
    STRIDECategory.SPOOFING: frozenset(
        {
            "replay",
            "impersonation",
            "credential theft",
            "identity forgery",
            "session hijack",
            "ble replay",
            "token replay",
            "phishing",
            "arp spoofing",
            "dns spoofing",
        }
    ),
    STRIDECategory.TAMPERING: frozenset(
        {
            "injection",
            "sql injection",
            "command injection",
            "firmware manipulation",
            "man-in-the-middle",
            "data modification",
            "parameter tampering",
            "payload manipulation",
            "code injection",
            "buffer overflow",
        }
    ),
    STRIDECategory.REPUDIATION: frozenset(
        {
            "log deletion",
            "audit bypass",
            "log tampering",
            "evidence removal",
            "non-repudiation bypass",
            "transaction denial",
        }
    ),
    STRIDECategory.INFORMATION_DISCLOSURE: frozenset(
        {
            "eavesdrop",
            "sniffing",
            "side channel",
            "data exfiltration",
            "unencrypted transmission",
            "information leak",
            "memory disclosure",
            "cleartext",
        }
    ),
    STRIDECategory.DENIAL_OF_SERVICE: frozenset(
        {
            "flood",
            "resource exhaustion",
            "crash",
            "amplification",
            "dos",
            "ddos",
            "availability",
            "starvation",
        }
    ),
    STRIDECategory.ELEVATION_OF_PRIVILEGE: frozenset(
        {
            "privilege escalation",
            "path traversal",
            "insecure deserialization",
            "access control bypass",
            "sudo",
            "kernel exploit",
            "role escalation",
        }
    ),
}

# ─── STRIDE hint string → enum ───────────────────────────────────────────────

_STRIDE_STR_MAP: dict[str, STRIDECategory] = {
    "Spoofing": STRIDECategory.SPOOFING,
    "Tampering": STRIDECategory.TAMPERING,
    "Repudiation": STRIDECategory.REPUDIATION,
    "InformationDisclosure": STRIDECategory.INFORMATION_DISCLOSURE,
    "DenialOfService": STRIDECategory.DENIAL_OF_SERVICE,
    "ElevationOfPrivilege": STRIDECategory.ELEVATION_OF_PRIVILEGE,
}

# ─── Default KB paths ────────────────────────────────────────────────────────

_DEFAULT_INDEX_PATH = Path("kb/data/threat_agent.faiss")
_DEFAULT_METADATA_PATH = Path("kb/data/kb_metadata.json")
_DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"

# ─── Module-level lazy singletons (loaded once per process) ─────────────────

_INDEX: Any | None = None  # faiss.IndexFlatIP
_METADATA: dict[str, dict[str, Any]] | None = None  # FAISS id → KBEntry dict
_ENCODER: Any | None = None  # SentenceTransformer


def _import_faiss() -> object:
    try:
        import faiss  # type: ignore[import-untyped]

        return faiss
    except ImportError as err:
        raise KBStoreUnreachableError(
            store_path=str(_DEFAULT_INDEX_PATH),
            cause=ImportError("faiss-cpu is not installed. Run: pip install faiss-cpu"),
        ) from err


def _import_encoder() -> object:
    try:
        from sentence_transformers import SentenceTransformer

        return SentenceTransformer
    except ImportError as err:
        raise KBStoreUnreachableError(
            store_path=str(_DEFAULT_INDEX_PATH),
            cause=ImportError(
                "sentence-transformers is not installed. "
                "Run: pip install sentence-transformers"
            ),
        ) from err


def _get_index(index_path: Path | None = None) -> object:
    """Return the cached FAISS index, loading it on first call."""
    global _INDEX
    if _INDEX is None:
        path = index_path or _DEFAULT_INDEX_PATH
        if not path.exists():
            raise KBStoreUnreachableError(
                store_path=str(path),
                cause=FileNotFoundError(
                    f"FAISS index not found at {path}. "
                    "Run: python -m kb.scripts.build_index"
                ),
            )
        try:
            faiss = _import_faiss()
            _INDEX = faiss.read_index(str(path))  # type: ignore[attr-defined]
        except Exception as exc:
            raise KBStoreUnreachableError(store_path=str(path), cause=exc) from exc
    return _INDEX


def _get_metadata(metadata_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return the cached KB metadata dict, loading it on first call."""
    global _METADATA
    if _METADATA is None:
        path = metadata_path or _DEFAULT_METADATA_PATH
        if not path.exists():
            raise KBStoreUnreachableError(
                store_path=str(path),
                cause=FileNotFoundError(
                    f"KB metadata not found at {path}. "
                    "Run: python -m kb.scripts.build_index"
                ),
            )
        try:
            _METADATA = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise KBStoreUnreachableError(store_path=str(path), cause=exc) from exc
    return _METADATA


def _get_encoder(model_name: str | None = None) -> object:
    """Return the cached SentenceTransformer, loading it on first call."""
    global _ENCODER
    if _ENCODER is None:
        name = model_name or _DEFAULT_MODEL_NAME
        st_cls = _import_encoder()
        _ENCODER = st_cls(name)  # type: ignore[operator]
    return _ENCODER


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _metadata_to_kb_candidate(
    meta: dict[str, Any],
    asset_id: str,
    retrieval_score: float,
) -> KBCandidate:
    """Convert a metadata dict + retrieval context into a KBCandidate.

    Args:
        meta:            Dict from kb_metadata.json for one FAISS vector ID.
        asset_id:        The asset whose query produced this result.
        retrieval_score: Normalised cosine similarity score [0, 1].

    Returns:
        A frozen KBCandidate Pydantic model.
    """
    stride_raw: str | None = meta.get("stride_hint")
    stride_hint = _STRIDE_STR_MAP.get(stride_raw) if stride_raw else None
    return KBCandidate(
        pattern_id=meta["pattern_id"],
        source=KBSource(meta["source"]),
        title=meta["title"],
        description=meta["description"],
        retrieval_score=max(0.0, min(1.0, float(retrieval_score))),
        asset_id=asset_id,
        stride_hint=stride_hint,
        mitre_tactics=list(meta.get("mitre_tactics", [])),
    )


def _cosine_to_score(cosine_similarity: float) -> float:
    """Normalise a cosine similarity value to [0, 1].

    FAISS IndexFlatIP with L2-normalised vectors returns cosine similarities
    in [-1, 1].  We shift and scale to [0, 1] for the retrieval_score field.
    """
    return max(0.0, min(1.0, (float(cosine_similarity) + 1.0) / 2.0))


def _filter_by_sources(
    candidates: list[KBCandidate],
    kb_sources: list[str],
) -> list[KBCandidate]:
    """Filter candidates to only those from the requested KB sources."""
    allowed = {KBSource(s) for s in kb_sources}
    return [c for c in candidates if c.source in allowed]


# ─── Public retrieval interface ───────────────────────────────────────────────


def fetch_candidates(
    plan: RetrievalPlan,
    *,
    index_path: Path | None = None,
    metadata_path: Path | None = None,
    model_name: str | None = None,
) -> list[KBCandidate]:
    """Retrieve ranked KB candidates for all asset queries in the plan.

    Executes each query in ``plan.queries`` against the FAISS index, collects
    results, deduplicates (same pattern_id per asset_id), enforces top_k, and
    returns a flat list sorted by retrieval_score descending.

    Args:
        plan:          RetrievalPlan produced by plan() in the ThreatAgent.
        index_path:    Override for FAISS binary path (default: config value).
        metadata_path: Override for KB metadata JSON path (default: config).
        model_name:    Override for embedding model (default: config value).

    Returns:
        Flat list of KBCandidate objects, sorted by retrieval_score descending.
        Returns ``[]`` if a single query has no matches (not an error).

    Raises:
        KBStoreUnreachableError: If the FAISS index or metadata cannot be
                                 loaded from disk.
        EmptyKBMatchError:       If ALL queries for a given asset_id return
                                 zero candidates — hard failure per §5.
        MalformedAssetInputError: If a query has an empty query_text, which
                                  would produce a degenerate embedding vector.
    """
    import numpy as np  # type: ignore[import-untyped]

    index = _get_index(index_path)
    metadata = _get_metadata(metadata_path)
    encoder = _get_encoder(model_name)

    log_step(
        logger,
        "INFO",
        "fetch_start",
        plan.run_id,
        {"query_count": len(plan.queries), "top_k": plan.top_k},
    )

    # Group queries by asset_id to detect per-asset empty-match failures
    asset_candidates: dict[str, list[KBCandidate]] = {}

    for query in plan.queries:
        asset_id: str = query["asset_id"]  # type: ignore[index]
        query_text: str = query["query_text"]  # type: ignore[index]
        kb_sources: list[str] = query["kb_sources"]  # type: ignore[index]

        if not query_text.strip():
            raise MalformedAssetInputError(
                asset_id=asset_id,
                reason=(
                    f"query_text is empty for asset '{asset_id}'. "
                    "Cannot produce a FAISS embedding vector."
                ),
            )

        # Embed query text and search FAISS
        query_vec: np.ndarray = encoder.encode(  # type: ignore[union-attr]
            [query_text],
            normalize_embeddings=True,
        ).astype(np.float32)

        top_k = plan.top_k if hasattr(plan, "top_k") else 10
        n_results = min(top_k, index.ntotal)  # type: ignore[union-attr]
        distances, ids = index.search(query_vec, n_results)  # type: ignore[union-attr]

        # Convert FAISS results to KBCandidates
        query_candidates: list[KBCandidate] = []
        for dist, vid in zip(distances[0], ids[0], strict=False):
            if vid == -1:  # FAISS sentinel for "no result"
                continue
            meta = metadata.get(str(vid))
            if meta is None:
                continue
            candidate = _metadata_to_kb_candidate(
                meta=meta,
                asset_id=asset_id,
                retrieval_score=_cosine_to_score(dist),
            )
            query_candidates.append(candidate)

        # Filter to requested KB sources only
        if kb_sources:
            query_candidates = _filter_by_sources(query_candidates, kb_sources)

        asset_candidates.setdefault(asset_id, [])
        asset_candidates[asset_id].extend(query_candidates)

    # Per-asset deduplication and empty-match guard
    seen: dict[str, set[str]] = {}  # asset_id → set of pattern_ids seen
    final: list[KBCandidate] = []

    for asset_id, candidates in asset_candidates.items():
        if not candidates:
            raise EmptyKBMatchError(
                asset_id=asset_id,
                query_text="<all queries for asset>",
            )

        seen.setdefault(asset_id, set())
        deduped: list[KBCandidate] = []
        for c in sorted(candidates, key=lambda x: x.retrieval_score, reverse=True):
            if c.pattern_id not in seen[asset_id]:
                seen[asset_id].add(c.pattern_id)
                deduped.append(c)
                if len(deduped) >= (plan.top_k if hasattr(plan, "top_k") else 10):
                    break

        final.extend(deduped)

    # Global sort by score descending
    final.sort(key=lambda c: c.retrieval_score, reverse=True)

    log_step(
        logger,
        "INFO",
        "fetch_end",
        plan.run_id,
        {"total_candidates": len(final)},
    )

    return final


@lru_cache(maxsize=512)
def get_kb_entry(
    pattern_id: str,
    source: KBSource,
    *,
    metadata_path_str: str | None = None,
) -> KBCandidate:
    """Look up a single KB entry by canonical pattern ID and source.

    Used by Shriraj's validator (citation_presence_check) to confirm that a
    kb_reference in a ThreatScenario resolves to a real KB entry.

    Results are LRU-cached so repeated lookups in the validator loop are O(1).

    Args:
        pattern_id:        e.g. 'CAPEC-94', 'ATT&CK-T1190', 'CWE-306'.
        source:            Which KB to look up in.
        metadata_path_str: Optional override for kb_metadata.json path.

    Returns:
        KBCandidate with retrieval_score=1.0 (direct lookup, not FAISS-ranked).

    Raises:
        KBEntryNotFoundError:    If pattern_id has no match in the given source.
        KBStoreUnreachableError: If the KB metadata store is unavailable.
    """
    meta_path = Path(metadata_path_str) if metadata_path_str else None
    metadata = _get_metadata(meta_path)

    for _vid, entry_dict in metadata.items():
        if entry_dict.get("pattern_id") == pattern_id and entry_dict.get(
            "source"
        ) == str(source):
            return _metadata_to_kb_candidate(
                meta=entry_dict,
                asset_id="LOOKUP",  # No asset context for direct lookup
                retrieval_score=1.0,
            )

    raise KBEntryNotFoundError(
        pattern_id=pattern_id,
        source=str(source),
    )
