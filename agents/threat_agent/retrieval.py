"""
agents/threat_agent/retrieval.py
════════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  KB Retrieval Layer  (Aryan)
────────────────────────────────────────────────────────────────────────────────
Migrated from FAISS to PostgreSQL + pgvector.

  - fetch_candidates() — pgvector cosine search, per-query dedup,
    top_k enforcement, score normalisation, and typed error guards.
  - get_kb_entry()     — direct KB lookup by pattern_id + source.

Function signatures are UNCHANGED from the FAISS implementation so
generator.py, attack_chain.py and validator.py require zero edits.

Pipeline position:
    plan() → RetrievalPlan → fetch_candidates() → list[KBCandidate]
                                                         │
                                           attack_chain.build_paths()

STRIDE_VECTOR_VOCABULARY (TRC-STUB-001 resolution):
    Exported for Shriraj's consistency_check in validator.py.
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
    AssetModel,
    KBCandidate,
    KBSource,
    RetrievalPlan,
    STRIDECategory,
    ThreatAgentInput,
)
from common.db import get_db_connection
from common.logging import get_logger, log_step

logger = get_logger(__name__)

# ─── STRIDE ↔ attack-vector vocabulary (TRC-STUB-001 resolution) ─────────────
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

_DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"

# ─── Module-level lazy singleton (loaded once per process) ───────────────────
_ENCODER: Any | None = None


def _import_encoder() -> object:
    try:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        return SentenceTransformer
    except ImportError as err:
        raise KBStoreUnreachableError(
            store_path="pgvector",
            cause=ImportError(
                "sentence-transformers is not installed. "
                "Run: pip install sentence-transformers"
            ),
        ) from err


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
    """Convert a metadata dict + retrieval context into a KBCandidate."""
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


def _filter_by_sources(
    candidates: list[KBCandidate],
    kb_sources: list[str],
) -> list[KBCandidate]:
    """Filter candidates to only those from the requested KB sources."""
    allowed = {KBSource(s) for s in kb_sources}
    return [c for c in candidates if c.source in allowed]


# ─── Retrieval Plan builder (plan() step) ────────────────────────────────────

# KB sources always included regardless of asset type
_CORE_SOURCES: frozenset[str] = frozenset({"CAPEC", "STRIDE"})

# Keywords that trigger ATT&CK inclusion
_ATTCK_TYPE_KEYWORDS: frozenset[str] = frozenset(
    {"api", "rest", "network", "cloud", "web", "http", "backend", "server", "endpoint"}
)

# Keywords that trigger CWE inclusion
_CWE_TYPE_KEYWORDS: frozenset[str] = frozenset(
    {"firmware", "embedded", "ota", "bootloader", "software", "driver", "kernel"}
)

# Interface keywords that force full KB coverage
_WIRELESS_INTERFACE_KEYWORDS: frozenset[str] = frozenset(
    {
        "ble",
        "bluetooth",
        "wifi",
        "wi-fi",
        "wireless",
        "zigbee",
        "zwave",
        "rf",
        "lte",
        "5g",
    }
)


def _select_kb_sources(asset: AssetModel) -> list[str]:
    """Derive relevant KB source set for an asset based on its type and interfaces.

    Logic (deterministic, no LLM) — UNCHANGED from the FAISS implementation:
    - CAPEC + STRIDE always included.
    - ATT&CK added for network-facing / API / cloud assets.
    - CWE added for firmware / embedded / software assets.
    - Wireless interfaces (BLE, WiFi, etc.) trigger ATT&CK + CWE coverage.
    - Untrusted trust zone triggers full coverage (all 4 sources).

    This logic now populates the source = ANY($2) SQL parameter instead of
    selecting which FAISS sub-index to search.
    """
    sources: set[str] = set(_CORE_SOURCES)
    asset_type_lower = asset.asset_type.lower() if asset.asset_type else ""

    if any(kw in asset_type_lower for kw in _ATTCK_TYPE_KEYWORDS):
        sources.add("ATT&CK")
    if any(kw in asset_type_lower for kw in _CWE_TYPE_KEYWORDS):
        sources.add("CWE")

    for iface in asset.dfd_context.interfaces:
        iface_lower = iface.lower()
        if any(kw in iface_lower for kw in _WIRELESS_INTERFACE_KEYWORDS):
            sources.update({"ATT&CK", "CWE"})
        if any(kw in iface_lower for kw in {"http", "rest", "api", "https", "grpc"}):
            sources.add("ATT&CK")

    if asset.dfd_context.trust_zone.lower() in {"untrusted", "external"}:
        sources.update({"ATT&CK", "CWE"})

    return sorted(sources)


def _build_query_text(asset: AssetModel) -> str:
    """Construct a semantic query string from an asset's properties."""
    parts: list[str] = [asset.name]
    if asset.asset_type and asset.asset_type != "unspecified":
        parts.append(asset.asset_type)
    if asset.dfd_context.interfaces:
        parts.extend(asset.dfd_context.interfaces)
    if asset.device_config:
        for key, value in asset.device_config.items():
            parts.append(f"{key}: {value}")
    parts.append(asset.dfd_context.trust_zone)
    return " ".join(parts)


def build_retrieval_plan(
    agent_input: ThreatAgentInput,
    top_k: int = 10,
) -> RetrievalPlan:
    """Build a structured RetrievalPlan dynamically from a ThreatAgentInput."""
    if not agent_input.assets:
        raise ValueError(
            "ThreatAgentInput.assets must contain at least one AssetModel."
        )

    queries: list[dict[str, str | list[str]]] = [
        {
            "asset_id": asset.asset_id,
            "query_text": _build_query_text(asset),
            "kb_sources": _select_kb_sources(asset),
        }
        for asset in agent_input.assets
    ]

    log_step(
        logger,
        "INFO",
        "plan_built",
        agent_input.run_id,
        {
            "asset_count": len(agent_input.assets),
            "query_count": len(queries),
            "top_k": top_k,
        },
    )

    return RetrievalPlan(
        run_id=agent_input.run_id,
        queries=queries,
        top_k=top_k,
    )


# ─── Public retrieval interface ───────────────────────────────────────────────


def fetch_candidates(
    plan: RetrievalPlan,
    *,
    index_path: Path | None = None,     # kept for signature compat; unused
    metadata_path: Path | None = None,  # kept for signature compat; unused
    model_name: str | None = None,
) -> list[KBCandidate]:
    """Retrieve ranked KB candidates for all asset queries in the plan.

    Executes each query against the pgvector threat_patterns table, collects
    results, deduplicates (same pattern_id per asset_id), enforces top_k, and
    returns a flat list sorted by retrieval_score descending.

    Args:
        plan:          RetrievalPlan produced by build_retrieval_plan().
        index_path:    Unused — kept so callers need no changes.
        metadata_path: Unused — kept so callers need no changes.
        model_name:    Override for embedding model (default: config value).

    Returns:
        Flat list of KBCandidate objects, sorted by retrieval_score descending.

    Raises:
        KBStoreUnreachableError: If the DB is unreachable or the query fails.
        EmptyKBMatchError:       If ALL queries for an asset_id return zero candidates.
        MalformedAssetInputError: If a query has an empty query_text.
    """
    import numpy as np  # noqa: PLC0415
    from pgvector.psycopg import register_vector  # noqa: PLC0415

    encoder = _get_encoder(model_name)
    top_k = plan.top_k if hasattr(plan, "top_k") else 10

    log_step(
        logger,
        "INFO",
        "fetch_start",
        plan.run_id,
        {"query_count": len(plan.queries), "top_k": top_k},
    )

    asset_candidates: dict[str, list[KBCandidate]] = {}

    try:
        with get_db_connection() as conn:
            register_vector(conn)
            with conn.cursor() as cur:
                for query in plan.queries:
                    asset_id: str = query["asset_id"]  # type: ignore[index]
                    query_text: str = query["query_text"]  # type: ignore[index]
                    kb_sources: list[str] = query["kb_sources"]  # type: ignore[index]

                    if not query_text.strip():
                        raise MalformedAssetInputError(
                            asset_id=asset_id,
                            reason=(
                                f"query_text is empty for asset {asset_id!r}. "
                                "Cannot produce an embedding vector."
                            ),
                        )

                    # Embed query text
                    query_vec: Any = encoder.encode(  # type: ignore[union-attr]
                        [query_text],
                        normalize_embeddings=True,
                    ).astype(np.float32)[0]

                    # pgvector <=> = cosine distance; 1-distance = cosine similarity.
                    # source = ANY(%s) replaces the old FAISS sub-index selection logic.
                    cur.execute(
                        """
                        SELECT metadata,
                               1 - (embedding <=> %s) AS similarity
                        FROM   threat_patterns
                        WHERE  source = ANY(%s)
                        ORDER  BY embedding <=> %s
                        LIMIT  %s;
                        """,
                        (query_vec, kb_sources, query_vec, top_k * 2),
                    )

                    rows = cur.fetchall()
                    query_candidates: list[KBCandidate] = []
                    for row in rows:
                        meta_dict = row[0]
                        if isinstance(meta_dict, str):
                            meta_dict = json.loads(meta_dict)
                        similarity = float(row[1])
                        # Normalise cosine similarity [-1, 1] → [0, 1]
                        # (mirrors the old _cosine_to_score from the FAISS path)
                        score = max(0.0, min(1.0, (similarity + 1.0) / 2.0))
                        candidate = _metadata_to_kb_candidate(
                            meta=meta_dict,
                            asset_id=asset_id,
                            retrieval_score=score,
                        )
                        query_candidates.append(candidate)

                    # Belt-and-suspenders source filter
                    if kb_sources:
                        query_candidates = _filter_by_sources(query_candidates, kb_sources)

                    asset_candidates.setdefault(asset_id, [])
                    asset_candidates[asset_id].extend(query_candidates)

    except Exception as exc:
        if isinstance(exc, MalformedAssetInputError):
            raise
        raise KBStoreUnreachableError(
            store_path="pgvector",
            cause=exc,
        ) from exc

    # Per-asset deduplication and empty-match guard
    seen: dict[str, set[str]] = {}
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
                if len(deduped) >= top_k:
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
    metadata_path_str: str | None = None,  # kept for signature compat; unused
) -> KBCandidate:
    """Look up a single KB entry by canonical pattern ID and source.

    Used by Shriraj's validator (citation_presence_check) to confirm that a
    kb_reference in a ThreatScenario resolves to a real KB entry.

    Results are LRU-cached so repeated lookups in the validator loop are O(1).

    Args:
        pattern_id:        e.g. 'CAPEC-94', 'ATT&CK-T1190', 'CWE-306'.
        source:            Which KB to look up in.
        metadata_path_str: Unused — kept so callers need no changes.

    Returns:
        KBCandidate with retrieval_score=1.0 (direct lookup, not ranked).

    Raises:
        KBEntryNotFoundError:    If pattern_id has no match in the given source.
        KBStoreUnreachableError: If the DB is unavailable.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT metadata
                    FROM   threat_patterns
                    WHERE  pattern_id = %s
                      AND  source     = %s
                    LIMIT  1;
                    """,
                    (pattern_id, str(source)),
                )
                row = cur.fetchone()
                if row is None:
                    raise KBEntryNotFoundError(
                        pattern_id=pattern_id,
                        source=str(source),
                    )
                meta_dict = row[0]
                if isinstance(meta_dict, str):
                    meta_dict = json.loads(meta_dict)
                return _metadata_to_kb_candidate(
                    meta=meta_dict,
                    asset_id="LOOKUP",
                    retrieval_score=1.0,
                )
    except KBEntryNotFoundError:
        raise
    except Exception as exc:
        raise KBStoreUnreachableError(
            store_path="pgvector",
            cause=exc,
        ) from exc
