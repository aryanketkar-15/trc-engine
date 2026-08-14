"""
agents/threat_agent/exceptions.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Typed Exception Hierarchy  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Centralised exception definitions for the Threat Agent pipeline.
All custom exceptions inherit from ThreatAgentError to allow callers
(router.py, orchestrator) to catch module-specific errors cleanly.

Design principles:
  • No bare exceptions — every failure mode maps to a typed exception class.
  • Rich context — exceptions carry structured attributes (not just string
    messages) so loggers and retry handlers can inspect root causes.
  • Domain-specific base classes — KB errors inherit from ThreatAgentError;
    attack chain errors inherit from AttackChainError.
"""

from __future__ import annotations


class ThreatAgentError(Exception):
    """Base class for all Threat Agent exceptions.

    Catch this to handle any Threat Agent error generically; catch a
    subclass for specific handling.
    """


class KBStoreUnreachableError(ThreatAgentError):
    """Raised when the FAISS index or KB metadata store cannot be loaded.

    This is a hard infrastructure failure — not a 'no results' condition.
    The caller (ThreatAgent.fetch / attack_chain) must not silently fall
    back to an empty result; it must propagate this exception so the
    orchestrator can surface a clear failure rather than an empty threat list.

    Attributes:
        store_path: Filesystem path or URI of the unreachable store.
        cause:      The underlying OSError or similar that triggered this.
    """

    def __init__(self, store_path: str, cause: Exception | None = None) -> None:
        self.store_path = store_path
        self.cause = cause
        detail = f" Caused by: {cause!r}" if cause else ""
        super().__init__(
            f"KB store unreachable at '{store_path}'.{detail} "
            "Ensure the FAISS index has been built and kb/data/ is accessible."
        )


class EmptyKBMatchError(ThreatAgentError):
    """Raised when a retrieval query returns zero KB candidates for an asset.

    Per build plan §6 unit test spec: 'empty KB match returns empty list,
    not an error' applies only at the *per-query* level.  At the
    *per-asset* level, zero matches across ALL queries for a given asset
    is a hard error — it means the KB has no coverage for this asset type,
    which must be surfaced explicitly, not silently dropped.

    Attributes:
        asset_id:    The asset that produced no KB matches.
        query_text:  The query that was attempted.
    """

    def __init__(self, asset_id: str, query_text: str) -> None:
        self.asset_id = asset_id
        self.query_text = query_text
        super().__init__(
            f"KB returned zero candidates for asset '{asset_id}' "
            f"with query: '{query_text[:80]}...'.  "
            "This asset has no KB coverage — add relevant CAPEC/ATT&CK/CWE "
            "entries to kb/data/ or review the asset's attribute embedding."
        )


class MalformedKBEntryError(ThreatAgentError):
    """Raised when a raw KB record fails Pydantic schema validation.

    Indicates a data quality problem in kb/data/ — not a retrieval bug.
    The loader must raise this rather than silently skip the entry, so
    the KB maintainer is forced to fix the data.

    Attributes:
        pattern_id:      The pattern ID of the malformed entry (if known).
        source:          KB source name (CAPEC/ATT&CK/CWE/STRIDE).
        validation_error: The Pydantic ValidationError message.
    """

    def __init__(
        self,
        pattern_id: str,
        source: str,
        validation_error: str,
    ) -> None:
        self.pattern_id = pattern_id
        self.source = source
        self.validation_error = validation_error
        super().__init__(
            f"KB entry '{pattern_id}' from source '{source}' failed schema "
            f"validation: {validation_error}.  Fix the raw KB data in kb/data/."
        )


class KBEntryNotFoundError(ThreatAgentError):
    """Raised by get_kb_entry() when a pattern_id has no match in the KB.

    Used by Shriraj's citation_presence_check to verify that a scenario's
    kb_reference resolves to a real KB entry — not just a syntactically
    valid-looking ID.

    Attributes:
        pattern_id: The ID that was not found.
        source:     The KB source that was searched.
    """

    def __init__(self, pattern_id: str, source: str) -> None:
        self.pattern_id = pattern_id
        self.source = source
        super().__init__(
            f"KB entry '{pattern_id}' not found in source '{source}'.  "
            "Verify the pattern ID is correct and the KB snapshot is current."
        )


class MalformedAssetInputError(ThreatAgentError):
    """Raised when an AssetModel field fails pre-retrieval validation.

    Pydantic enforces type at parse time, but semantic validation (e.g.
    an asset with an empty attributes dict that cannot produce a meaningful
    FAISS query vector) is enforced here at the retrieval boundary.

    Attributes:
        asset_id: The offending asset's ID.
        reason:   Human-readable description of the semantic failure.
    """

    def __init__(self, asset_id: str, reason: str) -> None:
        self.asset_id = asset_id
        self.reason = reason
        super().__init__(
            f"Asset '{asset_id}' failed pre-retrieval validation: {reason}.  "
            "Ensure the asset has non-empty 'attributes' and 'asset_type' "
            "before calling fetch_candidates()."
        )


# ══════════════════════════════════════════════════════════════════════════════
# § 2  —  Attack Chain exceptions
# ══════════════════════════════════════════════════════════════════════════════


class AttackChainError(ThreatAgentError):
    """Base class for all attack_chain.py exceptions."""


class EmptyAttackPathError(AttackChainError):
    """Raised when build_paths() or generate_scenarios() receives an empty
    candidate / path list.

    Per build plan §5: 'empty result' from any external call is a hard error,
    not a silent no-op.  An empty candidate list means retrieval found nothing
    for the entire system model, which must be surfaced immediately.

    NOTE: Chetan's generator.py also raises this class independently — once
    both modules are on develop, this definition is the canonical one and
    generator.py's local copy should be replaced with an import from here.

    Attributes:
        context: Human-readable description of where the empty list originated.
    """

    def __init__(self, context: str = "") -> None:
        self.context = context
        msg = "Cannot build attack paths: input list is empty."
        if context:
            msg += f"  Context: {context}"
        super().__init__(msg)


class UnlinkableCandidateError(AttackChainError):
    """Raised when build_paths() is forced to flag a candidate as having no
    plausible link to any other candidate in the set.

    This is NOT a hard failure — it results in a single-step AttackPath with
    is_forced=True.  The exception is raised internally and caught within
    attack_chain.py to set the flag; it does NOT propagate to the caller.

    Attributes:
        pattern_id: The candidate that could not be linked.
        reason:     Why no link was found.
    """

    def __init__(self, pattern_id: str, reason: str) -> None:
        self.pattern_id = pattern_id
        self.reason = reason
        super().__init__(
            f"No plausible chain link found for pattern '{pattern_id}': {reason}.  "
            "Will produce a single-step AttackPath with is_forced=True."
        )


# ══════════════════════════════════════════════════════════════════════════════
# § 3  —  Module-level exports
# ══════════════════════════════════════════════════════════════════════════════

__all__: list[str] = [
    "ThreatAgentError",
    # KB / Retrieval
    "KBStoreUnreachableError",
    "EmptyKBMatchError",
    "MalformedKBEntryError",
    "KBEntryNotFoundError",
    "MalformedAssetInputError",
    # Attack Chain
    "AttackChainError",
    "EmptyAttackPathError",
    "UnlinkableCandidateError",
]
