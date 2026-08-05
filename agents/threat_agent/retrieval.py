"""
agents/threat_agent/retrieval.py
════════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  KB Retrieval Layer  (Aryan)
────────────────────────────────────────────────────────────────────────────────
STUB — Day 1 / Week 1 interface contract.

This file exposes the public function signature that Chetan's generator.py
and Shriraj's consistency_check (TRC-STUB-001) will program against.
All bodies are NotImplementedError stubs — the FAISS index, embedding logic,
and KB loader integration will be filled in on feature/threat-agent-retrieval.

DO NOT merge to develop until stubs are replaced with real implementation.
"""

from __future__ import annotations

from agents.threat_agent.schemas import (
    KBCandidate,
    KBSource,
    RetrievalPlan,
    STRIDECategory,
)

# ─── STRIDE ↔ attack-vector vocabulary (TRC-STUB-001 resolution) ────────────
# This dict is the data-driven rule table that Shriraj needs to replace
# the heuristic stub in consistency_check().
#
# Format:
#   STRIDECategory → frozenset of *canonical* attack-vector keyword fragments
#   that are semantically valid for that STRIDE class.
#
# Shriraj's validator loads this at startup; it does NOT hardcode the rules.
# Aryan populates this from the KB schema once CAPEC/ATT&CK ingestion is done.
#
# STATUS: initial seed — expand after KB loaders are complete (Week 2).
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


# ─── Public retrieval interface ───────────────────────────────────────────────


def fetch_candidates(plan: RetrievalPlan) -> list[KBCandidate]:
    """Retrieve ranked KB candidates for all asset queries in the plan.

    Args:
        plan: A RetrievalPlan produced by plan() in the ThreatAgent.
              Contains per-asset queries and KB sources to search.

    Returns:
        Flat list of KBCandidate objects, ranked by retrieval_score descending,
        across all assets and KB sources in the plan.

    Raises:
        KBStoreUnreachableError: If the FAISS index cannot be loaded.
        EmptyKBMatchError:       If zero candidates are found for any asset
                                 (not a warning — this is a hard error per
                                 build plan §5 error-handling rules).
        MalformedKBEntryError:   If a KB record fails schema validation
                                 during ingestion.

    Implementation plan (Week 1-2):
        1. Load FAISS index from kb/data/ (mmap, read-only).
        2. For each query in plan.queries:
           a. Embed query_text → float32 vector via sentence-transformers.
           b. faiss_index.search(vector, plan.top_k) → distances + ids.
           c. Map ids → KBCandidate objects from the KB metadata store.
           d. Normalise L2 distance → cosine similarity → retrieval_score.
        3. Collect + deduplicate (same pattern_id for same asset_id).
        4. Return sorted by retrieval_score desc.
    """
    raise NotImplementedError(
        "fetch_candidates() — STUB. "
        "FAISS retrieval implementation pending "
        "(feature/threat-agent-retrieval, Week 2)."
    )


def get_kb_entry(pattern_id: str, source: KBSource) -> KBCandidate:
    """Look up a single KB entry by its canonical pattern ID.

    Used by Shriraj's validator (citation_presence_check + consistency_check)
    to confirm that a kb_reference or matched_pattern resolves to a real entry.

    Args:
        pattern_id: e.g. 'CAPEC-94', 'ATT&CK T1190', 'CWE-306'
        source:     Which KB to look up in (CAPEC, ATT&CK, CWE, STRIDE).

    Returns:
        KBCandidate for the matched entry.

    Raises:
        KBEntryNotFoundError: If pattern_id has no match in the given source.
        KBStoreUnreachableError: If the KB metadata store is unavailable.
    """
    raise NotImplementedError(
        "get_kb_entry() — STUB. "
        "KB metadata lookup pending "
        "(feature/threat-agent-retrieval, Week 2)."
    )
