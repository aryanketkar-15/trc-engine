"""
agents/threat_agent/attack_chain.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Attack Chain Analysis  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Pipeline position:
    retrieval.py  →  list[KBCandidate]
                  →  attack_chain.py
                  →  list[AttackPath]
                  →  generator.py  (Chetan)

Responsibility
──────────────
Given a flat list of KB candidates retrieved for a system model, this module
links them into plausible multi-step attack paths — ordered kill-chain
sequences that reflect how a real adversary would chain individual
vulnerabilities into an end-to-end compromise.

Why this step is non-optional
──────────────────────────────
1.  **Realism**: Real attacks are multi-step.  Treating CAPEC-62 (BLE replay)
    and ATT&CK T1190 (public-facing app exploit) as independent threats
    misses the scenario where BLE replay *enables* credential theft that
    *enables* lateral movement.  The chain captures compounded risk.

2.  **Confidence scoring**: `AttackPath.chain_confidence` (geometric mean of
    step retrieval_scores) is consumed by scorer.py as the
    `retrieval_match_strength` signal (40% of confidence score, §2.6).
    Bypassing chain analysis removes this signal entirely.

3.  **Generator context**: Chetan's generator.py receives `list[AttackPath]`,
    not `list[KBCandidate]`.  The path's `reasoning` field is injected into
    the LLM prompt as chain-level context, improving attack_vector quality.

Algorithm (implementation target — Week 2)
───────────────────────────────────────────
1.  **Asset grouping**: partition candidates by `asset_id`.  Paths must not
    span assets without a trust-boundary crossing justification.

2.  **Tactic ordering**: sort candidates within an asset group by their
    `mitre_tactics` position in `MITRE_TACTIC_ORDER` (see constant below).
    Candidates without tactic IDs are placed by CAPEC prerequisite logic.

3.  **Link validation**: for consecutive steps (step N → step N+1), check
    that the post-condition of step N is a plausible pre-condition of step
    N+1.  Rule table loaded from `kb/data/chain_links.json` (data-driven,
    not hardcoded).  If no link is found → set `is_forced=True` on the path.

4.  **Cross-asset chaining**: if a candidate's MITRE tactic is
    `Lateral Movement` (TA0008), attempt to link to candidates on a
    different asset whose trust_zone is less restrictive.

5.  **chain_confidence**: geometric mean of step `retrieval_score` values,
    discounted by `FORCED_CHAIN_PENALTY` if `is_forced=True`.

6.  **Single-step paths**: a candidate that cannot be linked to any other
    still produces a valid single-step `AttackPath` — never silently dropped.

SCRP Compliance
───────────────
• Structured JSON log at the start and end of `build_paths()`.
• Every path carries a `reasoning` string for LLM prompt injection.
• `is_forced` flag makes the heuristic transparent to scorer.py and
  the human reviewer — no silent confidence inflation.

STUB STATUS
───────────
All function bodies are `NotImplementedError` stubs.
Real implementation begins in Week 2 once the FAISS index is built.
DO NOT merge to develop until stubs are replaced.
"""

from __future__ import annotations

import math
import uuid
from typing import Final

from agents.threat_agent.exceptions import (
    EmptyAttackPathError,
)
from agents.threat_agent.schemas import (
    AttackPath,
    KBCandidate,
    NormalizedInput,
    STRIDECategory,
)
from common.logging import get_logger, log_step

logger = get_logger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# § 0  —  Constants
# ══════════════════════════════════════════════════════════════════════════════

#: MITRE ATT&CK Enterprise tactic order — used to topologically sort
#: KBCandidates into a realistic kill-chain sequence.
#: Reference: https://attack.mitre.org/tactics/enterprise/
MITRE_TACTIC_ORDER: Final[dict[str, int]] = {
    "TA0043": 0,  # Reconnaissance
    "TA0042": 1,  # Resource Development
    "TA0001": 2,  # Initial Access
    "TA0002": 3,  # Execution
    "TA0003": 4,  # Persistence
    "TA0004": 5,  # Privilege Escalation
    "TA0005": 6,  # Defense Evasion
    "TA0006": 7,  # Credential Access
    "TA0007": 8,  # Discovery
    "TA0008": 9,  # Lateral Movement
    "TA0009": 10,  # Collection
    "TA0011": 11,  # Command and Control
    "TA0010": 12,  # Exfiltration
    "TA0040": 13,  # Impact
}

#: Fallback tactic position for candidates with no ATT&CK tactic IDs
#: (CAPEC-only, CWE-only, or STRIDE-only entries).
#: Placed after Initial Access and before Execution — a conservative middle.
_FALLBACK_TACTIC_POSITION: Final[int] = 2

#: chain_confidence discount when a chain is flagged as forced
#: (no evidence-based link between consecutive steps).
#: Documented in AttackPath.chain_confidence field description.
FORCED_CHAIN_PENALTY: Final[float] = 0.10

#: Minimum chain_confidence before scorer.py emits a low-confidence warning.
#: Not a hard rejection threshold — that lives in scorer.py.
MIN_CHAIN_CONFIDENCE_WARNING: Final[float] = 0.35


# ══════════════════════════════════════════════════════════════════════════════
# § 1  —  Internal helpers  (stubs — Week 2 implementation)
# ══════════════════════════════════════════════════════════════════════════════


def _tactic_position(candidate: KBCandidate) -> int:
    """Return the lowest kill-chain position for a candidate's tactic IDs.

    Candidates with multiple tactic IDs (common in ATT&CK) are placed by
    their *earliest* tactic — reflecting the first opportunity an adversary
    could use the technique.

    Args:
        candidate: A KBCandidate retrieved from the FAISS index.

    Returns:
        Integer position in ``MITRE_TACTIC_ORDER`` (lower = earlier in chain).
        Returns ``_FALLBACK_TACTIC_POSITION`` for candidates with no tactic IDs.
    """
    if not candidate.mitre_tactics:
        return _FALLBACK_TACTIC_POSITION
    positions = [
        MITRE_TACTIC_ORDER.get(tactic, _FALLBACK_TACTIC_POSITION)
        for tactic in candidate.mitre_tactics
    ]
    return min(positions)


def _compute_chain_confidence(steps: list[KBCandidate], is_forced: bool) -> float:
    """Compute chain_confidence as the geometric mean of step retrieval_scores.

    Formula (from AttackPath.chain_confidence docstring and §2.6):
        chain_confidence = geometric_mean(retrieval_scores)
                         - FORCED_CHAIN_PENALTY  (if is_forced)
        clamped to [0.0, 1.0]

    Args:
        steps:     Ordered list of KBCandidate steps forming the chain.
        is_forced: Whether the chain link was inferred rather than evidenced.

    Returns:
        Float in [0.0, 1.0].
    """
    if not steps:
        return 0.0
    log_sum = sum(math.log(max(s.retrieval_score, 1e-9)) for s in steps)
    geo_mean = math.exp(log_sum / len(steps))
    confidence = geo_mean - (FORCED_CHAIN_PENALTY if is_forced else 0.0)
    return max(0.0, min(1.0, confidence))


def _build_chain_reasoning(
    steps: list[KBCandidate],
    is_forced: bool,
) -> str:
    """Produce the `reasoning` string injected into Chetan's LLM prompt.

    Each step is described as: "<position>. <source>/<pattern_id>: <title>"
    Followed by a forced-chain disclaimer if applicable.

    Args:
        steps:     Ordered chain steps.
        is_forced: Whether the chain was heuristically inferred.

    Returns:
        Multi-line string suitable for LLM prompt injection.
    """
    lines = ["Attack chain (ordered by kill-chain stage):"]
    for i, step in enumerate(steps, start=1):
        lines.append(f"  Step {i}: [{step.source}/{step.pattern_id}] {step.title}")
    if is_forced:
        lines.append(
            "\nNOTE: The link between one or more consecutive steps was "
            "inferred (no direct prerequisite evidence found in the KB). "
            "Mark the generated ThreatScenario's confidence accordingly."
        )
    return "\n".join(lines)


def _group_by_asset(
    candidates: list[KBCandidate],
) -> dict[str, list[KBCandidate]]:
    """Partition candidates by asset_id.

    Paths are built within an asset group first; cross-asset paths are
    introduced only when a lateral-movement tactic (TA0008) is detected.

    Args:
        candidates: Flat list of all retrieved KBCandidates.

    Returns:
        Dict mapping asset_id → list of candidates for that asset,
        preserving retrieval-score ordering within each group.
    """
    groups: dict[str, list[KBCandidate]] = {}
    for candidate in candidates:
        groups.setdefault(candidate.asset_id, []).append(candidate)
    return groups


def _has_lateral_movement(candidate: KBCandidate) -> bool:
    """Return True if the candidate includes a Lateral Movement tactic.

    Used to decide whether to attempt cross-asset chain linking.
    """
    return "TA0008" in candidate.mitre_tactics


def _stride_compatible(
    step_a: KBCandidate,
    step_b: KBCandidate,
) -> bool:
    """Heuristic: are two adjacent steps STRIDE-compatible?

    Rule: Spoofing → Tampering, Tampering → ElevationOfPrivilege,
    InformationDisclosure can follow any step, etc.
    Full rule table loaded from kb/data/chain_links.json in Week 2.

    Args:
        step_a: Earlier step in the chain.
        step_b: Later step in the chain.

    Returns:
        True if the STRIDE pairing is plausible.  Returns True when
        either hint is None (no hint → no disqualification).
    """
    if step_a.stride_hint is None or step_b.stride_hint is None:
        return True  # cannot disqualify without both hints
    # Compatible pairs (seed list — full table in chain_links.json, Week 2)
    compatible_pairs: set[tuple[STRIDECategory, STRIDECategory]] = {
        (STRIDECategory.SPOOFING, STRIDECategory.TAMPERING),
        (STRIDECategory.SPOOFING, STRIDECategory.ELEVATION_OF_PRIVILEGE),
        (STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE),
        (STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE),
        (STRIDECategory.TAMPERING, STRIDECategory.DENIAL_OF_SERVICE),
        (STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.ELEVATION_OF_PRIVILEGE),
        (STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING),
        (STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.DENIAL_OF_SERVICE),
        (STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.REPUDIATION),
    }
    return (step_a.stride_hint, step_b.stride_hint) in compatible_pairs


# ══════════════════════════════════════════════════════════════════════════════
# § 2  —  Public interface
# ══════════════════════════════════════════════════════════════════════════════


def build_paths(
    candidates: list[KBCandidate],
    system_input: NormalizedInput,
) -> list[AttackPath]:
    """Link KB candidates into plausible multi-step attack paths.

    This is the production entry point consumed by generator.py.
    See module docstring for the full algorithm description.

    Pipeline contract (confirmed with Chetan — Aug 2026):
        fetch_candidates(plan)            → list[KBCandidate]
        build_paths(candidates, input)    → list[AttackPath]    ← THIS FUNCTION
        generate_scenarios(paths, input)  → list[ThreatScenario]

    Args:
        candidates:   Flat list of KBCandidates from retrieval.fetch_candidates().
                      Must be non-empty — raises EmptyAttackPathError otherwise.
        system_input: NormalizedInput from perceive(), used for asset trust-zone
                      context when deciding cross-asset chain viability.

    Returns:
        list[AttackPath]: One or more attack paths.  Single-step paths are
        valid — a candidate that cannot be chained still produces a path.
        Paths are ordered by decreasing chain_confidence.

    Raises:
        EmptyAttackPathError:    If ``candidates`` is empty.
        KBStoreUnreachableError: If chain_links.json cannot be loaded
                                 (propagated from the link-validation step).

    Structured log events emitted:
        step=chain_start  — run_id, candidate_count
        step=chain_end    — run_id, path_count, forced_count, latency_ms
    """
    if not candidates:
        raise EmptyAttackPathError(
            context=(
                f"build_paths() received 0 candidates for run_id "
                f"'{system_input.run_id}'.  "
                "Ensure fetch_candidates() returned results before calling "
                "build_paths()."
            )
        )

    log_step(
        logger,
        "INFO",
        "chain_start",
        system_input.run_id,
        {"candidate_count": len(candidates)},
    )

    # ── STUB — real implementation Week 2 ────────────────────────────────────
    raise NotImplementedError(
        "build_paths() — STUB. "
        "Full kill-chain ordering + link validation implementation "
        "pending (feature/threat-agent-retrieval, Week 2). "
        "Algorithm: group by asset → sort by MITRE_TACTIC_ORDER → "
        "validate links via chain_links.json → compute chain_confidence "
        "as geometric mean of retrieval_scores."
    )


def build_single_step_path(
    candidate: KBCandidate,
    reason: str = "",
) -> AttackPath:
    """Wrap a single KBCandidate in a valid single-step AttackPath.

    Used when:
      1.  A candidate cannot be linked to any other in the set.
      2.  build_paths() catches an UnlinkableCandidateError internally.
      3.  generate_from_candidates() in generator.py wraps individual
          candidates for fallback / test-only generation.

    This function is intentionally simple and does NOT raise stubs —
    it is fully implemented because it has zero external dependencies
    (no FAISS, no chain_links.json).

    Args:
        candidate: The single KB candidate to wrap.
        reason:    Optional reason this candidate was not chained
                   (populated when called from UnlinkableCandidateError handler).

    Returns:
        A valid single-step AttackPath with is_forced=False (single-step paths
        are not "forced" — they are legitimate single-step threats).
    """
    reasoning_parts = [
        f"Single-step path for [{candidate.source}/{candidate.pattern_id}] "
        f"'{candidate.title}' on asset '{candidate.asset_id}'."
    ]
    if reason:
        reasoning_parts.append(f"Isolation reason: {reason}")

    return AttackPath(
        path_id=f"PATH-{uuid.uuid4().hex[:8].upper()}",
        steps=[candidate],
        target_asset_ids=[candidate.asset_id],
        is_forced=False,
        chain_confidence=float(candidate.retrieval_score),
        reasoning="\n".join(reasoning_parts),
    )


def deduplicate_paths(paths: list[AttackPath]) -> list[AttackPath]:
    """Remove AttackPath duplicates with identical step sequences.

    Two paths are considered duplicates if their ordered pattern_id sequences
    are identical, regardless of path_id (which is random).  Keeps the path
    with higher chain_confidence.

    Args:
        paths: Raw list of AttackPath objects (may contain duplicates).

    Returns:
        Deduplicated list ordered by decreasing chain_confidence.

    Implementation note:
        This is fully implemented because deduplication has no FAISS dependency.
        It can be unit-tested and used by the real build_paths() in Week 2.
    """
    seen: dict[tuple[str, ...], AttackPath] = {}
    for path in paths:
        key: tuple[str, ...] = tuple(step.pattern_id for step in path.steps)
        if key not in seen or path.chain_confidence > seen[key].chain_confidence:
            seen[key] = path
    return sorted(seen.values(), key=lambda p: p.chain_confidence, reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# § 3  —  Module-level exports
# ══════════════════════════════════════════════════════════════════════════════

__all__: list[str] = [
    "FORCED_CHAIN_PENALTY",
    "MIN_CHAIN_CONFIDENCE_WARNING",
    "MITRE_TACTIC_ORDER",
    "_build_chain_reasoning",
    "_compute_chain_confidence",
    "_has_lateral_movement",
    "_stride_compatible",
    "_tactic_position",
    "build_paths",
    "build_single_step_path",
    "deduplicate_paths",
]
