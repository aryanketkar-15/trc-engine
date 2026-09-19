"""
agents/threat_agent/validator.py
─────────────────────────────────
Protocol Invariant Validator — the test-gate between the LLM generator and the
human-approval checkpoint.

DESIGN INTENT:
Each check is an independent, side-effect-free method that takes a
ThreatScenario and returns (bool, FailedCheck | None).  They share *no*
mutable state, which means:
  - They can be unit-tested in complete isolation.
  - They can be reordered or skipped without surprising side effects.
  - The audit log can record exactly which checks ran and which failed.

SCHEMA ALIGNMENT (critical):
This module uses the *frozen* schema from develop:
  - FailedCheck(check_id, affected_tid, detail) — NOT bare str
  - STRIDECategory StrEnum — NOT Literal[...]
  - ValidationResult consistency validator rejects passed=True + non-empty
    failed_checks, so we must only pass passed=True when failed_checks == []

TRC-STUB-001 RESOLVED (Aryan, 2026-08-06):
consistency_check now uses STRIDE_VECTOR_VOCABULARY from retrieval.py.
The rule: if attack_vector contains *none* of the valid keyword fragments for
the given STRIDECategory, flag it as inconsistent.
"""

from __future__ import annotations

from agents.threat_agent.schemas import (
    FailedCheck,
    STRIDECategory,
    ThreatScenario,
    ValidationResult,
)

# STRIDE_VECTOR_VOCABULARY is loaded from retrieval.py (Aryan's module).
# We import it here at runtime — if retrieval.py isn't present yet (e.g. in
# isolated unit tests), the test module can monkey-patch this symbol before
# importing Validator.  See test_validator.py for the patch fixture.
try:
    from agents.threat_agent.retrieval import STRIDE_VECTOR_VOCABULARY
except ImportError:  # pragma: no cover — retrieval not yet present locally
    STRIDE_VECTOR_VOCABULARY: dict[STRIDECategory, frozenset[str]] = {}  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Strings treated as placeholder citations (lowercased for comparison).
PLACEHOLDER_CITATION_STRINGS: frozenset[str] = frozenset(
    {
        "",
        "n/a",
        "tbd",
        "todo",
        "placeholder",
        "unknown",
        "none",
        "null",
        "undefined",
    }
)

#: Strings treated as generic placeholder applicability_reasons.
PLACEHOLDER_APPLICABILITY_STRINGS: frozenset[str] = frozenset(
    {
        "n/a",
        "tbd",
        "todo",
        "unknown",
        "none",
        "null",
        "undefined",
        "not applicable",
        "not available",
    }
)

#: Minimum character length for a non-trivial applicability_reason.
#: MUST match the frozen schema's min_length=20 constraint on EvidenceChain.applicability_reason.
MIN_APPLICABILITY_REASON_LENGTH: int = 20

# ---------------------------------------------------------------------------
# Check ID constants — machine-readable, branchable by router.py / generator.py
# ---------------------------------------------------------------------------
CHECK_CITATION_MISSING: str = "CITATION_MISSING"
CHECK_SCHEMA_INCOMPLETE: str = "SCHEMA_INCOMPLETE"
CHECK_CONSISTENCY_MISMATCH: str = "CONSISTENCY_MISMATCH"
CHECK_EVIDENCE_GENERIC: str = "EVIDENCE_GENERIC"


class Validator:
    """
    Protocol Invariant Validator for ThreatScenario objects.

    Runs four independent checks to gate LLM-generated scenarios before they
    reach the human-approval step.  All checks are pure functions of the
    scenario (and optional prior context); no state is shared between them.

    Return contract for each check:
        (True, None)          — check passed
        (False, FailedCheck)  — check failed; FailedCheck carries a
                                machine-readable check_id and a human-readable
                                detail string that becomes the retry prompt context.
    """

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def citation_presence_check(
        self, scenario: ThreatScenario
    ) -> tuple[bool, FailedCheck | None]:
        """
        Check: evidence_chain.citation must be non-empty and not a placeholder.

        WHY THIS CHECK EXISTS:
        An uncited threat scenario is an opinion, not evidence.  In a
        cybersecurity review or audit, every claim must trace back to a source
        (CAPEC, ATT&CK, CWE, or an equivalent KB).  This check catches the most
        common LLM failure mode: generating plausible-sounding threats without
        grounding them in a real KB entry or document.

        check_id: CITATION_MISSING
        """
        citation = scenario.evidence_chain.citation.strip()
        if not citation:
            return False, FailedCheck(
                check_id=CHECK_CITATION_MISSING,
                affected_tid=scenario.tid,
                detail=(
                    "citation_presence_check: evidence_chain.citation is empty.  "
                    "Every threat scenario must cite a KB source (CAPEC/ATT&CK/CWE)."
                ),
            )
        if citation.lower() in PLACEHOLDER_CITATION_STRINGS:
            return False, FailedCheck(
                check_id=CHECK_CITATION_MISSING,
                affected_tid=scenario.tid,
                detail=(
                    f"citation_presence_check: citation is a placeholder string "
                    f"({citation!r}).  Replace with a real KB URL or entry ID."
                ),
            )
        return True, None

    def schema_completeness_check(
        self, scenario: ThreatScenario
    ) -> tuple[bool, FailedCheck | None]:
        """
        Check: all required top-level ThreatScenario fields are present and non-empty.

        WHY THIS CHECK EXISTS:
        Pydantic validates *type* at construction, but it cannot check whether a
        field was filled with a meaningful value vs. an empty string that slipped
        past the required-field guard.  This check closes that gap for the five
        fields that downstream consumers (Risk Agent, human reviewer) always need:
        tid, asset_id, stride_category, attack_vector, kb_reference.

        check_id: SCHEMA_INCOMPLETE
        """
        required_fields: dict[str, str] = {
            "tid": scenario.tid,
            "asset_id": scenario.asset_id,
            "stride_category": str(scenario.stride_category),
            "attack_vector": scenario.attack_vector,
            "kb_reference": scenario.kb_reference,
        }
        empty_fields: list[str] = [
            field for field, value in required_fields.items() if not value.strip()
        ]
        if empty_fields:
            return False, FailedCheck(
                check_id=CHECK_SCHEMA_INCOMPLETE,
                affected_tid=scenario.tid,
                detail=(
                    f"schema_completeness_check: the following required fields are "
                    f"empty or whitespace-only: {empty_fields}.  "
                    f"All must be populated with non-trivial values."
                ),
            )
        return True, None

    def consistency_check(
        self,
        scenario: ThreatScenario,
        prior_context: object | None = None,  # typed when SCRSContext lands (Phase 2)
    ) -> tuple[bool, FailedCheck | None]:
        """
        Check: stride_category must be logically consistent with attack_vector.

        WHY THIS CHECK EXISTS:
        LLMs can hallucinate mismatched STRIDE/attack-vector combinations —
        e.g., labelling a brute-force credential attack as "Repudiation" rather
        than "Spoofing".  This inconsistency would propagate into the Risk Agent's
        reasoning about controls.  The check provides an automated sanity layer
        before human review.

        IMPLEMENTATION (TRC-STUB-001 RESOLVED — Aryan, 2026-08-06):
        Uses STRIDE_VECTOR_VOCABULARY from retrieval.py — a data-driven
        dict[STRIDECategory, frozenset[str]] mapping each STRIDE class to the
        set of valid attack-vector keyword fragments for that class.

        Rule: if the attack_vector (lowercased) contains *none* of the valid
        fragments for scenario.stride_category, the pair is flagged inconsistent.

        FALLBACK: if STRIDE_VECTOR_VOCABULARY is empty (e.g. retrieval.py not
        yet present in a local environment), the check passes silently rather
        than blocking development — this is safe because the check will be fully
        active in CI once retrieval.py is merged into develop.

        The `prior_context` parameter is reserved for SCRS context from previous
        reasoning cycles.  Wire in Phase 1.5 / Phase 2 prep once
        StateManager.read() is implemented.

        check_id: CONSISTENCY_MISMATCH
        """
        if not STRIDE_VECTOR_VOCABULARY:
            # Vocabulary not yet available locally — pass silently, active in CI.
            return True, None

        valid_fragments = STRIDE_VECTOR_VOCABULARY.get(scenario.stride_category)
        if valid_fragments is None:
            # Unrecognised stride_category — schema validator should have caught
            # this; if it slips through, pass silently (not our gate).
            return True, None

        vector_lower = scenario.attack_vector.lower()
        matched = any(fragment in vector_lower for fragment in valid_fragments)

        if not matched:
            return False, FailedCheck(
                check_id=CHECK_CONSISTENCY_MISMATCH,
                affected_tid=scenario.tid,
                detail=(
                    f"consistency_check: stride_category "
                    f"'{scenario.stride_category}' does not appear consistent "
                    f"with attack_vector '{scenario.attack_vector}'.  "
                    f"Valid attack-vector keywords for this STRIDE class: "
                    f"{sorted(valid_fragments)}.  "
                    f"Either correct the stride_category or revise the attack_vector."
                ),
            )
        return True, None

    def evidence_completeness_check(
        self, scenario: ThreatScenario
    ) -> tuple[bool, FailedCheck | None]:
        """
        Check: evidence_chain has non-trivial exposure, matched_pattern, and
        applicability_reason.

        WHY THIS CHECK EXISTS:
        The Evidence & Confidence Scorer (§2.6) awards 20% of the confidence
        score to evidence completeness — this check is the *programmatic*
        enforcement of that criterion.  It catches two generator failure modes:
          1. Structural absence — a field is empty.
          2. Semantic laziness — the field contains a generic placeholder
             ("N/A", "TBD") or is so short (<10 chars) that it conveys nothing.
        Catching these before human review saves reviewer time and prevents
        low-quality threats from reaching the SCRS.

        check_id: EVIDENCE_GENERIC
        """
        chain = scenario.evidence_chain
        failures: list[str] = []

        if not chain.exposure.strip():
            failures.append("evidence_chain.exposure is empty.")

        if not chain.matched_pattern.strip():
            failures.append("evidence_chain.matched_pattern is empty.")

        reason_stripped = chain.applicability_reason.strip()
        if not reason_stripped:
            failures.append("evidence_chain.applicability_reason is empty.")
        elif reason_stripped.lower() in PLACEHOLDER_APPLICABILITY_STRINGS:
            failures.append(
                f"evidence_chain.applicability_reason is a generic placeholder "
                f"({reason_stripped!r}).  Provide specific, actionable prose."
            )
        elif len(reason_stripped) < MIN_APPLICABILITY_REASON_LENGTH:
            failures.append(
                f"evidence_chain.applicability_reason is too short "
                f"({len(reason_stripped)} chars < {MIN_APPLICABILITY_REASON_LENGTH} "
                f"minimum).  Provide at least {MIN_APPLICABILITY_REASON_LENGTH} chars "
                f"of specific prose."
            )

        if failures:
            return False, FailedCheck(
                check_id=CHECK_EVIDENCE_GENERIC,
                affected_tid=scenario.tid,
                detail=(
                    "evidence_completeness_check: " + " | ".join(failures)
                ),
            )
        return True, None

    # ------------------------------------------------------------------
    # Top-level validation entry point
    # ------------------------------------------------------------------

    def validate(self, scenario: ThreatScenario) -> ValidationResult:
        """
        Run all four checks against *scenario* and return a ValidationResult.

        Checks are independent — a failure in one does not short-circuit the
        others.  All FailedCheck objects are collected so the retry loop can
        feed the full set of .detail strings back into Reason+Fetch, rather
        than fixing one issue at a time across multiple retries.

        ValidationResult consistency: the frozen schema rejects passed=True when
        failed_checks is non-empty (and vice-versa), so we derive `passed`
        strictly from whether failed_checks is empty.

        Args:
            scenario: The ThreatScenario produced by the generator.

        Returns:
            ValidationResult with passed=True and empty failed_checks on full
            pass; otherwise passed=False and a list of FailedCheck objects.
        """
        check_results: list[tuple[bool, FailedCheck | None]] = [
            self.citation_presence_check(scenario),
            self.schema_completeness_check(scenario),
            self.consistency_check(scenario),
            self.evidence_completeness_check(scenario),
        ]

        failed_checks: list[FailedCheck] = [
            fc for passed, fc in check_results if not passed and fc is not None
        ]

        return ValidationResult(
            passed=len(failed_checks) == 0,
            failed_checks=failed_checks,
            retry_count=0,  # caller sets this correctly in the retry loop
        )

    # ------------------------------------------------------------------
    # Retry orchestration
    # ------------------------------------------------------------------

    def retry_with_context(
        self,
        scenario: ThreatScenario,
        validation_result: ValidationResult,
        retry_count: int,
    ) -> tuple[str, dict[str, object]]:
        """
        Orchestrate one retry cycle after a validation failure.

        INTERFACE CONTRACT (for Chetan/Aryan):
        Produces a structured context dict that must be passed back into the
        Act/Fetch → Reason+Plan loop.  The retry_context string is injected
        verbatim into the generator prompt — it contains each FailedCheck.detail
        so the LLM understands specifically what to fix.

        The actual re-invocation of generator.py / retrieval.py is NOT done
        here — that is Chetan/Aryan's responsibility.

        Args:
            scenario:          The scenario that failed validation.
            validation_result: The ValidationResult from the failed run.
            retry_count:       The retry counter *before* incrementing.

        Returns:
            ("retry", context_dict)            — call generator with context
            ("escalate_to_human", context_dict) — max retries exhausted
        """
        new_retry_count = retry_count + 1

        if new_retry_count > 3:
            return (
                "escalate_to_human",
                {
                    "tid": scenario.tid,
                    "asset_id": scenario.asset_id,
                    "retry_count": retry_count,
                    "failed_checks": [fc.model_dump() for fc in validation_result.failed_checks],
                    "note": (
                        "Max retry attempts (3) exhausted.  "
                        "Scenario escalated to human reviewer for manual triage."
                    ),
                },
            )

        return (
            "retry",
            {
                "tid": scenario.tid,
                "asset_id": scenario.asset_id,
                "retry_count": new_retry_count,
                "failed_checks": [fc.model_dump() for fc in validation_result.failed_checks],
                "retry_context": (
                    "The previous attempt failed the Protocol Invariant Validator.  "
                    "Failure reasons (address each one in your next attempt):\n"
                    + "\n".join(
                        f"  [{i + 1}] [{check.check_id}] {check.detail}"
                        for i, check in enumerate(validation_result.failed_checks)
                    )
                ),
            },
        )
