"""
agents/threat_agent/schemas.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Data Contract (Day-1 Freeze)
──────────────────────────────────────────────────────────────────────────────
This module is the **single source of truth** for every data shape flowing
through the Threat Agent.  All other modules (retrieval, attack_chain,
generator, scorer, validator, router) import from here — never the reverse.

Design principles enforced here
────────────────────────────────
• Clean Architecture  – every inter-module boundary is a Pydantic model.
• Type Safety         – full annotations; no `Any` except where semantically
                        required and explicitly justified via a comment.
• Immutability        – all models are frozen after construction
                        (`model_config = ConfigDict(frozen=True)`).
• Explicitness        – every field carries a `Field(description=…)` string
                        so the schema is self-documenting and IDE-friendly.
• Validation-on-load  – range checks, pattern checks, and enum constraints
                        are enforced by Pydantic at instantiation time, not
                        sprinkled ad-hoc across business logic.

SCRP Loop mapping (Section 2.2 of Phase1_Threat_Agent_Build_Plan_v4.md)
────────────────────────────────────────────────────────────────────────
  Perceive  →  ThreatAgentInput  →  NormalizedInput
  Plan      →  RetrievalPlan
  Act/Fetch →  KBCandidate
  Chain     →  AttackPath
  Observe   →  ThreatScenario  (carries EvidenceChain + confidence_score)
  Validate  →  ValidationResult
  Produce   →  SCRSWriteResult

All imports that external modules need:

    from agents.threat_agent.schemas import (
        EvidenceChain,
        ThreatScenario,
        ValidationResult,
        AttackPath,
        KBCandidate,
        ThreatAgentInput,
        NormalizedInput,
        RetrievalPlan,
        SCRSWriteResult,
        STRIDECategory,
        ThreatStatus,
        KBSource,
    )

Ruff compliance
───────────────
• Line length  ≤ 88 chars (ruff default).
• No unused imports.
• No mutable default arguments (use `default_factory`).
• String annotations are *not* used (Python 3.11+ runtime evaluation is fine).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ══════════════════════════════════════════════════════════════════════════════
# § 0  —  Enumerations  (stable, version-controlled vocabulary)
# ══════════════════════════════════════════════════════════════════════════════


class STRIDECategory(StrEnum):
    """STRIDE threat-category taxonomy.

    Each value corresponds to one of the six canonical STRIDE classes defined
    in Microsoft's threat-modelling methodology.  Using a typed enum instead of
    a raw string prevents generator / validator divergence at the schema level.
    """

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "InformationDisclosure"
    DENIAL_OF_SERVICE = "DenialOfService"
    ELEVATION_OF_PRIVILEGE = "ElevationOfPrivilege"


class ThreatStatus(StrEnum):
    """Lifecycle state of a ThreatScenario.

    State transitions (enforced by validator.py / router.py — not here):

        pending_test  →  pending_human  (Protocol Invariant Validator passed)
                      ↘  pending_test   (retry, max 3 times)
        pending_human →  approved       (human approves)
                      →  rejected       (human rejects → retry or escalate)
    """

    PENDING_TEST = "pending_test"
    PENDING_HUMAN = "pending_human"
    APPROVED = "approved"
    REJECTED = "rejected"


class KBSource(StrEnum):
    """Knowledge-base provenance tags.

    Identifies which threat-intelligence database a KBCandidate was drawn
    from.  Kept as an enum so retrieval.py, attack_chain.py, and scorer.py
    can branch deterministically without string matching.
    """

    STRIDE = "STRIDE"
    CAPEC = "CAPEC"
    ATT_AND_CK = "ATT&CK"
    CWE = "CWE"


# ══════════════════════════════════════════════════════════════════════════════
# § 1  —  EvidenceChain
#         (core explainability unit — one per ThreatScenario)
# ══════════════════════════════════════════════════════════════════════════════


class EvidenceChain(BaseModel):
    """Structured evidence linking a KB pattern to a specific asset.

    This model is the explainability backbone of every ThreatScenario.
    The validator (validator.py) checks each field individually for
    non-emptiness and non-genericity before allowing a scenario to advance
    from ``pending_test`` to ``pending_human``.

    Evidence-completeness score (used by scorer.py — Section 2.6):
        +1.0  all three prose fields are non-empty and non-generic
        +0.5  one field is empty or flagged as generic
        +0.0  two or more fields fail the completeness check
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    exposure: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "The concrete asset attribute, configuration, or interface "
                "property that creates the attack surface.  Must reference a "
                "real field from the system model — not a generic placeholder "
                "such as 'unknown exposure' or 'N/A'."
            ),
        ),
    ]

    matched_pattern: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "The canonical KB pattern identifier that was matched to this "
                "exposure, e.g. 'CAPEC-94', 'ATT&CK T1190', 'CWE-306'.  "
                "Must resolve to a real entry in the KB store — validated "
                "by the Protocol Invariant Validator."
            ),
        ),
    ]

    applicability_reason: Annotated[
        str,
        Field(
            min_length=20,
            description=(
                "LLM-generated prose that explicitly explains WHY the matched "
                "pattern applies to this specific asset and exposure — not a "
                "generic restatement of the pattern description.  Minimum "
                "20 characters enforced to deter single-word placeholders; "
                "the Validator performs a deeper genericity check at runtime."
            ),
        ),
    ]

    citation: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Human-readable citation for the KB entry, e.g.: "
                "'CAPEC-94: Adversary in the Middle (CAPEC v3.9)' or "
                "'MITRE ATT&CK T1190: Exploit Public-Facing Application "
                "(v14.1)'.  Must be non-empty; used by the human reviewer "
                "to verify the evidence without accessing the raw KB."
            ),
        ),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# § 2  —  ThreatScenario
#         (primary output unit of the Threat Agent)
# ══════════════════════════════════════════════════════════════════════════════


# Confidence score type alias — self-documenting at call sites
ConfidenceScore = Annotated[
    float,
    Field(
        ge=0.0,
        le=1.0,
        description=(
            "Weighted confidence score ∈ [0.0, 1.0] computed per the "
            "Section 2.6 formula:\n"
            "  0.4 × retrieval_match_strength\n"
            "+ 0.4 × self_consistency\n"
            "+ 0.2 × evidence_completeness\n"
            "Scores below 0.4 are considered low-confidence and will trigger "
            "a validator warning (not an automatic rejection)."
        ),
    ),
]


class ThreatScenario(BaseModel):
    """A fully structured, evidence-backed threat scenario.

    Produced by generator.py, scored by scorer.py, validated by validator.py,
    and written to the SCRS by state_manager.py after human approval.

    Lifecycle enforced externally (validator.py / router.py):
        pending_test  →  [Validator pass]  →  pending_human
        pending_human →  [Human approve]   →  approved
        pending_human →  [Human reject]    →  rejected (retry or escalate)
        pending_test  →  [Validator fail]  →  pending_test (retry ≤ 3 times)

    Immutability:
        The model is frozen.  State transitions are performed by producing a
        new instance via ``model.model_copy(update={"status": new_status})``.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    tid: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Unique threat identifier within this run.  Convention: "
                "'THR-<run_id>-<zero-padded sequence>', e.g. 'THR-abc123-001'. "
                "Generated by generator.py; immutable after creation."
            ),
        ),
    ]

    asset_id: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Identifier of the system-model asset this scenario targets.  "
                "Must correspond to an asset declared in the originating "
                "ThreatAgentInput.system_model — validated by validator.py."
            ),
        ),
    ]

    stride_category: Annotated[
        STRIDECategory,
        Field(
            description=(
                "STRIDE classification of the threat.  Using the enum (not a "
                "raw string) ensures generator/validator agreement without "
                "string comparison."
            ),
        ),
    ]

    attack_vector: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Human-readable description of the technical attack vector, "
                "e.g. 'Unauthenticated BLE advertisement replay' or "
                "'SQL injection via unvalidated REST query parameter'.  "
                "Must be specific to the asset — not a copy of the KB "
                "pattern title."
            ),
        ),
    ]

    kb_reference: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Primary KB entry identifier this scenario is grounded in, "
                "e.g. 'CAPEC-94', 'ATT&CK T1190', 'CWE-306'.  "
                "The validator confirms this ID resolves to a real KB entry."
            ),
        ),
    ]

    evidence_chain: Annotated[
        EvidenceChain,
        Field(
            description=(
                "Structured evidence that links the KB pattern to the "
                "specific asset and explains applicability.  Required; "
                "a ThreatScenario without evidence is not permitted."
            ),
        ),
    ]

    confidence_score: ConfidenceScore

    status: Annotated[
        ThreatStatus,
        Field(
            default=ThreatStatus.PENDING_TEST,
            description=(
                "Lifecycle state.  Always starts as 'pending_test'; "
                "transitions are driven by validator.py and router.py, "
                "never mutated inside generator.py or scorer.py."
            ),
        ),
    ]

    # ── derived / audit fields ────────────────────────────────────────────────

    created_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp of scenario creation (auto-set).",
        ),
    ]

    run_id: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Identifier of the ThreatAgent run that produced this "
                "scenario.  Ties the scenario to its audit log entry in "
                "common/logging.py and to the SCRS write record."
            ),
        ),
    ]

    @field_validator("confidence_score", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        """Hard-clamp before Pydantic's ge/le check for defensive safety.

        Rationale: floating-point arithmetic in scorer.py may produce values
        like 1.0000000000000002 due to IEEE 754 rounding.  Clamping here
        prevents spurious ValidationError while keeping the semantic range.
        """
        return max(0.0, min(1.0, float(v)))


# ══════════════════════════════════════════════════════════════════════════════
# § 3  —  ValidationResult
#         (output of validator.py — drives retry logic)
# ══════════════════════════════════════════════════════════════════════════════


class FailedCheck(BaseModel):
    """A single failed invariant check from the Protocol Invariant Validator.

    Structured as its own model (not a bare ``str``) so that router.py and
    the retry loop can branch on ``check_id`` without parsing free text.
    """

    model_config = ConfigDict(frozen=True)

    check_id: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Machine-readable identifier for the failed check, e.g. "
                "'CITATION_MISSING', 'CONFIDENCE_BELOW_THRESHOLD', "
                "'ASSET_REF_INVALID', 'EVIDENCE_GENERIC'."
            ),
        ),
    ]

    affected_tid: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "``tid`` of the ThreatScenario that triggered this failure, "
                "or ``None`` if the failure is batch-level (e.g. empty output)."
            ),
        ),
    ]

    detail: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Human-readable explanation of why the check failed.  "
                "This text is passed verbatim as context to the retry prompt "
                "in generator.py — it must be actionable, not just a code."
            ),
        ),
    ]


class ValidationResult(BaseModel):
    """Outcome of one Protocol Invariant Validator execution.

    Consumed by:
    • router.py   — to gate state transition from pending_test → pending_human
    • generator.py — the ``detail`` strings in ``failed_checks`` are injected
                     into the retry prompt so the LLM understands what to fix.
    • scorer.py   — ``passed`` and ``failed_checks`` inform the
                     evidence-completeness component of the confidence score.

    Retry-count contract (Section 2.2 / 2.6 of build plan):
        retry_count starts at 0 on the first validator call and increments by 1
        on each failure before the next LLM invocation.  At retry_count == 3
        the system must NOT call the LLM again; instead it escalates to human
        review as a *flagged* failure with status ``pending_human``.
    """

    model_config = ConfigDict(frozen=True)

    passed: Annotated[
        bool,
        Field(
            description=(
                "True iff every invariant check passed.  "
                "When False, ``failed_checks`` will be non-empty."
            ),
        ),
    ]

    failed_checks: Annotated[
        list[FailedCheck],
        Field(
            default_factory=list,
            description=(
                "Ordered list of invariant checks that failed.  Empty when "
                "``passed`` is True.  Each entry is a structured FailedCheck "
                "rather than a bare string so retry logic can branch "
                "programmatically on ``check_id``."
            ),
        ),
    ]

    retry_count: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            le=3,
            description=(
                "Number of LLM retry attempts consumed so far for this "
                "validation cycle.  Strictly capped at 3 (le=3).  "
                "validator.py raises ``MaxRetriesExceededError`` if an "
                "attempt is made to increment beyond this limit."
            ),
        ),
    ]

    validated_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp of this validation run (auto-set).",
        ),
    ]

    @model_validator(mode="after")
    def _check_passed_consistency(self) -> ValidationResult:
        """Enforce semantic consistency between ``passed`` and ``failed_checks``.

        Invariants:
          • passed=True  must imply failed_checks is empty.
          • passed=False must imply failed_checks is non-empty.

        This prevents the silent ambiguity of a model reporting success while
        carrying failure details (or vice-versa), which would break retry logic.
        """
        if self.passed and self.failed_checks:
            raise ValueError(
                "ValidationResult is inconsistent: passed=True but "
                f"failed_checks is non-empty ({len(self.failed_checks)} items). "
                "Set passed=False or clear failed_checks."
            )
        if not self.passed and not self.failed_checks:
            raise ValueError(
                "ValidationResult is inconsistent: passed=False but "
                "failed_checks is empty.  Provide at least one FailedCheck "
                "so the retry loop has actionable context."
            )
        return self


# ══════════════════════════════════════════════════════════════════════════════
# § 4  —  KBCandidate
#         (output of retrieval.py — input to attack_chain.py)
# ══════════════════════════════════════════════════════════════════════════════


class KBCandidate(BaseModel):
    """A single ranked KB pattern retrieved for a given asset attribute.

    Produced by retrieval.py (FAISS nearest-neighbour search) and consumed
    by attack_chain.py to build AttackPath objects, and by scorer.py to
    compute the retrieval_match_strength component of the confidence score.
    """

    model_config = ConfigDict(frozen=True)

    pattern_id: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Canonical KB pattern identifier, e.g. 'CAPEC-94', "
                "'ATT&CK T1190', 'CWE-306'.  Must be unique within a "
                "retrieval result set for a given asset."
            ),
        ),
    ]

    source: Annotated[
        KBSource,
        Field(description="Knowledge-base provenance (STRIDE/CAPEC/ATT&CK/CWE)."),
    ]

    title: Annotated[
        str,
        Field(
            min_length=1,
            description="Human-readable title of the KB pattern.",
        ),
    ]

    description: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Full description of the threat pattern as stored in the KB. "
                "Passed to generator.py as context for the LLM prompt."
            ),
        ),
    ]

    retrieval_score: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description=(
                "Normalized similarity score from FAISS (L2-to-cosine "
                "converted, range [0, 1]).  Used directly as the "
                "retrieval_match_strength input for scorer.py (Section 2.6)."
            ),
        ),
    ]

    asset_id: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "ID of the asset whose attributes were used as the FAISS "
                "query vector to retrieve this candidate."
            ),
        ),
    ]

    stride_hint: Annotated[
        STRIDECategory | None,
        Field(
            default=None,
            description=(
                "Optional STRIDE classification hint embedded in the KB entry. "
                "When present, generator.py uses this as a prior; when absent, "
                "the LLM infers the STRIDE category from context."
            ),
        ),
    ]

    mitre_tactics: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "MITRE ATT&CK tactic IDs associated with this pattern "
                "(e.g. ['TA0001', 'TA0003']).  Empty list when the source "
                "is not ATT&CK or no tactic mapping exists."
            ),
        ),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# § 5  —  AttackPath
#         (output of attack_chain.py — input to generator.py)
# ══════════════════════════════════════════════════════════════════════════════


class AttackPath(BaseModel):
    """A plausible multi-step attack path composed of linked KB candidates.

    attack_chain.py constructs these by topologically ordering KBCandidates
    such that the post-condition of step N is a pre-condition of step N+1.
    This captures realistic kill-chain sequences (e.g. Reconnaissance →
    Initial Access → Lateral Movement) rather than treating each threat in
    isolation.

    Design note (Section 2.4 of build plan):
        attack_chain.py must *not* force a chain if no plausible link exists.
        Use ``is_forced=True`` to flag chains where the link is inferred
        rather than pattern-evidenced — scorer.py will penalise forced chains.

    Generator consumption:
        generator.py receives a list[AttackPath].  Each path produces one
        or more ThreatScenario objects.  The path's ``path_id`` is embedded
        in each scenario's ``tid`` prefix for traceability.
    """

    model_config = ConfigDict(frozen=True)

    path_id: Annotated[
        str,
        Field(
            default_factory=lambda: f"PATH-{uuid.uuid4().hex[:8].upper()}",
            description=(
                "Unique identifier for this attack path within a run.  "
                "Auto-generated; embedded in derived ThreatScenario ``tid``s."
            ),
        ),
    ]

    steps: Annotated[
        list[KBCandidate],
        Field(
            min_length=1,
            description=(
                "Ordered list of KB candidates that form the attack chain, "
                "from earliest (reconnaissance / initial access) to latest "
                "(impact / exfiltration).  Must contain at least one step; "
                "single-step paths are valid when no multi-step chain exists."
            ),
        ),
    ]

    target_asset_ids: Annotated[
        list[str],
        Field(
            min_length=1,
            description=(
                "Asset IDs that this path ultimately threatens.  May span "
                "multiple assets for lateral-movement chains."
            ),
        ),
    ]

    is_forced: Annotated[
        bool,
        Field(
            default=False,
            description=(
                "True when attack_chain.py could not find a pattern-evidenced "
                "link between consecutive steps and inferred the connection.  "
                "Scorer penalises forced chains; Validator emits a warning "
                "check (not a hard failure) when this is True."
            ),
        ),
    ]

    chain_confidence: Annotated[
        float,
        Field(
            ge=0.0,
            le=1.0,
            description=(
                "Aggregate plausibility score for the chain as a whole, "
                "computed by attack_chain.py as the geometric mean of "
                "individual step retrieval_scores, discounted by 0.1 "
                "if is_forced=True.  Used by scorer.py as a secondary "
                "signal for the retrieval_match_strength component."
            ),
        ),
    ]

    reasoning: Annotated[
        str,
        Field(
            default="",
            description=(
                "Free-text explanation of why these steps form a plausible "
                "chain.  Populated by attack_chain.py; passed to generator.py "
                "as chain-level context in the LLM prompt."
            ),
        ),
    ]

    @model_validator(mode="after")
    def _validate_chain_ordering(self) -> AttackPath:
        """Verify there are no duplicate pattern_ids within the same path.

        Duplicate KB patterns in a single chain indicate a logic error in
        attack_chain.py (a loop in the candidate graph), not a legitimate
        multi-step sequence.
        """
        seen: set[str] = set()
        for step in self.steps:
            if step.pattern_id in seen:
                raise ValueError(
                    f"AttackPath '{self.path_id}' contains duplicate "
                    f"pattern_id '{step.pattern_id}'.  Each step in a chain "
                    "must reference a distinct KB pattern."
                )
            seen.add(step.pattern_id)
        return self


# ══════════════════════════════════════════════════════════════════════════════
# § 6  —  ThreatAgent I/O  (Perceive → Produce boundary models)
# ══════════════════════════════════════════════════════════════════════════════


class AssetModel(BaseModel):
    """A single asset entry from the system model provided by the orchestrator.

    Kept deliberately domain-neutral — fields apply equally to a Smart Door
    Lock BLE controller, a medical infusion pump, and a vehicle ECU.
    """

    model_config = ConfigDict(frozen=True)

    asset_id: Annotated[
        str,
        Field(min_length=1, description="Unique asset identifier in the system model."),
    ]

    name: Annotated[
        str,
        Field(min_length=1, description="Human-readable asset name."),
    ]

    asset_type: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Asset category, e.g. 'firmware', 'REST API endpoint', "
                "'BLE peripheral', 'CAN bus node', 'cloud backend'."
            ),
        ),
    ]

    interfaces: Annotated[
        list[str],
        Field(
            default_factory=list,
            description=(
                "Communication interfaces exposed by this asset, e.g. "
                "['BLE 5.0', 'UART', 'OTA update channel']."
            ),
        ),
    ]

    trust_zone: Annotated[
        str,
        Field(
            default="untrusted",
            description=(
                "Trust boundary zone in the DFD/UML system model, "
                "e.g. 'trusted', 'untrusted', 'DMZ', 'internal'."
            ),
        ),
    ]

    attributes: Annotated[
        dict[str, str],
        Field(
            default_factory=dict,
            description=(
                "Arbitrary key-value properties relevant to threat modelling, "
                "e.g. {'auth_mechanism': 'PIN-only', 'encryption': 'none', "
                "'firmware_version': '2.3.1'}.  These are the primary "
                "inputs to retrieval.py's FAISS query embedding."
            ),
        ),
    ]


class ThreatAgentInput(BaseModel):
    """Top-level input payload sent by the orchestrator to the Threat Agent.

    After PII redaction (middleware.py), this is passed to perceive().
    Must not assume any domain — valid for Smart Door Lock, infusion pump,
    vehicle ECU, and any future fixture.
    """

    model_config = ConfigDict(frozen=True)

    run_id: Annotated[
        str,
        Field(
            default_factory=lambda: uuid.uuid4().hex,
            description=(
                "Unique identifier for this Threat Agent invocation.  "
                "Auto-generated if not supplied by the orchestrator.  "
                "Propagated to every ThreatScenario, log entry, and "
                "SCRS write record."
            ),
        ),
    ]

    use_case: Annotated[
        str,
        Field(
            min_length=10,
            description=(
                "Natural-language description of the system use case being "
                "threat-modelled.  Minimum 10 chars to reject trivially empty "
                "submissions; the LLM uses this as the top-level context."
            ),
        ),
    ]

    system_model: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Serialized system model (DFD/UML description, data flows, "
                "trust boundaries) as a string.  Structured formats (JSON/YAML) "
                "are accepted; perceive() normalises this into NormalizedInput."
            ),
        ),
    ]

    assets: Annotated[
        list[AssetModel],
        Field(
            min_length=1,
            description=(
                "Ordered list of assets within the system model.  "
                "Must contain at least one asset; retrieval.py iterates "
                "over this list to build FAISS query vectors."
            ),
        ),
    ]

    kb_snapshot_version: Annotated[
        str,
        Field(
            default="latest",
            description=(
                "Version or content-hash of the KB snapshot to use.  "
                "Logged verbatim for reproducibility (Section 2.7).  "
                "Use 'latest' to resolve to the current KB at runtime."
            ),
        ),
    ]

    requested_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp when the orchestrator submitted this input.",
        ),
    ]


class NormalizedInput(BaseModel):
    """Output of perceive(): a sanitized, PII-free, structured input.

    perceive() transforms the raw ThreatAgentInput into this model, which
    is the only form that crosses the boundary into plan(), fetch(), etc.
    Any PII field identified during normalization is replaced with a
    ``[REDACTED]`` token before this model is constructed.
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    use_case: str
    assets: list[AssetModel]
    kb_snapshot_version: str
    system_model_summary: Annotated[
        str,
        Field(
            description=(
                "Structured, normalised summary of the system model.  "
                "perceive() extracts trust boundaries and data flows from "
                "the raw system_model string into this field."
            ),
        ),
    ]
    pii_redacted: Annotated[
        bool,
        Field(
            default=False,
            description="True if at least one PII token was redacted by middleware.",
        ),
    ]


class RetrievalPlan(BaseModel):
    """Output of plan(): specifies which KB categories to query per asset.

    plan() produces this after reasoning about which STRIDE/CAPEC/ATT&CK/CWE
    categories are relevant for each asset's type, interfaces, and trust zone.
    retrieval.py executes the plan against the FAISS index.
    """

    model_config = ConfigDict(frozen=True)

    run_id: str

    queries: Annotated[
        list[dict[str, str | list[str]]],
        Field(
            min_length=1,
            description=(
                "List of retrieval queries, one per asset-category combination.  "
                "Each entry: {'asset_id': str, 'kb_sources': list[KBSource], "
                "'query_text': str}.  retrieval.py iterates this list."
            ),
        ),
    ]

    top_k: Annotated[
        int,
        Field(
            default=10,
            ge=1,
            le=50,
            description=(
                "Maximum number of KB candidates to retrieve per query.  "
                "Default 10; increase for broad assets, decrease for "
                "narrowly-scoped components."
            ),
        ),
    ]


class SCRSWriteResult(BaseModel):
    """Outcome of writing approved scenarios to the Shared Reasoning State.

    Returned by produce() after state_manager.py commits the approved
    ThreatScenario list to the SCRS.  The Risk Agent reads the SCRS
    using the ``scrs_entry_id`` to locate this run's threat output.
    """

    model_config = ConfigDict(frozen=True)

    run_id: str

    scrs_entry_id: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Stable SCRS key under which the approved ThreatScenario list "
                "is stored.  Communicated to the Risk Agent by the orchestrator."
            ),
        ),
    ]

    scenario_count: Annotated[
        int,
        Field(
            ge=0,
            description="Number of approved ThreatScenario objects written to SCRS.",
        ),
    ]

    written_at: Annotated[
        datetime,
        Field(
            default_factory=lambda: datetime.now(UTC),
            description="UTC timestamp of the SCRS write operation.",
        ),
    ]

    audit_log_ref: Annotated[
        str,
        Field(
            description=(
                "Reference to the structured audit log entry for this write, "
                "formatted as '<log_file>:<line_offset>' or a log-store ID."
            ),
        ),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# § 7  —  Module-level exports
# ══════════════════════════════════════════════════════════════════════════════

__all__: list[str] = [
    # Enumerations
    "STRIDECategory",
    "ThreatStatus",
    "KBSource",
    # Core domain models
    "EvidenceChain",
    "ThreatScenario",
    "FailedCheck",
    "ValidationResult",
    "KBCandidate",
    "AttackPath",
    # I/O boundary models
    "AssetModel",
    "ThreatAgentInput",
    "NormalizedInput",
    "RetrievalPlan",
    "SCRSWriteResult",
    # Type aliases
    "ConfidenceScore",
]
