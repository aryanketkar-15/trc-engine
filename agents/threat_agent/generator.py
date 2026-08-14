"""
agents/threat_agent/generator.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Threat Scenario Generator  (Chetan)
──────────────────────────────────────────────────────────────────────────────
Pipeline position:
    retrieval.py → [list[KBCandidate] via AttackPath] → generator.py
                                                      → [list[ThreatScenario]]
                                                      → validator.py (Shriraj)

Responsibility:
    This module is the LLM-reasoning half of the hybrid framework.
    Given attack paths (ordered lists of KB candidates) and normalized system
    context (assets, data flows, use case), it calls an LLM to:
      1. Classify each path/candidate into a STRIDE category.
      2. Draft a specific attack_vector description for the asset.
      3. Produce a fully populated EvidenceChain with a written
         applicability_reason that explains WHY the KB pattern applies to
         this exact asset — not a generic restatement of the pattern.
      4. Assign a preliminary confidence_score (scorer.py later refines it
         with retrieval_match_strength + self_consistency; this module
         supplies the evidence_completeness signal via the EvidenceChain).

    Deterministic scoring (Section 2.6 weighted formula) is scorer.py's job.
    State transitions (pending_test → pending_human) are validator.py's job.
    This module never mutates a ThreatScenario after construction.

Reproducibility stance (Section 2.7):
    All LLM calls use a fixed low temperature (LLM_TEMPERATURE, default 0.1)
    to reduce run-to-run variance.  Every call logs: prompt template version,
    model version string, KB snapshot version, and the full rendered prompt.
    Exact wording is not guaranteed to be bit-identical across runs, but
    threat coverage and citations are consistent given the same KB snapshot
    and low-temperature generation.

LLM client:
    Calls are delegated to common.llm_client (Manthan's module — stubbed here
    with a clear interface).  No API key appears in this file; keys are loaded
    exclusively from environment variables via config/settings.py.

TODO (validate against retrieval.py once it lands on develop):
    - generator() currently accepts list[AttackPath] (from attack_chain.py),
      which wraps list[KBCandidate] internally.  Confirm with Aryan that
      fetch_candidates() → attack_chain.py → list[AttackPath] is the agreed
      handoff, OR adjust if attack_chain.py is skipped in early integration
      and generator.py receives list[KBCandidate] directly.
    - Validate STRIDE_VECTOR_VOCABULARY import once retrieval.py merges.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import TYPE_CHECKING

from agents.threat_agent.exceptions import EmptyAttackPathError
from agents.threat_agent.schemas import (
    AttackPath,
    EvidenceChain,
    KBCandidate,
    NormalizedInput,
    STRIDECategory,
    ThreatScenario,
    ThreatStatus,
)

if TYPE_CHECKING:
    pass  # future: import common.llm_client types here when Manthan's module lands

try:
    from common.logging import get_logger, log_step

    logger = get_logger(__name__)
except ImportError:
    import logging

    logger = logging.getLogger(__name__)

    def log_step(
        logger: logging.Logger,
        level: str,
        step: str,
        run_id: str,
        payload: dict | None = None,
    ) -> None:
        """Fallback log_step implementation until common.logging is on develop."""
        record = {
            "step": step,
            "run_id": run_id,
            "payload": payload or {},
        }
        getattr(logger, level.lower())(json.dumps(record))

# ─── Configuration constants (all overridable via environment variables) ──────

#: LLM model identifier — sourced from env, never hardcoded.
#: Must match a model string accepted by common/llm_client.py.
LLM_MODEL: str = os.environ.get("TRC_LLM_MODEL", "gpt-4o-mini")

#: Fixed low temperature for reproducibility (Section 2.7).
LLM_TEMPERATURE: float = float(os.environ.get("TRC_LLM_TEMPERATURE", "0.1"))

#: Prompt template version — logged with every LLM call for audit.
PROMPT_TEMPLATE_VERSION: str = "v1.0.0"

#: Minimum acceptable evidence_completeness contribution; scenarios below
#: this are flagged (not rejected) so the validator can emit a warning.
MIN_EVIDENCE_COMPLETENESS: float = 0.5

# ─── Sentinel error types (typed, not bare exceptions) ────────────────────────


class LLMResponseError(ValueError):
    """Raised when the LLM returns a response that cannot be parsed or is
    structurally invalid (e.g. missing required keys, wrong types).

    Not the same as a transport/timeout error, which is raised by
    common/llm_client.py and propagates unchanged to the caller.
    """


# ─── Prompt construction ──────────────────────────────────────────────────────


def _build_system_prompt() -> str:
    """Return the static system-role prompt for the threat-generation LLM call.

    Kept in this module so it is version-controlled alongside the generation
    logic.  Long-term: move to prompts.py when Chetan's prompts module exists.

    Returns:
        The system prompt string.  Language is domain-neutral — valid for
        Smart Door Lock, infusion pump, vehicle ECU, and any future fixture.
    """
    return (
        "You are a senior cybersecurity threat modeller with deep expertise in "
        "STRIDE, CAPEC, MITRE ATT&CK, and CWE. "
        "Your task is to analyse a system asset and a retrieved knowledge-base "
        "attack pattern, then produce a structured threat scenario. "
        "Every scenario you produce MUST:\n"
        "  1. Classify the threat into exactly one STRIDE category "
        "(Spoofing, Tampering, Repudiation, InformationDisclosure, "
        "DenialOfService, ElevationOfPrivilege).\n"
        "  2. Describe a specific attack_vector for the named asset — "
        "do NOT copy the KB pattern title verbatim.\n"
        "  3. Provide a non-generic applicability_reason that explicitly "
        "explains WHY this KB pattern applies to this specific asset, "
        "referencing concrete asset properties (interfaces, trust zone, "
        "auth mechanism, etc.).\n"
        "  4. Output ONLY valid JSON — no markdown fences, no commentary "
        "outside the JSON object.\n"
        "  5. Be concise but precise.  Vague placeholders like 'unknown' "
        "or 'N/A' are forbidden and will cause the scenario to be rejected.\n"
    )


def _build_user_prompt(
    path: AttackPath,
    context: NormalizedInput,
) -> str:
    """Render the per-path user-role prompt from an AttackPath and system context.

    This prompt is logged verbatim (Section 2.7 reproducibility) so it must
    contain no secrets and no PII (middleware.py guarantees PII is redacted
    before context reaches this module).

    Args:
        path:    The AttackPath to generate scenarios for.
        context: The NormalizedInput produced by perceive() — PII-free.

    Returns:
        Rendered prompt string passed to the LLM as the ``user`` message.
    """
    # Build a compact JSON representation of each step for the prompt.
    steps_json = json.dumps(
        [
            {
                "pattern_id": step.pattern_id,
                "source": step.source,
                "title": step.title,
                "description": step.description,
                "stride_hint": step.stride_hint,
                "retrieval_score": step.retrieval_score,
                "mitre_tactics": step.mitre_tactics,
            }
            for step in path.steps
        ],
        indent=2,
    )

    # Gather the assets targeted by this path so the LLM knows which ones
    # to reference in attack_vector and applicability_reason.
    target_assets = [a for a in context.assets if a.asset_id in path.target_asset_ids]
    assets_json = json.dumps(
        [
            {
                "asset_id": a.asset_id,
                "name": a.name,
                "asset_type": a.asset_type,
                "interfaces": a.interfaces,
                "trust_zone": a.trust_zone,
                "attributes": a.attributes,
            }
            for a in target_assets
        ],
        indent=2,
    )

    return (
        f"USE CASE:\n{context.use_case}\n\n"
        f"SYSTEM MODEL SUMMARY:\n{context.system_model_summary}\n\n"
        f"TARGET ASSETS:\n{assets_json}\n\n"
        f"ATTACK PATH (path_id={path.path_id}, is_forced={path.is_forced}):\n"
        f"Chain reasoning: {path.reasoning or 'not provided'}\n"
        f"Steps:\n{steps_json}\n\n"
        "TASK:\n"
        "For EACH step in the attack path, produce one JSON object with these "
        "exact keys:\n"
        "  {\n"
        '    "asset_id": "<the asset_id from TARGET ASSETS this step threatens>",\n'
        '    "stride_category": "<one of: Spoofing|Tampering|Repudiation|'
        'InformationDisclosure|DenialOfService|ElevationOfPrivilege>",\n'
        '    "attack_vector": "<specific vector for the named asset>",\n'
        '    "kb_reference": "<pattern_id from this step>",\n'
        '    "exposure": "<concrete asset attribute/interface that creates the '
        'attack surface>",\n'
        '    "matched_pattern": "<same pattern_id as kb_reference>",\n'
        '    "applicability_reason": "<min 20 chars: WHY this pattern applies '
        'to this asset — reference its specific properties>",\n'
        '    "citation": "<human-readable KB citation, e.g. CAPEC-94: Adversary '
        'in the Middle (CAPEC v3.9)>"\n'
        "  }\n\n"
        "Return a JSON array of these objects — one per step.  "
        "No extra keys.  No markdown."
    )


# ─── LLM call stub ────────────────────────────────────────────────────────────


def _call_llm(system_prompt: str, user_prompt: str, run_id: str) -> str:
    """Invoke the LLM and return the raw response string.

    This is a STUB.  The real implementation delegates to
    ``common.llm_client.chat_completion()`` (Manthan's module), which
    provides timeout, exponential-backoff retry, and per-run cost ceiling.

    Args:
        system_prompt: The system-role message for the LLM.
        user_prompt:   The user-role message containing the attack path data.
        run_id:        Propagated to structured log entries for this call.

    Returns:
        Raw string response from the LLM (expected to be valid JSON).

    Raises:
        common.llm_client.LLMTimeoutError: On request timeout.
        common.llm_client.LLMAPIError: On rate-limit / API errors
            (exponential backoff exhausted).
        LLMResponseError: If the response cannot be decoded as UTF-8 text.

    TODO (Manthan):
        Replace this stub body with:
            from common.llm_client import chat_completion
            return chat_completion(
                model=LLM_MODEL,
                temperature=LLM_TEMPERATURE,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                run_id=run_id,
            )
    """
    # STUB — logs the call and raises NotImplementedError so integration
    # tests that mock this function work without a live API key.
    log_step(
        logger,
        "INFO",
        "llm_call_stub",
        run_id,
        {
            "model": LLM_MODEL,
            "temperature": LLM_TEMPERATURE,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "status": "stub",
        },
    )
    raise NotImplementedError(
        "_call_llm() is a stub.  "
        "Replace with common.llm_client.chat_completion() call "
        "once Manthan's LLM client module is available on develop."
    )


# ─── Response parsing ─────────────────────────────────────────────────────────

_REQUIRED_RESPONSE_KEYS = frozenset(
    {
        "asset_id",
        "stride_category",
        "attack_vector",
        "kb_reference",
        "exposure",
        "matched_pattern",
        "applicability_reason",
        "citation",
    }
)


def _parse_llm_response(raw: str, path: AttackPath, run_id: str) -> list[dict]:  # type: ignore[type-arg]
    """Parse the LLM's raw JSON response into a list of scenario dicts.

    Args:
        raw:    Raw string returned by _call_llm().
        path:   The AttackPath the response corresponds to (for error context).
        run_id: Propagated to error messages and log entries.

    Returns:
        List of dicts, one per attack-path step, each containing the keys
        enumerated in _REQUIRED_RESPONSE_KEYS.

    Raises:
        LLMResponseError: On JSON decode failure, wrong top-level type,
                          or missing required keys in any item.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMResponseError(
            f"[run={run_id}, path={path.path_id}] "
            f"LLM returned non-JSON response: {exc}. "
            f"Raw (first 200 chars): {raw[:200]!r}"
        ) from exc

    if not isinstance(data, list):
        raise LLMResponseError(
            f"[run={run_id}, path={path.path_id}] "
            f"Expected JSON array at top level; got {type(data).__name__}."
        )

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise LLMResponseError(
                f"[run={run_id}, path={path.path_id}] "
                f"Item {idx} is not a JSON object (got {type(item).__name__})."
            )
        missing = _REQUIRED_RESPONSE_KEYS - item.keys()
        if missing:
            raise LLMResponseError(
                f"[run={run_id}, path={path.path_id}] "
                f"Item {idx} is missing required keys: {sorted(missing)}."
            )

    return data  # type: ignore[return-value]


# ─── ThreatScenario construction ──────────────────────────────────────────────


def _make_scenario(
    item: dict,  # type: ignore[type-arg]
    path: AttackPath,
    run_id: str,
    seq: int,
) -> ThreatScenario:
    """Construct an immutable ThreatScenario from one parsed LLM response item.

    Args:
        item:   Parsed dict from the LLM response (validated by
                _parse_llm_response).
        path:   The originating AttackPath (for tid prefix + traceability).
        run_id: The ThreatAgent run identifier.
        seq:    Zero-based sequence number within this path's scenarios.

    Returns:
        A fully constructed, frozen ThreatScenario in PENDING_TEST status.

    Raises:
        pydantic.ValidationError: If the item data violates schema constraints
            (e.g. confidence_score out of range, empty required fields).
            This is intentional — let Pydantic surface bad LLM output immediately
            rather than passing invalid objects downstream.
        KeyError: If a required key is absent (should not happen after
            _parse_llm_response validation, but kept for defence-in-depth).
    """
    # tid format: THR-<path_id>-<zero-padded seq>
    # Example:    THR-PATH-A1B2C3D4-001
    tid = f"THR-{path.path_id}-{seq + 1:03d}"

    evidence = EvidenceChain(
        exposure=item["exposure"],
        matched_pattern=item["matched_pattern"],
        applicability_reason=item["applicability_reason"],
        citation=item["citation"],
    )

    # Preliminary confidence_score: set to the mean retrieval_score of path
    # steps as a reasonable initial estimate.  scorer.py overwrites this with
    # the full Section 2.6 formula (retrieval_strength + self_consistency +
    # evidence_completeness).
    preliminary_score: float = (
        sum(s.retrieval_score for s in path.steps) / len(path.steps)
        if path.steps
        else 0.0
    )

    return ThreatScenario(
        tid=tid,
        asset_id=item["asset_id"],
        stride_category=STRIDECategory(item["stride_category"]),
        attack_vector=item["attack_vector"],
        kb_reference=item["kb_reference"],
        evidence_chain=evidence,
        confidence_score=preliminary_score,
        status=ThreatStatus.PENDING_TEST,
        run_id=run_id,
    )


# ─── Public interface ─────────────────────────────────────────────────────────


def generate_scenarios(
    paths: list[AttackPath],
    context: NormalizedInput,
    *,
    validation_failure_context: list[str] | None = None,
) -> list[ThreatScenario]:
    """Generate threat scenarios for a list of attack paths.

    This is the primary entry point for generator.py.  It is called:
      - On the initial generation pass by the ThreatAgent orchestration loop.
      - On retry passes (max 3, enforced by validator.py) with
        ``validation_failure_context`` populated from FailedCheck.detail
        strings so the LLM understands what to fix.

    Pipeline:
        attack_chain.py → list[AttackPath] → generate_scenarios()
                                           → list[ThreatScenario]
                                           → scorer.py (confidence refinement)
                                           → validator.py (invariant checks)

    Args:
        paths:
            Non-empty list of AttackPath objects produced by attack_chain.py.
            Each path wraps one or more KBCandidate steps.
        context:
            NormalizedInput from perceive() — contains assets, use_case,
            system_model_summary, run_id, and kb_snapshot_version.
            PII is guaranteed redacted by middleware.py before this point.
        validation_failure_context:
            Optional list of FailedCheck.detail strings from a prior
            ValidationResult.  When present, these are prepended to each
            user prompt so the LLM can correct specific deficiencies.
            Pass None (default) on the first generation attempt.

    Returns:
        List of ThreatScenario objects, one per (path × step) combination.
        Each scenario:
          - Has status=PENDING_TEST (lifecycle managed externally).
          - Carries a populated EvidenceChain.
          - Has a preliminary confidence_score (scorer.py refines this).
          - Is immutable (frozen Pydantic model).

    Raises:
        EmptyAttackPathError:  If ``paths`` is empty.
        LLMResponseError:      If the LLM response cannot be parsed.
        NotImplementedError:   While _call_llm() is a stub (Week 1-2).
        pydantic.ValidationError: If LLM output violates schema constraints.

    Note on KB snapshot logging (Section 2.7):
        kb_snapshot_version is logged with every call.  When scorer.py runs
        self_consistency sampling (N=3 runs at low temperature), it calls
        this function directly — the run_id stays the same so all consistency
        samples are tied to the same audit log entry.
    """
    run_id = context.run_id

    if not paths:
        raise EmptyAttackPathError(
            f"[run={run_id}] generate_scenarios() received an empty attack-path "
            "list.  Retrieval must return at least one candidate for at least "
            "one asset before generation can proceed."
        )

    # Structured log entry: Observe step start (Section 2.9 format)
    log_step(
        logger,
        "INFO",
        "observe_start",
        run_id,
        {
            "path_count": len(paths),
            "kb_snapshot_version": context.kb_snapshot_version,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "model": LLM_MODEL,
            "temperature": LLM_TEMPERATURE,
            "retry": validation_failure_context is not None,
            "status": "started",
        },
    )

    system_prompt = _build_system_prompt()
    # Prepend failure context on retry so LLM knows what to fix.
    retry_preamble = ""
    if validation_failure_context:
        failure_lines = "\n".join(
            f"  - {detail}" for detail in validation_failure_context
        )
        retry_preamble = (
            "IMPORTANT — THIS IS A RETRY.  The previous generation attempt "
            "failed the Protocol Invariant Validator.  You MUST fix ALL of "
            "the following issues in your new output:\n"
            f"{failure_lines}\n\n"
        )

    scenarios: list[ThreatScenario] = []
    seq = 0  # global scenario sequence across all paths

    for path in paths:
        user_prompt = retry_preamble + _build_user_prompt(path, context)

        log_step(
            logger,
            "INFO",
            "llm_call_start",
            run_id,
            {
                "path_id": path.path_id,
                "step_count": len(path.steps),
                "is_forced": path.is_forced,
                "status": "pending",
            },
        )

        raw_response = _call_llm(system_prompt, user_prompt, run_id)

        items = _parse_llm_response(raw_response, path, run_id)

        for item in items:
            scenario = _make_scenario(item, path, run_id, seq)
            scenarios.append(scenario)
            seq += 1

        log_step(
            logger,
            "INFO",
            "observe_path_complete",
            run_id,
            {
                "path_id": path.path_id,
                "scenarios_produced": len(items),
                "status": "ok",
            },
        )

    log_step(
        logger,
        "INFO",
        "observe_end",
        run_id,
        {
            "total_scenarios": len(scenarios),
            "status": "ok",
        },
    )

    return scenarios


# ─── Direct-KBCandidate convenience wrapper ───────────────────────────────────


def generate_from_candidates(
    candidates: list[KBCandidate],
    context: NormalizedInput,
    *,
    validation_failure_context: list[str] | None = None,
) -> list[ThreatScenario]:
    """Test-only convenience wrapper that converts a flat list of KBCandidates
    into single-step AttackPaths and delegates to generate_scenarios().

    Note (Architecture confirmation from Aryan):
        The production pipeline is mandatory:
            retrieval.fetch_candidates() -> attack_chain.build_paths()
            -> generate_scenarios()
        generate_from_candidates() is TEST-ONLY / fallback for unit testing
        without running full chain analysis. It is NOT a production entry point.

    Args:
        candidates:
            Flat list of KBCandidate objects from retrieval.py.  Each is
            wrapped in a single-step AttackPath for generation purposes.
        context:
            NormalizedInput — same as generate_scenarios().
        validation_failure_context:
            Passed through to generate_scenarios() unchanged.

    Returns:
        list[ThreatScenario] — same contract as generate_scenarios().

    Raises:
        EmptyAttackPathError: If ``candidates`` is empty.
    """
    if not candidates:
        raise EmptyAttackPathError(
            f"[run={context.run_id}] generate_from_candidates() received an "
            "empty candidate list.  Retrieval must return at least one "
            "KBCandidate before generation can proceed."
        )

    # Wrap each candidate in a minimal single-step AttackPath.
    paths = [
        AttackPath(
            path_id=f"PATH-{uuid.uuid4().hex[:8].upper()}",
            steps=[candidate],
            target_asset_ids=[candidate.asset_id],
            is_forced=False,
            chain_confidence=candidate.retrieval_score,
            reasoning=(
                f"Single-step path wrapping KBCandidate {candidate.pattern_id} "
                f"(attack_chain.py not yet integrated)."
            ),
        )
        for candidate in candidates
    ]

    return generate_scenarios(
        paths,
        context,
        validation_failure_context=validation_failure_context,
    )
