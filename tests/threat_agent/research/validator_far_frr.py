"""
tests/threat_agent/research/validator_far_frr.py
────────────────────────────────────────────────
Protocol Invariant Validator FAR/FRR Measurement Suite.

Evaluates the Protocol Invariant Validator (agents/threat_agent/validator.py)
against a ground-truth labeled benchmark dataset containing valid and invalid
ThreatScenario objects.

Measures:
  - False Acceptance Rate (FAR): Invalid scenarios incorrectly passed by the validator.
  - False Rejection Rate (FRR): Valid scenarios incorrectly rejected by the validator.
  - True Acceptance Rate (TAR): Valid scenarios correctly passed (1 - FRR).
  - True Rejection Rate (TRR): Invalid scenarios correctly rejected (1 - FAR).
  - Check-level breakdown: Detection performance across all 4 validator invariant checks:
      * Citation Presence (CHECK_CITATION_MISSING)
      * Schema Completeness (CHECK_SCHEMA_INCOMPLETE)
      * STRIDE Consistency (CHECK_CONSISTENCY_MISMATCH)
      * Evidence Detail (CHECK_EVIDENCE_GENERIC)

Run standalone:
    python tests/threat_agent/research/validator_far_frr.py

Run via pytest:
    pytest tests/threat_agent/research/validator_far_frr.py -v
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import agents.threat_agent.validator as validator_module  # noqa: E402
from agents.threat_agent.schemas import (  # noqa: E402
    EvidenceChain,
    STRIDECategory,
    ThreatScenario,
    ValidationResult,
)
from agents.threat_agent.validator import (  # noqa: E402
    CHECK_CITATION_MISSING,
    CHECK_CONSISTENCY_MISMATCH,
    CHECK_EVIDENCE_GENERIC,
    CHECK_SCHEMA_INCOMPLETE,
    Validator,
)

# Canonical vocabulary fallback if retrieval.py was not imported at validator module load
_CANONICAL_VOCABULARY: dict[STRIDECategory, frozenset[str]] = {
    STRIDECategory.SPOOFING: frozenset(
        {
            "replay", "impersonation", "impersonat", "credential theft", "identity forgery",
            "session hijack", "ble replay", "token replay", "phishing", "arp spoofing",
            "dns spoofing", "spoof", "spoofing", "fake", "forged", "forgery",
            "masquerade", "fabricat", "fabricated",
        }
    ),
    STRIDECategory.TAMPERING: frozenset(
        {
            "injection", "sql injection", "command injection", "firmware manipulation",
            "man-in-the-middle", "data modification", "parameter tampering", "payload manipulation",
            "code injection", "buffer overflow", "inject", "malicious", "malware",
            "modify", "corrupt", "overwrite", "tamper", "tampering", "firmware",
            "update", "firmware update", "software update", "update mechanism",
            "unsecured", "unverified", "alter", "manipulat", "integrity",
        }
    ),
    STRIDECategory.REPUDIATION: frozenset(
        {
            "log deletion", "audit bypass", "log tampering", "evidence removal",
            "non-repudiation bypass", "transaction denial", "repudiat", "deny",
            "denial of action", "delete log", "clear log", "cover track",
        }
    ),
    STRIDECategory.INFORMATION_DISCLOSURE: frozenset(
        {
            "eavesdrop", "sniffing", "side channel", "data exfiltration",
            "unencrypted transmission", "information leak", "memory disclosure",
            "cleartext", "leak", "disclos", "expose", "exposure", "plaintext", "intercept",
        }
    ),
    STRIDECategory.DENIAL_OF_SERVICE: frozenset(
        {
            "flood", "resource exhaustion", "crash", "amplification", "dos", "ddos",
            "availability", "starvation", "denial of service", "disrupt", "shutdown",
            "freeze", "hang", "starve", "reboot",
        }
    ),
    STRIDECategory.ELEVATION_OF_PRIVILEGE: frozenset(
        {
            "privilege escalation", "path traversal", "insecure deserialization",
            "access control bypass", "sudo", "kernel exploit", "role escalation",
            "unauthorized access", "bypass", "unlock", "unauthenticated",
            "authentication bypass", "unauth", "gain access", "escalat", "privilege", "unauthorized",
        }
    ),
}

if not validator_module.STRIDE_VECTOR_VOCABULARY:
    validator_module.STRIDE_VECTOR_VOCABULARY = _CANONICAL_VOCABULARY

DATASET_PATH = Path(__file__).parent / "validator_far_frr_dataset.json"


@dataclass
class CaseEvaluation:
    """Evaluation result for a single labeled scenario."""

    case_id: str
    ground_truth_label: str  # 'valid' or 'invalid'
    target_check: str | None
    description: str
    passed: bool
    failed_check_ids: list[str] = field(default_factory=list)
    failed_check_details: list[str] = field(default_factory=list)
    classification: str = ""  # 'TRUE_ACCEPT', 'FALSE_REJECT', 'TRUE_REJECT', 'FALSE_ACCEPT'
    misclassified: bool = False
    root_cause_notes: str = ""


@dataclass
class BenchmarkSummary:
    """Aggregate benchmark metrics."""

    total_scenarios: int
    total_valid: int
    total_invalid: int
    true_accepts: int
    false_rejects: int
    true_rejects: int
    false_accepts: int
    far: float  # False Acceptance Rate
    frr: float  # False Rejection Rate
    tar: float  # True Acceptance Rate
    trr: float  # True Rejection Rate
    accuracy: float
    check_breakdown: dict[str, dict[str, int]] = field(default_factory=dict)
    case_results: list[CaseEvaluation] = field(default_factory=list)


def build_scenario_from_dict(data: dict[str, Any]) -> ThreatScenario:
    """Reconstruct ThreatScenario using model_construct to preserve test mutations."""
    scen_dict = dict(data["scenario"])

    # Reconstruct nested EvidenceChain
    raw_evidence = scen_dict.get("evidence_chain", {})
    evidence_obj = EvidenceChain.model_construct(
        exposure=raw_evidence.get("exposure", ""),
        matched_pattern=raw_evidence.get("matched_pattern", ""),
        applicability_reason=raw_evidence.get("applicability_reason", ""),
        citation=raw_evidence.get("citation", ""),
    )
    scen_dict["evidence_chain"] = evidence_obj

    # Cast stride_category to STRIDECategory enum if present
    stride_val = scen_dict.get("stride_category")
    if stride_val is not None:
        try:
            scen_dict["stride_category"] = STRIDECategory(stride_val)
        except ValueError:
            pass  # Leave as-is if testing illegal STRIDE string

    return ThreatScenario.model_construct(**scen_dict)


def evaluate_dataset(
    dataset_path: Path = DATASET_PATH,
    validator: Validator | None = None,
) -> BenchmarkSummary:
    """Run full validator evaluation against labeled dataset."""
    if validator is None:
        validator = Validator()

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    raw_cases: list[dict[str, Any]] = json.loads(dataset_path.read_text(encoding="utf-8"))

    evaluations: list[CaseEvaluation] = []

    true_accepts = 0
    false_rejects = 0
    true_rejects = 0
    false_accepts = 0

    check_breakdown: dict[str, dict[str, int]] = {
        CHECK_CITATION_MISSING: {"total": 0, "detected": 0, "missed": 0},
        CHECK_SCHEMA_INCOMPLETE: {"total": 0, "detected": 0, "missed": 0},
        CHECK_CONSISTENCY_MISMATCH: {"total": 0, "detected": 0, "missed": 0},
        CHECK_EVIDENCE_GENERIC: {"total": 0, "detected": 0, "missed": 0},
    }

    for item in raw_cases:
        case_id = item["id"]
        label = item["label"]
        target_check = item.get("target_check")
        if target_check and target_check.startswith("CHECK_"):
            target_check = target_check[len("CHECK_") :]
        description = item.get("description", "")

        scenario = build_scenario_from_dict(item)
        val_result: ValidationResult = validator.validate(scenario)

        failed_check_ids = [fc.check_id for fc in val_result.failed_checks]
        failed_check_details = [fc.detail for fc in val_result.failed_checks]

        passed = val_result.passed

        classification = ""
        misclassified = False
        root_cause = ""

        if label == "valid":
            if passed:
                classification = "TRUE_ACCEPT"
                true_accepts += 1
            else:
                classification = "FALSE_REJECT"
                false_rejects += 1
                misclassified = True
                root_cause = (
                    f"Valid domain scenario rejected by checks: {failed_check_ids}. "
                    "Typically caused by narrow vocabulary or strict heuristic limits."
                )
        elif label == "invalid":
            if not passed:
                classification = "TRUE_REJECT"
                true_rejects += 1
            else:
                classification = "FALSE_ACCEPT"
                false_accepts += 1
                misclassified = True
                root_cause = (
                    f"Invalid scenario targeting {target_check} passed all checks. "
                    "Heuristic check did not detect subtle defect (e.g. negation, tautology, non-standard placeholder)."
                )

            # Track check breakdown for invalid cases
            if target_check and target_check in check_breakdown:
                check_breakdown[target_check]["total"] += 1
                if target_check in failed_check_ids:
                    check_breakdown[target_check]["detected"] += 1
                else:
                    check_breakdown[target_check]["missed"] += 1

        evaluations.append(
            CaseEvaluation(
                case_id=case_id,
                ground_truth_label=label,
                target_check=target_check,
                description=description,
                passed=passed,
                failed_check_ids=failed_check_ids,
                failed_check_details=failed_check_details,
                classification=classification,
                misclassified=misclassified,
                root_cause_notes=root_cause,
            )
        )

    total_valid = true_accepts + false_rejects
    total_invalid = true_rejects + false_accepts
    total_scenarios = len(evaluations)

    far = (false_accepts / total_invalid) if total_invalid > 0 else 0.0
    frr = (false_rejects / total_valid) if total_valid > 0 else 0.0
    tar = (true_accepts / total_valid) if total_valid > 0 else 0.0
    trr = (true_rejects / total_invalid) if total_invalid > 0 else 0.0
    accuracy = (
        ((true_accepts + true_rejects) / total_scenarios) if total_scenarios > 0 else 0.0
    )

    return BenchmarkSummary(
        total_scenarios=total_scenarios,
        total_valid=total_valid,
        total_invalid=total_invalid,
        true_accepts=true_accepts,
        false_rejects=false_rejects,
        true_rejects=true_rejects,
        false_accepts=false_accepts,
        far=far,
        frr=frr,
        tar=tar,
        trr=trr,
        accuracy=accuracy,
        check_breakdown=check_breakdown,
        case_results=evaluations,
    )


def print_benchmark_report(summary: BenchmarkSummary) -> None:
    """Print formatted summary report to console."""
    print("=" * 80)
    print(" PROTOCOL INVARIANT VALIDATOR: FAR / FRR BENCHMARK REPORT")
    print("=" * 80)
    print(f"Total Scenarios Evaluated: {summary.total_scenarios}")
    print(f"  - Valid Controls:        {summary.total_valid}")
    print(f"  - Invalid Test Cases:    {summary.total_invalid}")
    print("-" * 80)
    print("CONFUSION MATRIX & METRICS:")
    print(
        f"  True Accepts  (TA): {summary.true_accepts:2d} / {summary.total_valid:2d} "
        f" (TAR: {summary.tar * 100:5.2f}%)"
    )
    print(
        f"  False Rejects (FR): {summary.false_rejects:2d} / {summary.total_valid:2d} "
        f" (FRR: {summary.frr * 100:5.2f}%)"
    )
    print(
        f"  True Rejects  (TR): {summary.true_rejects:2d} / {summary.total_invalid:2d} "
        f" (TRR: {summary.trr * 100:5.2f}%)"
    )
    print(
        f"  False Accepts (FA): {summary.false_accepts:2d} / {summary.total_invalid:2d} "
        f" (FAR: {summary.far * 100:5.2f}%)"
    )
    print(f"  Overall Accuracy:   {summary.accuracy * 100:5.2f}%")
    print("-" * 80)
    print("TARGET CHECK DETECTION BREAKDOWN (for Invalid Scenarios):")
    for check_id, counts in summary.check_breakdown.items():
        total = counts["total"]
        detected = counts["detected"]
        missed = counts["missed"]
        pct = (detected / total * 100) if total > 0 else 0.0
        print(f"  [{check_id}]")
        print(f"    Targeted: {total:2d} | Detected: {detected:2d} ({pct:5.1f}%) | Missed: {missed:2d}")

    print("-" * 80)
    print("MISCLASSIFIED SCENARIOS (Root Cause Investigation):")
    misclassified = [r for r in summary.case_results if r.misclassified]
    if not misclassified:
        print("  None. 100% accuracy achieved.")
    else:
        for r in misclassified:
            print(f"  * {r.case_id} [{r.classification}] - Label: {r.ground_truth_label.upper()}")
            print(f"    Description: {r.description}")
            if r.failed_check_ids:
                print(f"    Failed Checks: {r.failed_check_ids}")
            print(f"    Analysis: {r.root_cause_notes}")
            print()
    print("=" * 80)


def test_validator_far_frr_sanity() -> None:
    """Pytest entrypoint to ensure FAR/FRR measurement runs green without error."""
    summary = evaluate_dataset()
    assert summary.total_scenarios >= 40, "Dataset must contain at least 40 scenarios"
    assert summary.total_valid >= 20, "Dataset must contain at least 20 valid scenarios"
    assert summary.total_invalid >= 20, "Dataset must contain at least 20 invalid scenarios"
    # The validator gate should have high specificity (TRR > 70%) and high sensitivity (TAR > 70%)
    assert summary.trr >= 0.70, f"TRR too low: {summary.trr}"
    assert summary.tar >= 0.70, f"TAR too low: {summary.tar}"


if __name__ == "__main__":
    benchmark_summary = evaluate_dataset()
    print_benchmark_report(benchmark_summary)
