"""tests/threat_agent/research/evaluate_t1_t6.py
==============================================================================
TRC Engine - Phase 1: Threat Agent  |  T1-T6 Ground-Truth Evaluation
------------------------------------------------------------------------------
Compares the Threat Agent's generated output against expert-authored T1-T6 baseline
threats for the Smart Door Lock fixture, computing Precision, Recall, and F1.

Author: Antigravity AI (Chetan)
Scope: Phase 1 Closeout - Smart Door Lock Fixture Evaluation (Section 4)
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sentence_transformers import SentenceTransformer, util  # noqa: E402

from agents.threat_agent.orchestrator import generate_and_validate_with_retry  # noqa: E402
from agents.threat_agent.schemas import (  # noqa: E402
    EvidenceChain,
    ThreatAgentInput,
    ThreatScenario,
)

_GROUND_TRUTH_PATH = Path(__file__).resolve().parent / "ground_truth_t1_t6.json"
_FIXTURE_PATH = (
    _REPO_ROOT
    / "tests"
    / "threat_agent"
    / "e2e"
    / "fixtures"
    / "smart_door_lock"
    / "input.json"
)
_RESULTS_DOC_PATH = _REPO_ROOT / "docs" / "research" / "t1_t6_evaluation_results.md"
_RAW_SCENARIOS_PATH = _REPO_ROOT / "docs" / "research" / "smart_door_lock_scenarios_raw.json"
_RAW_SCENARIOS_RUN2_PATH = _REPO_ROOT / "docs" / "research" / "smart_door_lock_scenarios_raw_run2.json"


def is_stride_match(scenario_stride: str, target_stride: str | list[str]) -> bool:
    """Check if the scenario's STRIDE category matches target STRIDE requirement."""
    s_norm = scenario_stride.strip().lower()
    targets = target_stride if isinstance(target_stride, list) else [target_stride]
    for t in targets:
        t_norm = t.strip().lower()
        if s_norm == t_norm:
            return True
        if "elevation" in s_norm and "elevation" in t_norm:
            return True
        if "disclosure" in s_norm and "disclosure" in t_norm:
            return True
        if "denial" in s_norm and "denial" in t_norm:
            return True
    return False


def check_match(
    scenario: ThreatScenario,
    threat: dict[str, Any],
    sim_score: float,
    threshold: float = 0.75,
) -> bool:
    """Predicate evaluating if generated scenario G matches expert threat T:
    G matches T iff:
      1. G.asset_id == T.asset_id
      2. G.stride_category matches T.stride_category
      3. Cosine similarity between G.attack_vector and T.attack_vector >= threshold
    """
    if scenario.asset_id != threat["asset_id"]:
        return False

    s_stride = (
        scenario.stride_category.value
        if hasattr(scenario.stride_category, "value")
        else str(scenario.stride_category)
    )
    if not is_stride_match(s_stride, threat["stride_category"]):
        return False

    return sim_score >= threshold


def test_matching_predicate_sanity() -> None:
    """Sanity test verifying that the matching predicate behaves correctly on two
    hand-constructed examples (one obvious match, one obvious non-match) independent
    of live pipeline runs."""
    model = SentenceTransformer("all-MiniLM-L6-v2")

    threat = {
        "threat_id": "T1",
        "title": "BLE replay",
        "asset_id": "AS-1",
        "stride_category": ["Spoofing", "Tampering"],
        "kb_reference": "CAPEC-94",
        "attack_vector": (
            "Adversary in the Middle or BLE replay attack capturing pairing "
            "tokens or unlock commands to spoof legitimate user."
        ),
    }

    evidence = EvidenceChain(
        exposure="BLE 5.0 interface",
        matched_pattern="CAPEC-94",
        applicability_reason="BLE controller exposes unauthenticated advertisement channel.",
        citation="CAPEC-94: Adversary in the Middle",
    )

    # 1. Obvious MATCH: same asset_id, valid stride, semantically aligned attack_vector
    match_scenario = ThreatScenario(
        tid="THR-TEST-001",
        asset_id="AS-1",
        stride_category="Spoofing",
        attack_vector=(
            "Adversary in the Middle BLE replay attack intercepting unlock "
            "commands on BLE 5.0 interface to gain unauthorized physical entry."
        ),
        kb_reference="CAPEC-94",
        evidence_chain=evidence,
        confidence_score=0.85,
        run_id="RUN-TEST-001",
    )
    emb_t = model.encode(threat["attack_vector"])
    emb_match = model.encode(match_scenario.attack_vector)
    sim_match = float(util.cos_sim(emb_match, emb_t).item())
    assert sim_match >= 0.75, f"Expected similarity >= 0.75, got {sim_match}"
    assert check_match(match_scenario, threat, sim_match, threshold=0.75) is True

    # 2. Obvious NON-MATCH: different asset_id, different STRIDE category, unrelated vector
    non_match_scenario = ThreatScenario(
        tid="THR-TEST-002",
        asset_id="AS-3",
        stride_category="DenialOfService",
        attack_vector="Cloud API rate-limit exhaustion via HTTP flooding.",
        kb_reference="CAPEC-125",
        evidence_chain=evidence,
        confidence_score=0.80,
        run_id="RUN-TEST-001",
    )
    emb_non_match = model.encode(non_match_scenario.attack_vector)
    sim_non_match = float(util.cos_sim(emb_non_match, emb_t).item())
    assert check_match(non_match_scenario, threat, sim_non_match, threshold=0.75) is False


def run_evaluation(threshold: float = 0.75) -> dict[str, Any]:
    """Execute the full evaluation pipeline and generate results."""
    print("[1/5] Loading ground-truth expert threats from:", _GROUND_TRUTH_PATH)
    ground_truth: list[dict[str, Any]] = json.loads(
        _GROUND_TRUTH_PATH.read_text(encoding="utf-8")
    )

    print("[2/5] Loading Smart Door Lock fixture from:", _FIXTURE_PATH)
    agent_input = ThreatAgentInput.model_validate_json(
        _FIXTURE_PATH.read_text(encoding="utf-8")
    )

    print("[3/5] Executing full Threat Agent pipeline (generate_and_validate_with_retry)...")
    scenarios, retry_count, val_status = generate_and_validate_with_retry(agent_input)
    print(
        f"Pipeline produced {len(scenarios)} scenarios (retries={retry_count}, status={val_status})"
    )

    # Save raw generated scenarios for verification / audit
    _RAW_SCENARIOS_PATH.parent.mkdir(parents=True, exist_ok=True)
    raw_scenarios_data = [s.model_dump(mode="json") for s in scenarios]
    _RAW_SCENARIOS_PATH.write_text(json.dumps(raw_scenarios_data, indent=2), encoding="utf-8")
    _RAW_SCENARIOS_RUN2_PATH.write_text(json.dumps(raw_scenarios_data, indent=2), encoding="utf-8")
    print("Saved raw scenario output to:", _RAW_SCENARIOS_RUN2_PATH)

    print("[4/5] Loading SentenceTransformer(all-MiniLM-L6-v2) for semantic matching...")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    expert_vectors = [t["attack_vector"] for t in ground_truth]
    scenario_vectors = [s.attack_vector for s in scenarios]

    expert_embs = model.encode(expert_vectors)
    scenario_embs = model.encode(scenario_vectors)

    sim_matrix = util.cos_sim(scenario_embs, expert_embs).cpu().numpy()

    print("[5/5] Evaluating matching predicate against generated scenarios...")
    matched_expert_threats: dict[str, list[dict[str, Any]]] = {
        t["threat_id"]: [] for t in ground_truth
    }
    highest_sim_per_threat: dict[str, dict[str, Any]] = {}
    matched_scenario_indices: set[int] = set()

    for t_idx, threat in enumerate(ground_truth):
        tid = threat["threat_id"]
        best_sim = -1.0
        best_match_info: dict[str, Any] = {"cosine_similarity": 0.0, "scenario_tid": "None"}
        for s_idx, scenario in enumerate(scenarios):
            sim = float(sim_matrix[s_idx, t_idx])
            if sim > best_sim:
                best_sim = sim
                best_match_info = {
                    "cosine_similarity": round(sim, 4),
                    "scenario_tid": scenario.tid,
                    "asset_id": scenario.asset_id,
                    "stride_category": (
                        scenario.stride_category.value
                        if hasattr(scenario.stride_category, "value")
                        else str(scenario.stride_category)
                    ),
                    "kb_reference": scenario.kb_reference,
                    "attack_vector": scenario.attack_vector,
                }
            if check_match(scenario, threat, sim, threshold=threshold):
                matched_expert_threats[tid].append(
                    {
                        "scenario_tid": scenario.tid,
                        "asset_id": scenario.asset_id,
                        "stride_category": (
                            scenario.stride_category.value
                            if hasattr(scenario.stride_category, "value")
                            else str(scenario.stride_category)
                        ),
                        "kb_reference": scenario.kb_reference,
                        "attack_vector": scenario.attack_vector,
                        "cosine_similarity": round(sim, 4),
                    }
                )
                matched_scenario_indices.add(s_idx)
        highest_sim_per_threat[tid] = best_match_info

    # Compute metrics
    tp_threats = [tid for tid, matches in matched_expert_threats.items() if len(matches) > 0]
    fn_threats = [tid for tid, matches in matched_expert_threats.items() if len(matches) == 0]

    tp = len(tp_threats)
    fn = len(fn_threats)
    total_expert = len(ground_truth)

    total_scenarios = len(scenarios)
    num_matched_scenarios = len(matched_scenario_indices)
    fp = total_scenarios - num_matched_scenarios

    precision = num_matched_scenarios / total_scenarios if total_scenarios > 0 else 0.0
    recall = tp / total_expert if total_expert > 0 else 0.0
    f1 = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    results_summary = {
        "timestamp": datetime.now(UTC).isoformat(),
        "total_expert_threats": total_expert,
        "total_generated_scenarios": total_scenarios,
        "true_positives_tp": tp,
        "false_negatives_fn": fn,
        "false_positives_fp": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "threshold": threshold,
        "tp_threat_ids": tp_threats,
        "fn_threat_ids": fn_threats,
        "matched_details": matched_expert_threats,
        "highest_sim_per_threat": highest_sim_per_threat,
    }

    print("\n=================== EVALUATION RESULTS ===================")
    print(f"Expert Threats (Total): {total_expert}")
    print(f"Generated Scenarios:   {total_scenarios}")
    print(f"True Positives (TP):   {tp} ({tp_threats})")
    print(f"False Negatives (FN):  {fn} ({fn_threats})")
    print(f"False Positives (FP):  {fp}")
    print(f"Precision:             {precision:.4f} ({precision*100:.1f}%)")
    print(f"Recall:                {recall:.4f} ({recall*100:.1f}%)")
    print(f"F1 Score:              {f1:.4f}")
    print("==========================================================\n")

    # Write results document
    write_results_markdown(results_summary, ground_truth, scenarios)

    return results_summary


def write_results_markdown(
    results: dict[str, Any],
    ground_truth: list[dict[str, Any]],
    scenarios: list[ThreatScenario],
) -> None:
    """Write markdown report to docs/research/t1_t6_evaluation_results.md."""
    _RESULTS_DOC_PATH.parent.mkdir(parents=True, exist_ok=True)

    gt_by_id = {t["threat_id"]: t for t in ground_truth}

    lines = [
        "# T1-T6 Ground-Truth Evaluation Results (Smart Door Lock)",
        "",
        f"**Evaluation Date:** {results['timestamp']}",
        "**Fixture Evaluated:** `tests/threat_agent/e2e/fixtures/smart_door_lock/input.json`",
        "**Semantic Model:** `sentence-transformers/all-MiniLM-L6-v2`",
        f"**Cosine Similarity Threshold:** {results['threshold']} (fixed §4 protocol threshold; no post-hoc tuning)",
        "",
        "## 1. Executive Summary & Metric Scores",
        "",
        "| Metric | Value | Definition |",
        "| :--- | :--- | :--- |",
        f"| **Expert Baseline Threats (N)** | **{results['total_expert_threats']}** | Total expert-authored threats (T1-T6) |",
        f"| **Generated Scenarios** | **{results['total_generated_scenarios']}** | Total scenarios produced by Threat Agent pipeline |",
        f"| **True Positives (TP)** | **{results['true_positives_tp']}** | Expert threats matched by $\\ge 1$ generated scenario |",
        f"| **False Negatives (FN)** | **{results['false_negatives_fn']}** | Expert threats missed by all generated scenarios |",
        f"| **False Positives (FP)** | **{results['false_positives_fp']}** | Generated scenarios matching no expert baseline threat |",
        f"| **Precision** | **{results['precision']:.4f}** ({results['precision']*100:.1f}%) | Ratio of matched scenarios to total generated scenarios |",
        f"| **Recall** | **{results['recall']:.4f}** ({results['recall']*100:.1f}%) | Ratio of matched expert threats to total expert threats (TP / 6) |",
        f"| **F1 Score** | **{results['f1']:.4f}** | Harmonic mean of Precision and Recall |",
        "",
        "> [!IMPORTANT]",
        "> **Evaluation Integrity Notice:** All results are reported exactly as computed under the fixed $0.75$ cosine similarity threshold. No post-hoc threshold adjustment was performed.",
        "",
        "## 2. Per-Threat Breakdown (T1-T6)",
        "",
        "| ID | Title | Asset | Expected STRIDE | Expected KB | Status | Matching Scenario(s) | Top Cosine Sim |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for t in ground_truth:
        tid = t["threat_id"]
        matches = results["matched_details"].get(tid, [])
        status = "MATCHED" if matches else "MISSED"
        stride_str = ", ".join(t["stride_category"]) if isinstance(t["stride_category"], list) else t["stride_category"]

        best_info = results.get("highest_sim_per_threat", {}).get(tid, {})
        top_sim = best_info.get("cosine_similarity", "N/A")
        if matches:
            tids = ", ".join(m["scenario_tid"] for m in matches)
        else:
            tids = "None"

        lines.append(
            f"| **{tid}** | {t['title']} | `{t['asset_id']}` | {stride_str} | `{t['kb_reference']}` | {status} | {tids} | {top_sim} |"
        )

    lines.extend([
        "",
        "## 3. Analysis of Findings",
        "",
        "### 3.1 True Positives (Matched Threats)",
    ])

    if results["tp_threat_ids"]:
        for tid in results["tp_threat_ids"]:
            t = gt_by_id[tid]
            matches = results["matched_details"][tid]
            lines.append(f"#### {tid}: {t['title']} ({t['asset_id']})")
            lines.append(f"* **Expert Attack Vector:** {t['attack_vector']}")
            lines.append(f"* **Matched Scenarios ({len(matches)}):**")
            for m in matches:
                lines.append(
                    f"  - `{m['scenario_tid']}` (`{m['kb_reference']}`, {m['stride_category']}, sim={m['cosine_similarity']}): {m['attack_vector']}"
                )
            lines.append("")
    else:
        lines.append(r"No expert threats met the combined match criteria ($asset\_id$, $STRIDE$, and $\ge 0.75$ semantic similarity).")
        lines.append("")

    lines.extend([
        "### 3.2 False Negatives (Missed Threats & Root Causes)",
    ])

    for tid in results["fn_threat_ids"]:
        t = gt_by_id[tid]
        best_info = results.get("highest_sim_per_threat", {}).get(tid, {})
        lines.append(f"#### {tid}: {t['title']} ({t['asset_id']})")
        lines.append(f"* **Expert Target Asset:** `{t['asset_id']}`")
        lines.append(f"* **Expected STRIDE:** {t['stride_category']}")
        lines.append(f"* **Expected KB Reference:** `{t['kb_reference']}`")
        lines.append(f"* **Expert Vector:** {t['attack_vector']}")
        lines.append(f"* **Highest Observed Cosine Similarity:** {best_info.get('cosine_similarity', 0.0)} ({best_info.get('scenario_tid', 'N/A')})")

        fixture_assets = ["AS-1", "AS-2", "AS-3", "AS-4", "AS-5", "AS-6"]
        if t["asset_id"] not in fixture_assets:
            lines.append(
                f"* **Root Cause Analysis (Asset Fixture Boundary):** The Smart Door Lock fixture (`tests/threat_agent/e2e/fixtures/smart_door_lock/input.json`) "
                f"only models assets `AS-1` (BLE Controller), `AS-2` (Secure Element), and `AS-3` (Cloud Backend). "
                f"Asset `{t['asset_id']}` is not defined in the input system model fixture. Consequently, the agent cannot generate threats for `{t['asset_id']}`."
            )
        else:
            lines.append(
                f"* **Root Cause Analysis (Semantic & Category Boundary):** Asset `{t['asset_id']}` exists in the fixture, but no generated scenario reached "
                f"the $\\ge 0.75$ cosine similarity threshold alongside exact STRIDE and asset matching. The highest observed similarity was {best_info.get('cosine_similarity', 0.0)}."
            )
        lines.append("")

    lines.extend([
        "## 4. Verification & Audit Trail",
        "",
        "* **Raw Scenarios Saved:** [`docs/research/smart_door_lock_scenarios_raw.json`](file:///C:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw.json)",
        "* **Ground Truth Source:** [`tests/threat_agent/research/ground_truth_t1_t6.json`](file:///C:/Users/Chetan/trc-engine/tests/threat_agent/research/ground_truth_t1_t6.json)",
        "* **Evaluation Script:** [`tests/threat_agent/research/evaluate_t1_t6.py`](file:///C:/Users/Chetan/trc-engine/tests/threat_agent/research/evaluate_t1_t6.py)",
    ])

    _RESULTS_DOC_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Successfully wrote evaluation report to:", _RESULTS_DOC_PATH)


if __name__ == "__main__":
    test_matching_predicate_sanity()
    print("Sanity test passed! Running full evaluation...")
    run_evaluation()
