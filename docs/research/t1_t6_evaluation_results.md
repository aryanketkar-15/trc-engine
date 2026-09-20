# T1-T6 Ground-Truth Evaluation Results (Smart Door Lock)

**Scope:** Phase 1 Closeout — Smart Door Lock Fixture Evaluation (§4)  
**Evaluation Dates:** Run 1 (2026-09-19T09:02:06Z), Run 2 (2026-09-20T09:32:41Z)  
**Semantic Model:** `sentence-transformers/all-MiniLM-L6-v2`  
**Cosine Similarity Threshold:** 0.75 (fixed §4 protocol threshold; no post-hoc tuning)  
**Matching Predicate:** Scenario $G$ matches expert threat $T$ iff:
1. $G.\text{asset\_id} == T.\text{asset\_id}$
2. $G.\text{stride\_category}$ matches $T.\text{stride\_category}$
3. $\text{CosineSimilarity}(G.\text{attack\_vector}, T.\text{attack\_vector}) \ge 0.75$

> [!IMPORTANT]
> **Clarification on Evaluation Terminology:**
> A "false positive" in this T1–T6 matching evaluation means that a generated scenario did not match one of the six predefined expert ground-truth threats under the specified matching criteria. It does **NOT** by itself mean that the generated scenario is invalid, unsafe, or technically incorrect. The Threat Agent generates a broad, standards-grounded threat surface across all input assets, whereas T1–T6 represents a specific, curated six-threat baseline.

---

## Run 1 — Fixture Asset Coverage Gap Identified

* **Execution Date:** 2026-09-19T09:02:06.327224+00:00
* **Fixture Evaluated:** Initial 3-asset fixture (`smart_door_lock/input.json`)
* **Raw Scenario Audit:** [`docs/research/smart_door_lock_scenarios_raw_run1.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run1.json)

### Run 1 Summary & Metrics

| Metric | Value | Definition |
| :--- | :--- | :--- |
| **Expert Baseline Threats (N)** | **6** | Total expert-authored threats (T1–T6) |
| **Generated Scenarios** | **30** | Scenarios produced by Threat Agent pipeline (3 assets × 10 candidates) |
| **True Positives (TP)** | **0** | Expert threats matched by $\ge 1$ generated scenario |
| **False Negatives (FN)** | **6** | Expert threats missed by all generated scenarios |
| **False Positives (FP)** | **30** | Generated scenarios matching no expert baseline threat |
| **Precision** | **0.0000** (0.0%) | Ratio of matched scenarios to total generated scenarios |
| **Recall** | **0.0000** (0.0%) | Ratio of matched expert threats to total expert threats (TP / 6) |
| **F1 Score** | **0.0000** | Harmonic mean of Precision and Recall |

### Run 1 Per-Threat Breakdown (T1–T6)

| ID | Title | Asset | Expected STRIDE | Expected KB | Status | Matching Scenario(s) | Top Cosine Sim | Top Match Scenario ID |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | BLE replay | `AS-1` | Spoofing, Tampering | `CAPEC-94` | MISSED | None | 0.6801 | `THR-PATH-4DC3BCD8-003` |
| **T2** | cloud account takeover | `AS-2` | ElevationOfPrivilege | `ATT&CK-T1078` | MISSED | None | 0.4781 | `THR-PATH-908C25A0-028` |
| **T3** | malicious OTA firmware | `AS-3` | Tampering | `CAPEC-186` | MISSED | None | 0.5452 | `THR-PATH-93775C91-008` |
| **T4** | eavesdropping/MitM | `AS-5` | InformationDisclosure | `CAPEC-117` | MISSED | None | 0.5036 | `THR-PATH-F787D850-019` |
| **T5** | DoS on cloud | `AS-1` | DenialOfService | `CAPEC-125` | MISSED | None | 0.6934 | `THR-PATH-F3D7436E-026` |
| **T6** | key extraction via side-channel | `AS-6` | Tampering, InformationDisclosure | `CAPEC-189` | MISSED | None | 0.3477 | `THR-PATH-F787D850-019` |

### Run 1 Methodological Gap Analysis
1. **Ad-Hoc Fixture Scope:** The fixture used in Run 1 defined only 3 ad-hoc assets (`AS-1`: BLE Controller, `AS-2`: Secure Element, `AS-3`: Cloud Backend) which did not match the company specification's (§2.4) 6-asset Smart Door Lock model.
2. **Structural Impossibility:** Ground-truth threats T4 (targeting `AS-5` User PII / Schedule Data) and T6 (targeting `AS-6` Cryptographic Keys) were **structurally unable to match** because assets `AS-5` and `AS-6` did not exist in the fixture at all.
3. **Asset Conceptual Mismatch:** In the ground truth, T2 targets `AS-2` (E-key credential, ElevationOfPrivilege), but fixture `AS-2` was modeled as "Secure Element" (on-device hardware security module). Similarly, T3 targets `AS-3` (Firmware image, Tampering), but fixture `AS-3` was modeled as "Cloud Backend".

**Run 1 is NOT treated as the final system-quality measurement for Phase 1 due to this fixture/ground-truth mismatch.**

---

## Run 2 — Corrected Six-Asset Fixture

* **Execution Date:** 2026-09-20T09:32:41.582412+00:00
* **Fixture Evaluated:** Corrected 6-asset fixture (`smart_door_lock/input.json`) matching company document Section 2.4:
  - `AS-1`: Unlock Command (`Cloud<->Lock channel`, control command)
  - `AS-2`: E-Key Credential (`Cloud DB, App, Lock`, access credential)
  - `AS-3`: Firmware Image (`OTA, Lock flash`, embedded firmware)
  - `AS-4`: Audit Log (`Lock, Cloud`, event log)
  - `AS-5`: User PII (`Cloud, App`, schedule & user data)
  - `AS-6`: Cryptographic Keys (`Secure element`, key material)
* **Raw Scenario Audit:** [`docs/research/smart_door_lock_scenarios_raw_run2.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run2.json)
* **Methodology Integrity:** Evaluation methodology, cosine similarity threshold ($0.75$), and matching predicate are **100% identical** to Run 1 (no tuning, no threshold relaxation).

### Run 2 Summary & Metrics

| Metric | Value | Definition |
| :--- | :--- | :--- |
| **Expert Baseline Threats (N)** | **6** | Total expert-authored threats (T1–T6) |
| **Generated Scenarios** | **60** | Scenarios produced by Threat Agent pipeline (6 assets × 10 candidates) |
| **True Positives (TP)** | **0** | Expert threats matched by $\ge 1$ generated scenario |
| **False Negatives (FN)** | **6** | Expert threats missed by all generated scenarios |
| **False Positives (FP)** | **60** | Generated scenarios matching no expert baseline threat |
| **Precision** | **0.0000** (0.0%) | Ratio of matched scenarios to total generated scenarios |
| **Recall** | **0.0000** (0.0%) | Ratio of matched expert threats to total expert threats (TP / 6) |
| **F1 Score** | **0.0000** | Harmonic mean of Precision and Recall |

### Run 2 Per-Threat Breakdown (T1–T6)

| ID | Title | Asset | Expected STRIDE | Expected KB | Status | Matching Scenario(s) | Top Cosine Sim | Top Match Scenario ID |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | BLE replay | `AS-1` | Spoofing, Tampering | `CAPEC-94` | MISSED | None | **0.7020** | `THR-PATH-68911B85-022` |
| **T2** | cloud account takeover | `AS-2` | ElevationOfPrivilege | `ATT&CK-T1078` | MISSED | None | 0.4507 | `THR-PATH-6EC137CC-046` |
| **T3** | malicious OTA firmware | `AS-3` | Tampering | `CAPEC-186` | MISSED | None | **0.6167** | `THR-PATH-417E6BD5-002` |
| **T4** | eavesdropping/MitM | `AS-5` | InformationDisclosure | `CAPEC-117` | MISSED | None | **0.5481** | `THR-PATH-9658B404-023` |
| **T5** | DoS on cloud | `AS-1` | DenialOfService | `CAPEC-125` | MISSED | None | 0.3497 | `THR-PATH-E91AA507-045` |
| **T6** | key extraction via side-channel | `AS-6` | Tampering, InformationDisclosure | `CAPEC-189` | MISSED | None | **0.4466** | `THR-PATH-00398FCF-055` |

### Run 2 Root-Cause Analysis for Unmatched Threats

All six assets now exist in the fixture and were actively evaluated by the pipeline. The root cause for unmatched threats is no longer structural absence, but semantic threshold boundaries:

1. **T1: BLE replay (`AS-1`) — Near-Miss (Similarity: 0.7020):**
   * **Expert Vector:** *"Adversary in the Middle or BLE replay attack capturing pairing tokens or unlock commands to spoof legitimate user."*
   * **Top Scenario (`THR-PATH-68911B85-022`):** Asset matched (`AS-1`), STRIDE matched (`Spoofing`), KB matched (`CAPEC-94`). Cosine similarity reached **0.7020**, narrowly missing the 0.75 cutoff by 0.048.
   * **Root Cause:** Semantic phrasing variance between expert ground truth and pipeline-generated vector.
2. **T2: Cloud account takeover (`AS-2`) — Similarity: 0.4507:**
   * **Expert Vector:** *"Cloud account takeover exploiting valid credentials or phishing to gain administrative control and issue unauthorized commands."*
   * **Top Scenario (`THR-PATH-6EC137CC-046`):** Generated vector on `AS-2` focuses on JWT token tampering and replay rather than social-engineering phishing or credential stuffing.
3. **T3: Malicious OTA firmware (`AS-3`) — Similarity: 0.6167:**
   * **Expert Vector:** *"Malicious OTA firmware delivery replacing authentic device firmware via unauthenticated or unverified update mechanism."*
   * **Top Scenario (`THR-PATH-417E6BD5-002`):** Correctly targeted `AS-3` (Firmware Image) with Tampering, but similarity of 0.6167 did not cross the 0.75 threshold.
4. **T4: Eavesdropping/MitM (`AS-5`) — Similarity: 0.5481:**
   * **Expert Vector:** *"Eavesdropping and adversary-in-the-middle sniffing communication traffic on unencrypted channels to disclose sensitive information."*
   * **Top Scenario (`THR-PATH-9658B404-023`):** In Run 1, `AS-5` was absent. In Run 2, `AS-5` was populated and evaluated, achieving 0.5481 similarity on Information Disclosure, but below the 0.75 cutoff.
5. **T5: DoS on cloud (`AS-1`) — Similarity: 0.3497:**
   * **Expert Vector:** *"Denial of Service via resource exhaustion flooding cloud or lock communication channels to prevent normal lock operations."*
   * **Top Scenario (`THR-PATH-E91AA507-045`):** Pipeline prioritized physical unlock manipulation over volumetric cloud API flooding for `AS-1`.
6. **T6: Key extraction via side-channel (`AS-6`) — Similarity: 0.4466:**
   * **Expert Vector:** *"Cryptographic key extraction via physical or electromagnetic side-channel analysis."*
   * **Top Scenario (`THR-PATH-00398FCF-055`):** In Run 1, `AS-6` was absent. In Run 2, `AS-6` Cryptographic Keys was evaluated and achieved 0.4466 similarity on hardware key compromise, below 0.75.

---

## Comparison: Run 1 vs Run 2

| Evaluation Dimension | Run 1 (3-Asset Fixture) | Run 2 (Corrected 6-Asset Fixture) | Delta / Impact |
| :--- | :---: | :---: | :---: |
| **Fixture Assets Defined** | 3 (`AS-1`, `AS-2`, `AS-3`) | 6 (`AS-1`, `AS-2`, `AS-3`, `AS-4`, `AS-5`, `AS-6`) | +3 assets (100% spec alignment) |
| **Total Scenarios Generated** | 30 | 60 | +30 scenarios |
| **True Positives (TP)** | 0 | 0 | 0 |
| **False Negatives (FN)** | 6 | 6 | 0 |
| **False Positives (FP)** | 30 | 60 | +30 |
| **Precision** | 0.0000 (0.0%) | 0.0000 (0.0%) | 0.0% |
| **Recall** | 0.0000 (0.0%) | 0.0000 (0.0%) | 0.0% |
| **F1 Score** | 0.0000 | 0.0000 | 0.0000 |
| **T1 Similarity (AS-1)** | 0.6801 | **0.7020** | **+0.0219** (Near-miss to 0.75) |
| **T2 Similarity (AS-2)** | 0.4781 | 0.4507 | -0.0274 |
| **T3 Similarity (AS-3)** | 0.5452 | **0.6167** | **+0.0715** (Improved firmware alignment) |
| **T4 Similarity (AS-5)** | 0.5036 (cross-asset artifact) | **0.5481** (true AS-5 scenario) | **+0.0445** (Structural gap resolved) |
| **T5 Similarity (AS-1)** | 0.6934 | 0.3497 | -0.3437 |
| **T6 Similarity (AS-6)** | 0.3477 (cross-asset artifact) | **0.4466** (true AS-6 scenario) | **+0.0989** (Structural gap resolved) |

### Key Takeaways
1. **Methodological Rigor Preserved:** The metric scores ($P=0, R=0, F1=0$) remained at 0 because the strict 0.75 cosine similarity threshold was maintained without post-hoc tuning.
2. **Elimination of Structural Defect:** Expanding the fixture to all six assets completely resolved the architectural coverage gap where T4 and T6 were impossible to evaluate. Scenarios targeting `AS-5` and `AS-6` are now actively generated, validated, and ranked.
3. **Similarity Progress:** Cosine similarity improved for T1 (0.7020), T3 (0.6167), T4 (0.5481), and T6 (0.4466). T1 is within 0.048 of a formal match.

---

## Verification & Audit Artifacts

* **Run 1 Raw Output:** [`docs/research/smart_door_lock_scenarios_raw_run1.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run1.json)
* **Run 2 Raw Output:** [`docs/research/smart_door_lock_scenarios_raw_run2.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run2.json)
* **Ground Truth Source:** [`tests/threat_agent/research/ground_truth_t1_t6.json`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/ground_truth_t1_t6.json)
* **Consistency Regression Test:** [`tests/threat_agent/research/test_ground_truth_fixture_consistency.py`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/test_ground_truth_fixture_consistency.py)
* **Evaluation Script:** [`tests/threat_agent/research/evaluate_t1_t6.py`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/evaluate_t1_t6.py)
