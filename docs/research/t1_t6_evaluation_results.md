# T1-T6 Ground-Truth Evaluation Results (Smart Door Lock)

**Scope:** Phase 1 Closeout — Smart Door Lock Fixture Evaluation (§4)  
**Evaluation Dates:**
- Run 1: 2026-09-19T09:02:06Z (3-Asset Fixture, Fallback)
- Run 2: 2026-09-20T09:32:41Z (6-Asset Fixture, Fallback)
- Run 3: 2026-09-21T06:02:42Z (6-Asset Fixture, Live LLM Execution Attempt — Invalidated)
- Run 4: 2026-09-23T19:18:22Z (6-Asset Fixture, Verified 100% Live-LLM Execution — Authoritative)

**Semantic Model:** `sentence-transformers/all-MiniLM-L6-v2`  
**Cosine Similarity Threshold:** 0.75 (fixed §4 protocol threshold; no post-hoc tuning)  
**Matching Predicate:** Scenario $G$ matches expert threat $T$ iff:
1. $G.\text{asset\_id} == T.\text{asset\_id}$
2. $G.\text{stride\_category}$ matches $T.\text{stride\_category}$
3. $\text{CosineSimilarity}(G.\text{attack\_vector}, T.\text{attack\_vector}) \ge 0.75$

> [!IMPORTANT]
> **Clarification on Evaluation Terminology:**
> A "false positive" in this T1–T6 matching evaluation means that a generated scenario did not match one of the six predefined expert ground-truth threats under the specified matching criteria. It does **NOT** by itself mean that the generated scenario is invalid, unsafe, or technically incorrect. The Threat Agent generates a broad, standards-grounded threat surface across all input assets (60 scenarios), whereas T1–T6 represents a specific, curated six-threat baseline.

> [!NOTE]
> **Historical Offline Runs vs. Live-LLM Evaluation:**
> Run 1 and Run 2 are preserved historical/offline diagnostic runs executed under deterministic fallback generation due to credential unavailability at the time. Run 3 was a live execution attempt invalidated due to external API in-flight budget exhaustion. **Run 4 is the authoritative, verified 100% live-LLM evaluation** satisfying all Part 4/8 protocol conditions.

---

## Run 1 — Original Evaluation (Three-Asset Fixture, Fallback Generation)

* **Execution Date:** 2026-09-19T09:02:06.327224+00:00
* **Fixture Evaluated:** Initial 3-asset fixture (`smart_door_lock/input.json`)
* **Generation Mode:** Deterministic fallback generation (`_deterministic_fallback_for_path`).
* **Generation Mode Evidence:** `OPENAI_API_KEY` in environment was a placeholder mock key (`sk-local****-key`). When `chat_completion()` was called, OpenAI returned HTTP 401 Unauthorized (`invalid_api_key`), triggering `llm_fallback_engaged` audit events. All 30 generated scenarios (100%) follow the deterministic template syntax: `"Exploitation of {pattern} ({title}) via {kw} targeting {asset}"`.
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

---

## Run 2 — Six-Asset Fixture (Deterministic Fallback Generation)

* **Execution Date:** 2026-09-20T09:32:41.582412+00:00
* **Fixture Evaluated:** Corrected 6-asset fixture (`smart_door_lock/input.json`) matching company document Section 2.4:
  - `AS-1`: Unlock Command (`Cloud<->Lock channel`, control command)
  - `AS-2`: E-Key Credential (`Cloud DB, App, Lock`, access credential)
  - `AS-3`: Firmware Image (`OTA, Lock flash`, embedded firmware)
  - `AS-4`: Audit Log (`Lock, Cloud`, event log)
  - `AS-5`: User PII (`Cloud, App`, schedule & user data)
  - `AS-6`: Cryptographic Keys (`Secure element`, key material)
* **Generation Mode:** Deterministic fallback generation (`_deterministic_fallback_for_path`).
* **Generation Mode Evidence:** `OPENAI_API_KEY` was configured with local placeholder `sk-local****-key`. `chat_completion()` returned HTTP 401 Unauthorized (`invalid_api_key`), triggering `llm_fallback_engaged` audit logs. All 60 generated scenarios (100%) adhere strictly to the fallback template syntax: `"Exploitation of {pattern} ({title}) via {kw} targeting {asset}"`.
* **Auditability & Preservation:** Preserved verbatim for auditability in [`docs/research/smart_door_lock_scenarios_raw_run2.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run2.json).
* **Comparison Context:** Because both Run 1 and Run 2 executed under the deterministic fallback generator, Run 2 isolates the effect of expanding asset coverage from 3 to 6 assets under the heuristic engine.

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

---

## Run 3 — Six-Asset Fixture (Live LLM Execution Attempt — Invalidated)

* **Execution Date:** 2026-09-21T06:02:42.561250+00:00
* **Fixture Evaluated:** Corrected 6-asset fixture (`smart_door_lock/input.json`) matching company document Section 2.4.
* **Configured Model:** `gpt-4o-mini` (routed via OpenRouter to `openai/gpt-4o-mini`).
* **Generation Mode:** **Hybrid Partial Live / Fallback Invalidation.**
  - **Live LLM Scenarios Produced:** 14 scenarios were successfully generated by the live LLM (`openai/gpt-4o-mini`).
  - **Fallback Scenarios Produced:** 46 scenarios fell back to deterministic template generation (`_deterministic_fallback_for_path`).
* **Fallback Trigger Root Cause (Part 8 Stop Condition):**
  During execution of the 60 attack paths, the external API provider returned:
  ```text
  LLMAPIError: OpenAI API error (HTTP 402) on model 'gpt-4o-mini' after 1 attempt(s): Error code: 402 - 
  {'error': {'message': 'This request would exceed your available credits given your current in-flight requests. Retry after in-flight requests settle, or add credits.', 'code': 402, 'metadata': {'reason': 'in_flight_budget_exhausted', 'limit_source': 'openrouter_in_flight_budget'}}}
  ```
  The account credit balance ($0.01 remaining) was insufficient to support continuous in-flight reservations across 60 sequential calls, triggering `llm_fallback_engaged` on 46 paths.
* **Methodological Invalidation:**
  Per **Part 4** and **Part 8** of the evaluation specification, any occurrence of `llm_fallback_engaged` invalidates the run from being considered a valid, authoritative live-LLM evaluation ("do not treat 'mostly live' as 'live'").
* **Raw Scenario Audit:** Preserved verbatim for auditability in [`docs/research/smart_door_lock_scenarios_raw_run3_partial.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run3_partial.json).

---

## Run 4 — Six-Asset Fixture (Verified 100% Live-LLM Execution — Authoritative Final Baseline)

* **Execution Date:** 2026-09-23T19:18:22.426514+00:00 (2026-09-24 00:48:22 IST)
* **Fixture Evaluated:** Corrected 6-asset fixture (`tests/threat_agent/e2e/fixtures/smart_door_lock/input.json`) matching company document Section 2.4.
* **Configured Model:** `gpt-4o-mini` (routed via OpenRouter to `openai/gpt-4o-mini`, temperature: 0.1, `max_tokens`: 4096).
* **Generation Mode:** **100% Verified Live-LLM Inference.**
  - **Live LLM Scenarios Generated:** 60 / 60 scenarios (100%).
  - **Deterministic Fallback Invocations:** **0 / 60 scenarios (0%)**.
  - **API In-Flight Budget / Credit Status:** Verified account funded with credit allowance; all 60 API calls completed with zero HTTP 402 / 429 errors.
  - **Fallback Event Audit:** Full execution log inspection confirms zero occurrences of `llm_fallback_engaged`. All 60 scenarios contain natural-language vulnerability narratives synthesized by the model.
* **Protocol Invariant Validation:**
  - Evaluated across 240 invariant checks (60 scenarios × 4 checks).
  - Clean compliance across 239 checks; 1 scenario flagged on vocabulary synonym strictness (`imitate` vs `impersonat` for Spoofing), automatically escalated per protocol with zero unhandled exceptions.
* **Raw Scenario Audit:** [`docs/research/smart_door_lock_scenarios_raw_live.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_live.json)
* **Machine-Readable Summary:** [`docs/research/t1_t6_live_results.json`](file:///c:/Users/Chetan/trc-engine/docs/research/t1_t6_live_results.json)

### Run 4 Summary & Metrics

| Metric | Value | Definition |
| :--- | :--- | :--- |
| **Expert Baseline Threats (N)** | **6** | Total expert-authored threats (T1–T6) |
| **Generated Scenarios** | **60** | Scenarios produced by Threat Agent pipeline (6 assets × 10 candidates) |
| **True Positives (TP)** | **2** | Expert threats matched by $\ge 1$ generated scenario (`T1`, `T3`) |
| **False Negatives (FN)** | **4** | Expert threats missed by all generated scenarios (`T2`, `T4`, `T5`, `T6`) |
| **False Positives (FP)** | **56** | Generated scenarios covering system surface outside the 6-threat baseline |
| **Precision** | **0.0667** (6.7%) | Ratio of matched scenarios (4) to total generated scenarios (60) |
| **Recall** | **0.3333** (33.3%) | Ratio of matched expert threats (2) to total expert threats (6) |
| **F1 Score** | **0.1111** | Harmonic mean of Precision and Recall |

### Run 4 Per-Threat Breakdown (T1–T6)

| ID | Title | Asset | Expected STRIDE | Expected KB | Status | Matching Scenario(s) | Top Cosine Sim | Matching Scenario Source |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | BLE replay | `AS-1` | Spoofing, Tampering | `CAPEC-94` | **MATCHED** | `THR-PATH-D5983BE4-014`<br>`THR-PATH-49A3AA9F-019` | **0.7953** (overall)<br>**0.7804** (AS-1 match) | Live LLM (`openai/gpt-4o-mini`) |
| **T2** | cloud account takeover | `AS-2` | ElevationOfPrivilege | `ATT&CK-T1078` | MISSED | None | 0.5505 | Live LLM (`openai/gpt-4o-mini`) |
| **T3** | malicious OTA firmware | `AS-3` | Tampering | `CAPEC-186` | **MATCHED** | `THR-PATH-88CB46DA-002`<br>`THR-PATH-865F1D3D-012` | **0.8325** (overall)<br>**0.7986** (AS-3 match) | Live LLM (`openai/gpt-4o-mini`) |
| **T4** | eavesdropping/MitM | `AS-5` | InformationDisclosure | `CAPEC-117` | MISSED | None | 0.5385 | Live LLM (`openai/gpt-4o-mini`) |
| **T5** | DoS on cloud | `AS-1` | DenialOfService | `CAPEC-125` | MISSED | None | 0.3647 | Live LLM (`openai/gpt-4o-mini`) |
| **T6** | key extraction via side-channel | `AS-6` | Tampering, InformationDisclosure | `CAPEC-189` | MISSED | None | 0.5311 | Live LLM (`openai/gpt-4o-mini`) |

---

### Run 4 In-Depth Analysis of Findings

#### 1. True Positives (Matched Threats)
Under genuine live LLM synthesis, the Threat Agent produced nuanced, high-fidelity vulnerability vectors that crossed the strict 0.75 semantic cosine threshold while satisfying exact asset ID and STRIDE category constraints:

* **T1: BLE Replay Attack (`AS-1: Unlock Command`, Expected STRIDE: Spoofing/Tampering)**
  * **Ground Truth Vector:** *"Adversary in the Middle or BLE replay attack capturing pairing tokens or unlock commands to spoof legitimate user."*
  * **Matched Scenario 1 (`THR-PATH-D5983BE4-014`):**
    * *Attack Vector:* `"An attacker forges BLE pairing keys to impersonate a legitimate user and issue unlock commands."`
    * *STRIDE:* `Spoofing` | *KB Reference:* `CAPEC-196` | *Cosine Similarity:* **0.7804**
  * **Matched Scenario 2 (`THR-PATH-49A3AA9F-019`):**
    * *Attack Vector:* `"An attacker captures and replays BLE pairing handshake packets to gain unauthorized access."`
    * *STRIDE:* `Spoofing` | *KB Reference:* `CAPEC-60` | *Cosine Similarity:* **0.7790**

* **T3: Malicious OTA Firmware (`AS-3: Firmware Image`, Expected STRIDE: Tampering)**
  * **Ground Truth Vector:** *"Adversary uploads modified firmware image lacking cryptographic signature verification over OTA update channel."*
  * **Matched Scenario 1 (`THR-PATH-88CB46DA-002`):**
    * *Attack Vector:* `"An attacker exploits the lack of signature verification to upload malicious firmware via the BLE OTA interface."`
    * *STRIDE:* `Tampering` | *KB Reference:* `CAPEC-186` | *Cosine Similarity:* **0.7589**
  * **Matched Scenario 2 (`THR-PATH-865F1D3D-012`):**
    * *Attack Vector:* `"An attacker modifies firmware configuration parameters through an unauthenticated BLE OTA update."`
    * *STRIDE:* `Tampering` | *KB Reference:* `STRIDE-T-001` | *Cosine Similarity:* **0.7986**
  * *(Cross-asset alignment note: Scenario `THR-PATH-D1AD0BD3-058` targeting `AS-2` achieved **0.8325** similarity against T3's firmware vector).*

#### 2. False Negatives (Missed Threats & Root-Cause Audit)
* **T2: Cloud Account Takeover (`AS-2: E-Key Credential`, ElevationOfPrivilege / ATT&CK-T1078):**
  * *Top Scenario (`THR-PATH-D50F5885-034`, AS-2):* Reached 0.5505 similarity via hardcoded credential exploitation (`CWE-798`). The scenario classified under `Spoofing` rather than `ElevationOfPrivilege`. The matching predicate strictly enforces exact STRIDE category equivalence, preventing classification crossover.
* **T4: Eavesdropping/MitM (`AS-5: User PII`, InformationDisclosure / CAPEC-117):**
  * *Top Scenario (`THR-PATH-869D73D8-024`, AS-5):* Reached 0.5385 similarity (`STRIDE-I-001`): *"An attacker intercepts BLE communications to capture unencrypted PII during transactions."* While asset and STRIDE matched, the phrasing divergence kept the cosine score below 0.75.
* **T5: DoS on Cloud (`AS-1: Unlock Command`, DenialOfService / CAPEC-125):**
  * *Top Scenario (`THR-PATH-41CB48F5-052`, AS-2):* Scored 0.3647. T5 in the ground truth models a cloud API backend DoS, whereas the 6-asset Smart Door Lock fixture focuses primarily on on-device lock hardware and Bluetooth communication.
* **T6: Key Extraction via Side-Channel (`AS-6: Cryptographic Keys`, Tampering/InfoDisclosure / CAPEC-189):**
  * *Top Scenario (`THR-PATH-2AA0E45F-023`, AS-6):* Scored 0.5311 (`STRIDE-I-001`): *"An attacker intercepts unencrypted transmission of cryptographic keys over BLE."* The LLM favored wireless transmission interception over physical side-channel power/timing analysis (CAPEC-189).

---

## Comparison: All Four Evaluation Runs

| Dimension | Run 1 (3-Asset Offline) | Run 2 (6-Asset Offline) | Run 3 (Live Attempt, Invalidated) | Run 4 (Verified 100% Live LLM) |
| :--- | :---: | :---: | :---: | :---: |
| **Fixture Scope** | 3 assets (`AS-1`–`AS-3`) | 6 assets (`AS-1`–`AS-6`) | 6 assets (`AS-1`–`AS-6`) | **6 assets (`AS-1`–`AS-6`)** |
| **Generation Mode** | 100% Fallback | 100% Fallback | Hybrid (14 Live, 46 Fallback) | **100% Live LLM (`gpt-4o-mini`)** |
| **Live LLM Calls** | 0 | 0 | 14 | **60 / 60 (100%)** |
| **Fallback Scenarios** | 30 | 60 | 46 | **0 (0%)** |
| **True Positives (TP)** | 0 | 0 | 0 | **2 (`T1`, `T3`)** |
| **False Negatives (FN)** | 6 | 6 | 6 | **4 (`T2`, `T4`, `T5`, `T6`)** |
| **Precision** | 0.0000 (0.0%) | 0.0000 (0.0%) | 0.0000 (0.0%) | **0.0667 (6.7%)** |
| **Recall** | 0.0000 (0.0%) | 0.0000 (0.0%) | 0.0000 (0.0%) | **0.3333 (33.3%)** |
| **F1 Score** | 0.0000 | 0.0000 | 0.0000 | **0.1111** |
| **T1 Similarity (AS-1 Match)** | 0.6801 | 0.7020 | 0.7858 (Cross-asset) | **0.7804** (Direct Match) |
| **T2 Similarity** | 0.4781 | 0.4507 | 0.5021 | **0.5505** |
| **T3 Similarity (AS-3 Match)** | 0.5452 | 0.6167 | 0.7606 (Cross-asset) | **0.7986** (Direct Match) |
| **T4 Similarity** | 0.5036 | 0.5481 | 0.5481 | **0.5385** |
| **T5 Similarity** | 0.6934 | 0.3497 | 0.4077 | **0.3647** |
| **T6 Similarity** | 0.3477 | 0.4466 | 0.4466 | **0.5311** |

### Key Takeaways
1. **Recall Transition (0% $\rightarrow$ 33.3%):** Deterministic fallback templates were incapable of crossing the 0.75 semantic threshold due to rigid sentence formatting. Live LLM generation enabled semantic alignment that yielded **Recall of 33.3% (2/6 TP)** under strict zero-tolerance evaluation rules.
2. **Zero Fallback Compliance:** 60 out of 60 candidate attack paths were successfully executed and synthesized through the live OpenRouter endpoint without triggering `llm_fallback_engaged`.
3. **Rigorous Scientific Integrity:** The cosine similarity cutoff remained strictly anchored at $0.75$ with exact predicate matching (asset, STRIDE, and semantic text). No thresholds were loosened post-hoc.
4. **Complete Audit Trail:** All four runs are independently preserved in the repository for audit and review.

---

## Verification & Audit Artifacts

* **Run 1 Raw Output:** [`docs/research/smart_door_lock_scenarios_raw_run1.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run1.json)
* **Run 2 Raw Output:** [`docs/research/smart_door_lock_scenarios_raw_run2.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run2.json)
* **Run 3 Live Attempt Output (Partial):** [`docs/research/smart_door_lock_scenarios_raw_run3_partial.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_run3_partial.json)
* **Run 4 Final Live Raw Output:** [`docs/research/smart_door_lock_scenarios_raw_live.json`](file:///c:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw_live.json)
* **Live Machine-Readable Summary:** [`docs/research/t1_t6_live_results.json`](file:///c:/Users/Chetan/trc-engine/docs/research/t1_t6_live_results.json)
* **Ground Truth Source:** [`tests/threat_agent/research/ground_truth_t1_t6.json`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/ground_truth_t1_t6.json)
* **Consistency Regression Test:** [`tests/threat_agent/research/test_ground_truth_fixture_consistency.py`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/test_ground_truth_fixture_consistency.py)
* **Evaluation Script:** [`tests/threat_agent/research/evaluate_t1_t6.py`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/evaluate_t1_t6.py)
