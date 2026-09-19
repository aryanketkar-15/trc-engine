# T1-T6 Ground-Truth Evaluation Results (Smart Door Lock)

**Evaluation Date:** 2026-09-19T09:02:06.327224+00:00
**Fixture Evaluated:** `tests/threat_agent/e2e/fixtures/smart_door_lock/input.json`
**Semantic Model:** `sentence-transformers/all-MiniLM-L6-v2`
**Cosine Similarity Threshold:** 0.75 (fixed §4 protocol threshold; no post-hoc tuning)

## 1. Executive Summary & Metric Scores

| Metric | Value | Definition |
| :--- | :--- | :--- |
| **Expert Baseline Threats (N)** | **6** | Total expert-authored threats (T1-T6) |
| **Generated Scenarios** | **30** | Total scenarios produced by Threat Agent pipeline |
| **True Positives (TP)** | **0** | Expert threats matched by $\ge 1$ generated scenario |
| **False Negatives (FN)** | **6** | Expert threats missed by all generated scenarios |
| **False Positives (FP)** | **30** | Generated scenarios matching no expert baseline threat |
| **Precision** | **0.0000** (0.0%) | Ratio of matched scenarios to total generated scenarios |
| **Recall** | **0.0000** (0.0%) | Ratio of matched expert threats to total expert threats (TP / 6) |
| **F1 Score** | **0.0000** | Harmonic mean of Precision and Recall |

> [!IMPORTANT]
> **Evaluation Integrity Notice:** All results are reported exactly as computed under the fixed $0.75$ cosine similarity threshold. No post-hoc threshold adjustment was performed.

## 2. Per-Threat Breakdown (T1-T6)

| ID | Title | Asset | Expected STRIDE | Expected KB | Status | Matching Scenario(s) | Top Cosine Sim |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | BLE replay | `AS-1` | Spoofing, Tampering | `CAPEC-94` | MISSED | None | 0.6801 |
| **T2** | cloud account takeover | `AS-2` | ElevationOfPrivilege | `ATT&CK-T1078` | MISSED | None | 0.4781 |
| **T3** | malicious OTA firmware | `AS-3` | Tampering | `CAPEC-186` | MISSED | None | 0.5452 |
| **T4** | eavesdropping/MitM | `AS-5` | InformationDisclosure | `CAPEC-117` | MISSED | None | 0.5036 |
| **T5** | DoS on cloud | `AS-1` | DenialOfService | `CAPEC-125` | MISSED | None | 0.6934 |
| **T6** | key extraction via side-channel | `AS-6` | Tampering, InformationDisclosure | `CAPEC-189` | MISSED | None | 0.3477 |

## 3. Analysis of Findings

### 3.1 True Positives (Matched Threats)
No expert threats met the combined match criteria ($asset\_id$, $STRIDE$, and $\ge 0.75$ semantic similarity).

### 3.2 False Negatives (Missed Threats & Root Causes)
#### T1: BLE replay (AS-1)
* **Expert Target Asset:** `AS-1`
* **Expected STRIDE:** ['Spoofing', 'Tampering']
* **Expected KB Reference:** `CAPEC-94`
* **Expert Vector:** Adversary in the Middle or BLE replay attack capturing pairing tokens or unlock commands to spoof legitimate user.
* **Highest Observed Cosine Similarity:** 0.6801 (THR-PATH-4DC3BCD8-003)
* **Root Cause Analysis (Semantic & Category Boundary):** Asset `AS-1` exists in the fixture, but no generated scenario reached the $\ge 0.75$ cosine similarity threshold alongside exact STRIDE and asset matching. The highest observed similarity was 0.6801.

#### T2: cloud account takeover (AS-2)
* **Expert Target Asset:** `AS-2`
* **Expected STRIDE:** ['ElevationOfPrivilege']
* **Expected KB Reference:** `ATT&CK-T1078`
* **Expert Vector:** Cloud account takeover exploiting valid credentials or phishing to gain administrative control and issue unauthorized commands.
* **Highest Observed Cosine Similarity:** 0.4781 (THR-PATH-908C25A0-028)
* **Root Cause Analysis (Semantic & Category Boundary):** Asset `AS-2` exists in the fixture, but no generated scenario reached the $\ge 0.75$ cosine similarity threshold alongside exact STRIDE and asset matching. The highest observed similarity was 0.4781.

#### T3: malicious OTA firmware (AS-3)
* **Expert Target Asset:** `AS-3`
* **Expected STRIDE:** ['Tampering']
* **Expected KB Reference:** `CAPEC-186`
* **Expert Vector:** Malicious OTA firmware delivery replacing authentic device firmware via unauthenticated or unverified update mechanism.
* **Highest Observed Cosine Similarity:** 0.5452 (THR-PATH-93775C91-008)
* **Root Cause Analysis (Semantic & Category Boundary):** Asset `AS-3` exists in the fixture, but no generated scenario reached the $\ge 0.75$ cosine similarity threshold alongside exact STRIDE and asset matching. The highest observed similarity was 0.5452.

#### T4: eavesdropping/MitM (AS-5)
* **Expert Target Asset:** `AS-5`
* **Expected STRIDE:** ['InformationDisclosure']
* **Expected KB Reference:** `CAPEC-117`
* **Expert Vector:** Eavesdropping and adversary-in-the-middle sniffing communication traffic on unencrypted channels to disclose sensitive information.
* **Highest Observed Cosine Similarity:** 0.5036 (THR-PATH-F787D850-019)
* **Root Cause Analysis (Asset Fixture Boundary):** The Smart Door Lock fixture (`tests/threat_agent/e2e/fixtures/smart_door_lock/input.json`) only models assets `AS-1` (BLE Controller), `AS-2` (Secure Element), and `AS-3` (Cloud Backend). Asset `AS-5` is not defined in the input system model fixture. Consequently, the agent cannot generate threats for `AS-5`.

#### T5: DoS on cloud (AS-1)
* **Expert Target Asset:** `AS-1`
* **Expected STRIDE:** ['DenialOfService']
* **Expected KB Reference:** `CAPEC-125`
* **Expert Vector:** Denial of Service via resource exhaustion flooding cloud or lock communication channels to prevent normal lock operations.
* **Highest Observed Cosine Similarity:** 0.6934 (THR-PATH-F3D7436E-026)
* **Root Cause Analysis (Semantic & Category Boundary):** Asset `AS-1` exists in the fixture, but no generated scenario reached the $\ge 0.75$ cosine similarity threshold alongside exact STRIDE and asset matching. The highest observed similarity was 0.6934.

#### T6: key extraction via side-channel (AS-6)
* **Expert Target Asset:** `AS-6`
* **Expected STRIDE:** ['Tampering', 'InformationDisclosure']
* **Expected KB Reference:** `CAPEC-189`
* **Expert Vector:** Cryptographic key extraction via physical or electromagnetic side-channel analysis.
* **Highest Observed Cosine Similarity:** 0.3477 (THR-PATH-F787D850-019)
* **Root Cause Analysis (Asset Fixture Boundary):** The Smart Door Lock fixture (`tests/threat_agent/e2e/fixtures/smart_door_lock/input.json`) only models assets `AS-1` (BLE Controller), `AS-2` (Secure Element), and `AS-3` (Cloud Backend). Asset `AS-6` is not defined in the input system model fixture. Consequently, the agent cannot generate threats for `AS-6`.

## 4. Verification & Audit Trail

* **Raw Scenarios Saved:** [`docs/research/smart_door_lock_scenarios_raw.json`](file:///C:/Users/Chetan/trc-engine/docs/research/smart_door_lock_scenarios_raw.json)
* **Ground Truth Source:** [`tests/threat_agent/research/ground_truth_t1_t6.json`](file:///C:/Users/Chetan/trc-engine/tests/threat_agent/research/ground_truth_t1_t6.json)
* **Evaluation Script:** [`tests/threat_agent/research/evaluate_t1_t6.py`](file:///C:/Users/Chetan/trc-engine/tests/threat_agent/research/evaluate_t1_t6.py)
