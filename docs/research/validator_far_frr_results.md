# Protocol Invariant Validator: FAR & FRR Measurement Results

**Evaluation Date:** 2026-09-19  
**Component Under Test:** Protocol Invariant Validator (`agents/threat_agent/validator.py`)  
**Evaluation Dataset:** 50 hand-labeled scenarios (`tests/threat_agent/research/validator_far_frr_dataset.json`)  
**Benchmark Script:** `tests/threat_agent/research/validator_far_frr.py`  
**Execution Environment:** Python 3.14.7, pytest-9.1.1  

---

## 1. Executive Summary & Core Metrics

The Protocol Invariant Validator operates as the deterministic gate between the LLM threat generator and the human-approval checkpoint. This benchmark measures the validator's **False Acceptance Rate (FAR)** and **False Rejection Rate (FRR)** against a comprehensive ground-truth test suite of valid controls and invalid boundary cases.

| Metric | Measured Value | Percentage | Definition | Security / Usability Implication |
| :--- | :---: | :---: | :--- | :--- |
| **Total Scenarios ($N$)** | 50 | 100.0% | Complete labeled evaluation suite | Balanced sample covering all 4 validator checks |
| **Valid Controls ($N_{val}$)** | 24 | 48.0% | Expert-verified valid threat scenarios | Broad coverage across Smart Door Lock & Infusion Pump |
| **Invalid Cases ($N_{inv}$)** | 26 | 52.0% | Handcrafted defective/boundary threats | $\ge 5$ targeted defects per validator check |
| **True Accepts (TA)** | 22 / 24 | 91.67% | Valid scenarios correctly approved | Gating allows high throughput of valid threats |
| **False Rejects (FR)** | 2 / 24 | **8.33%** | Valid scenarios incorrectly rejected (**FRR**) | Reviewer friction; valid ideas dropped or forced to retry |
| **True Rejects (TR)** | 22 / 26 | 84.62% | Invalid scenarios correctly blocked (**TRR**) | Gating specificity against flawed threats |
| **False Accepts (FA)** | 4 / 26 | **15.38%** | Invalid scenarios incorrectly passed (**FAR**) | Security risk; defective threats reach human reviewer |
| **Overall Accuracy** | 44 / 50 | **88.00%** | $(TA + TR) / N$ | Aggregate classification performance |

> [!IMPORTANT]
> **Research Honesty Statement:** The measured False Acceptance Rate is **15.38%** ($4 / 26$) and False Rejection Rate is **8.33%** ($2 / 24$). As instructed by the Project Synopsis and Prompt Book, these numbers are reported without altering test cases to force artificial perfection. The non-zero FAR and FRR reveal concrete architectural boundaries between heuristic checks and semantic understanding.

---

## 2. Invariant Check Detection Breakdown

The validator executes four independent checks on each candidate scenario. The table below evaluates the detection rate specifically across the 26 invalid test cases targeted at each check:

| Invariant Check ID | Target Function | Invalid Cases Targeted | Successfully Blocked | Missed (False Accepts) | Detection Rate |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`CHECK_SCHEMA_INCOMPLETE`** | `schema_completeness_check` | 5 | 5 | 0 | **100.0%** |
| **`CHECK_EVIDENCE_GENERIC`** | `evidence_completeness_check` | 7 | 6 | 1 | **85.7%** |
| **`CHECK_CITATION_MISSING`** | `citation_presence_check` | 6 | 5 | 1 | **83.3%** |
| **`CHECK_CONSISTENCY_MISMATCH`** | `consistency_check` | 8 | 6 | 2 | **75.0%** |

### Key Check-Level Observations:
1. **Schema Completeness (100%):** Pure structural and whitespace checks (`value.strip()`) are deterministic and flawless. All missing fields (`tid`, `asset_id`, `attack_vector`, `kb_reference`) were caught with zero false accepts.
2. **Evidence Detail (85.7%):** Effectively catches missing fields, standard placeholders (`"N/A"`, `"TBD"`), and short strings ($<20$ characters). However, it cannot evaluate semantic quality if an LLM outputs long, tautological prose.
3. **Citation Presence (83.3%):** Catches empty strings, whitespace, and common placeholders. Fails when the placeholder is phrased as a sentence.
4. **STRIDE Consistency (75.0%):** Resolves typical cross-category hallucinations (e.g. DoS labeled as Spoofing). Fails when attacks use negated keywords or valid threats use domain terminology not in the static vocabulary.

---

## 3. Detailed Root-Cause Analysis of Misclassified Cases

Six scenarios in the evaluation set were misclassified (2 False Rejections, 4 False Acceptances). Each case was individually investigated to determine whether the root cause lies in the validator or the labeling:

### 3.1 False Rejections (Valid Scenarios Incorrectly Blocked — FRR = 8.33%)

#### 1. Case `VAL-CTL-023`
* **Scenario Summary:** Smart Door Lock — Physical badge cloning (`Spoofing`).
* **Attack Vector:** `"Physical duplication of RFID transponder to mimic authorized tenant keycard"`
* **Ground Truth:** VALID. Physical cloning of an RFID tag to impersonate an authorized user is a textbook STRIDE Spoofing attack.
* **Validator Outcome:** REJECTED (`CHECK_CONSISTENCY_MISMATCH`).
* **Root Cause:** **Validator Heuristic Vocabulary Gap.** `STRIDE_VECTOR_VOCABULARY[STRIDECategory.SPOOFING]` contains terms such as `replay`, `impersonation`, `credential theft`, `phishing`, `spoof`, `forgery`, and `masquerade`. However, standard domain terms like `duplication`, `mimic`, `clone`, `rfid`, or `transponder` are omitted. Because none of the hardcoded keywords appeared, the check flagged a false inconsistency.

#### 2. Case `VAL-CTL-024`
* **Scenario Summary:** Smart Door Lock — Hardware bus probing (`InformationDisclosure`).
* **Attack Vector:** `"Oscilloscope probing of serial SPI bus during device startup sequence"`
* **Ground Truth:** VALID. Attaching an oscilloscope or logic probe to sniff bus traffic during boot is a classic hardware Information Disclosure vector.
* **Validator Outcome:** REJECTED (`CHECK_CONSISTENCY_MISMATCH`).
* **Root Cause:** **Validator Heuristic Vocabulary Gap.** The vocabulary for `InformationDisclosure` contains network-centric keywords (`eavesdrop`, `sniffing`, `data exfiltration`, `unencrypted transmission`, `leak`, `expose`), but lacks physical instrumentation keywords such as `probing`, `oscilloscope`, `spi`, or `bus`.

---

### 3.2 False Acceptances (Invalid Scenarios Incorrectly Passed — FAR = 15.38%)

#### 3. Case `VAL-INV-006`
* **Scenario Summary:** Smart Door Lock — Cloud API authentication bypass with conversational placeholder citation.
* **Citation Field:** `"None provided by LLM analysis"`
* **Ground Truth:** INVALID. The scenario does not cite any real KB reference (CAPEC, ATT&CK, or CWE).
* **Validator Outcome:** PASSED (All checks passed).
* **Root Cause:** **Validator String Matching Heuristic.** `PLACEHOLDER_CITATION_STRINGS` uses an exact lowercased set lookup against `{"" , "n/a", "tbd", "todo", "placeholder", "unknown", "none", "null", "undefined"}`. Because `"none provided by llm analysis"` does not match `"none"` exactly, the check evaluated to `True`.

#### 4. Case `VAL-INV-018`
* **Scenario Summary:** Smart Door Lock — DoS packet blast mislabeled as Spoofing with negation trap.
* **STRIDE Category:** `Spoofing`
* **Attack Vector:** `"Volumetric packet blast which strictly avoids any fake identity or spoofing attempt"`
* **Ground Truth:** INVALID. The attack is volumetric Denial of Service, not Spoofing. The text explicitly asserts that it avoids spoofing.
* **Validator Outcome:** PASSED (`consistency_check` returned `(True, None)`).
* **Root Cause:** **Validator Substring Matching Heuristic.** The check performs `any(fragment in vector_lower for fragment in valid_fragments)`. Because the string contains `"fake"` and `"spoof"`, the substring match triggered positive, ignoring grammatical negation.

#### 5. Case `VAL-INV-019`
* **Scenario Summary:** Smart Door Lock — Mechanical wrench breach mislabeled as Information Disclosure with negation trap.
* **STRIDE Category:** `InformationDisclosure`
* **Attack Vector:** `"Physical wrench torque on bolt mechanism ensuring zero data leak or secret exposure"`
* **Ground Truth:** INVALID. The attack is physical tampering and brute-force destruction, not Information Disclosure.
* **Validator Outcome:** PASSED (`consistency_check` returned `(True, None)`).
* **Root Cause:** **Validator Substring Matching Heuristic.** Substring search matched `"leak"` and `"exposure"`, completely blind to the negative prefix `"zero data leak"`.

#### 6. Case `VAL-INV-026`
* **Scenario Summary:** Infusion Pump — Telemetry server impersonation with tautological applicability reasoning.
* **Applicability Reason:** `"This pattern applies to this asset because the vulnerability is applicable to the system configuration."` (102 characters)
* **Ground Truth:** INVALID. Tautological prose that restates the premise without explaining technical mechanisms or asset context.
* **Validator Outcome:** PASSED (`evidence_completeness_check` returned `(True, None)`).
* **Root Cause:** **Validator Length Threshold Heuristic.** The check verifies `len(reason) >= 20` and checks against 8 static generic strings (`"n/a"`, `"tbd"`, etc.). At 102 characters, the vacuous string comfortably cleared the length threshold.

---

## 4. Architectural Summary & Phase 2 Roadmap

| Check Area | Current Heuristic Implementation | Demonstrated Limitation | Phase 2 Solution |
| :--- | :--- | :--- | :--- |
| **Citation Verification** | Exact match against static 9-element placeholder set | Multi-word explanations like `"None provided"` evade detection | **Regex / Canonical Prefix Gate:** Require citation to match `^(CAPEC-\d+\|ATT&CK T\d+\|CWE-\d+\|https?://)` |
| **STRIDE Consistency** | Case-insensitive substring match in keyword fragment dictionary | 1. Omitted domain terms trigger FRR (8.3%)<br>2. Negation phrases trigger FAR (15.4%) | **Small NLI / LLM Guard:** Use embedding similarity or a lightweight NLI classifier to evaluate semantic alignment rather than raw substring presence |
| **Evidence Reasoning** | Character length $\ge 20$ + static placeholder set | Long tautologies pass without technical substance | **Entropy / Information Density Metric:** Measure token repetition or employ SCRS contextual consistency check |

---

## 5. Audit & Reproduction Commands

To reproduce these measurements locally on the repository:

```bash
# Fast standalone execution
python tests/threat_agent/research/validator_far_frr.py

# Pytest regression suite
pytest tests/threat_agent/research/validator_far_frr.py -v

# Code style compliance
ruff check tests/threat_agent/research/validator_far_frr.py
```

All 50 labeled scenarios are permanently audited in [`tests/threat_agent/research/validator_far_frr_dataset.json`](file:///c:/Users/Chetan/trc-engine/tests/threat_agent/research/validator_far_frr_dataset.json).
