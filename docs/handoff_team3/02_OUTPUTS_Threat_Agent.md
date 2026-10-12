# 02 · Outputs: what the Threat Agent produces

The Threat Agent outputs a **list of `ThreatScenario` objects**. One scenario = one way an attacker could harm
one asset, with the evidence for it. Exact definitions: `schemas/threat_schemas.py` (Pydantic) or
`schemas/threat_scenario.schema.json` (JSON Schema). Real examples: `samples/output_threat_scenarios_sample.json`
(and `.csv` for Excel).

## 1. One scenario, annotated

```json
{
  "tid": "THR-PATH-FF8876D6-001",                        // threat ID
  "asset_id": "AS-4",                                     // which asset (foreign key to Team 1's asset table)
  "stride_category": "Tampering",                         // type of threat
  "attack_vector": "Physical access to manipulate audit log firmware via SPI Flash.",
  "kb_reference": "CAPEC-665",                            // the catalogue entry it is based on
  "evidence_chain": {
    "exposure": "SPI Flash interface lacks tamper protection.",
    "matched_pattern": "CAPEC-665",
    "applicability_reason": "The audit log's SPI Flash interface is accessible without tamper protection, ...",
    "citation": "CAPEC-665: Exploitation of Thunderbolt Protection Flaws (CAPEC v3.9)"
  },
  "confidence_score": 0.769,                              // 0..1
  "status": "approved",                                   // lifecycle
  "validation_status": "passed",                          // automatic-check result
  "run_id": "RUN-SDL-E2E-001",                            // which run produced it
  "use_case_id": "UC-6E516A54",                           // traceability back to the use case
  "asset_version": "1.0",                                 // version of the asset record used
  "kb_snapshot_version": "latest",                        // knowledge-base version label
  "created_at": "2026-10-10T15:13:46.601214Z"
}
```

## 2. Attribute reference (`ThreatScenario`)

| Attribute | Type | Required | Meaning / allowed values | Notes for Team 3 |
|---|---|---|---|---|
| `tid` | string | yes | Unique threat ID. Format `THR-PATH-<8 hex>-<seq>` for AI-generated, `THR-EXP-<8 hex>` for expert-added | Use as the primary key for traceability. If a scenario is replaced after a rejection, the new one may get a new `tid`; the audit log entry `revise` links old (`previous_tid`) to new |
| `asset_id` | string | yes | `AS-n` of the targeted asset | Foreign key to Team 1's `SecurityAsset.id` |
| `stride_category` | enum | yes | `Spoofing`, `Tampering`, `Repudiation`, `InformationDisclosure`, `DenialOfService`, `ElevationOfPrivilege` | One STRIDE type per scenario |
| `attack_vector` | string | yes | Human-readable description of the attack, specific to the asset | The text a requirement would be written against |
| `kb_reference` | string | yes | Primary catalogue entry: `CAPEC-<n>`, `ATT&CK-T<nnnn>[.<nnn>]`, `CWE-<n>`, or `STRIDE-<X>-001` (our STRIDE rule entries) | **Every scenario has one**; it is verified in code to be a pattern that was really retrieved (or, for expert adds, that exists in the catalogue) |
| `evidence_chain.exposure` | string | yes | The property or interface of the asset that is exposed | |
| `evidence_chain.matched_pattern` | string | yes | Pattern ID matched; always equals `kb_reference` | |
| `evidence_chain.applicability_reason` | string | yes | Why the pattern applies to this asset (≥ 20 characters, specific) | Rationale for explainability |
| `evidence_chain.citation` | string | yes | Formal citation text naming the pattern | |
| `confidence_score` | float 0–1 | yes | **Average similarity** between the asset description and the pattern(s) used; **not** the probability that the attack is real | Below 0.4 we show a "low confidence" warning. Expert-added scenarios are fixed at 1.0 (human-asserted) |
| `status` | enum | yes | `pending_test`, `pending_human`, `approved`, `rejected` | **Only `approved` may be used downstream** (section 3) |
| `validation_status` | string or null | no | `passed`, `escalated_after_retries`, `expert_added` (see section 4) | Carry it into your reports as a quality flag |
| `run_id` | string | yes | The run that produced it (`RUN-…`) | |
| `use_case_id` | string or null | no | Use case the scenario belongs to | Today derived as `UC-<hash>` if the input has no ID; will be Team 1's `usecase_id` after integration |
| `asset_version` | string or null | no | Version of the asset record the threat was derived from | Compare with the current asset version to detect stale threats |
| `kb_snapshot_version` | string or null | no | Knowledge-base version label used | Currently the label `latest` (not yet a content hash) |
| `created_at` | datetime (UTC) | yes | When the scenario was created | |

## 3. Status lifecycle

```
pending_test ──(automatic checks pass)──► pending_human ──(human approves)──► approved   ← the only usable state
     ▲                                          │
     └──(checks fail, retry up to 3×)           └──(human rejects)──► rejected (revised version replaces it, or it is dropped)
```

* **`approved`** = a human expert accepted it. This is the only status you may build requirements or audits on.
* `pending_test` / `pending_human` = drafts. Ignore them.
* `rejected` = a human refused it. It is kept in the history (file 03) but is not part of the result.

## 4. `validation_status` (the automatic checks)

Every scenario passes five automatic, rule-based checks (no AI): citation present, schema complete, STRIDE fit
(attack words match the threat type), evidence specific, and grounded (cites only a retrieved pattern, a real
asset, and an exposure belonging to that asset). Result:

| Value | Meaning | What to do with it |
|---|---|---|
| `passed` | All checks passed | normal |
| `escalated_after_retries` | A check still failed after 3 automatic retries; a human looked at it and approved anyway | usable, but **report it as "approved with automatic-check warning"** |
| `expert_added` | Written by a human expert; validated and its catalogue ID verified | usable; confidence is 1.0 by definition |

Our measured error rates for the checker (50 labelled scenarios): wrongly accepts 15.38 %, wrongly rejects 8.33 %.
A passed scenario is therefore **not guaranteed correct**; that is why a human approves each one.

## 5. Where to read the output

| Method | Detail |
|---|---|
| **Files** | `samples/output_threat_scenarios_sample.json` (list of scenarios) and `samples/output_scrs_state_sample.json` (shared state, see file 03) |
| **REST API** (our service, prefix `/api/v1/threat-agent`) | `POST /analyze` start a run · `GET /{run_id}/status` · `GET /{run_id}/scenarios` · `POST /{run_id}/approve` · `POST /{run_id}/reject` · `POST /{run_id}/scenarios/{tid}/prune` · `POST /{run_id}/scenarios` (expert add). Header `X-API-Key` required |
| **Shared state (SCRS)** | JSON file with `threat_scenarios` (approved only), `audit_log`, `revision_history` |
| **After integration** | Team 2's `threat_artefacts` table in the shared database (the table exists in Team 1's schema; our write path is not built yet) |

## 6. What every scenario guarantees (and what it does not)

| Guaranteed (checked by code) | Not guaranteed |
|---|---|
| Has a catalogue reference that is real and was retrieved for this asset | That the attack is technically perfect or complete |
| Targets an asset that exists in the input | That all relevant threats for the asset were found (coverage is not proven) |
| Evidence fields are filled and specific to the asset | That `confidence_score` means probability |
| Approved scenarios were accepted by a human; all decisions are logged | That the knowledge base contains your company's internal patterns (it does not) |
