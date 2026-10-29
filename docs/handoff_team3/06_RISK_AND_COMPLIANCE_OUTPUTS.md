# 06 · Risk and attack-resistance outputs (built 29 Oct 2026)

These two records extend the chain to `UC → Asset → Threat → Risk → Resistance → Requirement`. Both are
produced by rules from human-confirmed ratings and stored in the SCRS **only after a named person approves**.

> **Placeholders:** the rating tables (risk matrix, feasibility points) and the resistance rule base are
> placeholders until the company confirms theirs. Every record carries `ratings_version` / `rules_version`
> (`placeholder-v0`) and says which cells came from the company, which were derived and which are provisional.

## 1. RiskAssessment (one per approved threat) — SCRS key `risk_assessments[tid]`

| Attribute | Meaning |
|---|---|
| `risk_id` | `RISK-<tid>` |
| `tid`, `project_id`, `use_case_id`, `asset_id` | links back to the threat, use case and asset |
| `impact` | `safety`, `financial`, `operational`, `privacy`, each Negligible / Moderate / Major / Severe or null (axis not applicable) |
| `overall_impact` | highest of the four axes (rule) |
| `feasibility_factors`, `feasibility_points` | the five ISO/SAE 21434 factors and their sum (null if the expert rated feasibility directly) |
| `attack_feasibility` | Low / Medium / High |
| `risk` | Low / Medium / High from the matrix (computed) |
| `risk_basis` | `company`, `derived` or `provisional`: where the matrix cell came from |
| `justification` | plain-language reasons for the score (impact, points, matrix cell, who suggested what) |
| `adjusted_risk`, `adjustment_reason` | the expert's override of the computed risk, with a mandatory reason |
| **`effective_risk`** | **use this one**: the adjusted risk if present, else `risk` |
| `rank_in_asset` | 1 = highest risk of that asset |
| `treatment` | Reduce / Share / Retain / Avoid |
| `treatment_rationale` | why |
| `residual_risk`, `residual_basis` | risk that remains after the treatment, and how it was decided (expert judgement / accepted as is) |
| `ai_suggested`, `suggestion_basis` | whether the ratings were an AI or rule suggestion, or entered by the expert |
| `status`, `approved_by` | `approved` and the approver's name (always present in the SCRS) |
| `rejections_before_approval` | how many times the expert rejected the suggestion first |
| `threat_fingerprint`, `ratings_version`, `run_id` | staleness check and traceability |

**What you should do with it**

| `treatment` | Requirements Agent |
|---|---|
| **Reduce** | derive a security requirement (key: `tid`, also `risk_id`); the resistance record below tells you how strong |
| **Share** | no requirement by default; record the party it moves to |
| **Retain** | no requirement; list under *residual risk* with `residual_risk` and `treatment_rationale` |
| **Avoid** | the feature or asset changes upstream; the threat becomes inactive when Team 1 updates the input |

## 2. ComplianceRecord (required attack resistance) — SCRS key `compliance_records[tid]`

Created for threats treated with **Reduce** (option `--all` / `include_all=true` maps the others too).

| Attribute | Meaning |
|---|---|
| `compliance_id` | `CMP-<tid>` |
| `tid`, `risk_id`, `asset_id`, `use_case_id`, `project_id` | links |
| `effective_risk` | the risk the mapping is based on |
| `suggested_attacker_class`, `attacker_class` | class by rule, and the class the expert confirmed (Basic, Enhanced-Basic, Moderate, High) |
| `required_resistance` | e.g. "Resistant to Moderate attackers" |
| `jil_attack_potential`, `sesip_level`, `cc_eal` | from the rule base; the text `needs company value` means the company has not given it yet |
| `rule_id`, `rule_basis` | `CR-1..3` (provisional rule risk → class) or `EXPERT-OVERRIDE`; table row source |
| `overridden`, `override_reason`, `notes` | the expert changed the class (reason mandatory) |
| `justification` | plain-language explanation |
| `status`, `confirmed_by` | `confirmed` and the expert's name |

## 3. Audit log actions you will see (all carry the person's name in `reason`)

`risk_reject`, `risk_edit`, `risk_adjust`, `risk_approve`, `risk_stale`,
`compliance_confirm`, `compliance_override`, `compliance_reject`, `compliance_stale`.

## 4. Staleness

If an approved threat is retired or re-generated, the risk built on it shows up as stale (`POST /risk-agent/staleness`);
if a risk or its treatment changes, the resistance record built on it shows up as stale
(`POST /compliance-agent/staleness`). Retire, then redo that step.

## 5. Interfaces

Command line: `python scripts/risk_demo.py`, `python scripts/compliance_demo.py`.
REST (`/api/v1/`): `risk-agent/{ratings,suggest,score,approve,reject,assessments,staleness,retire-stale}` and
`compliance-agent/{rules,propose,confirm,reject,records,staleness,retire-stale}`.
Samples in `samples/output_risk_assessments_sample.json`, `output_compliance_records_sample.json`,
`output_scrs_state_with_risk_sample.json`; models in `schemas/risk_schemas.py`, `schemas/compliance_schemas.py`.
