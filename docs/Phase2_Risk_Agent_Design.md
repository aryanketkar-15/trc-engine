# Phase 2: Risk Agent and attack-resistance mapping (design and status)

> The attack-resistance mapping grew into the Compliance Agent (Phase 3). Its current rules, including CR-5, are in `docs/Phase3_Compliance_Agent.md`.

Status 29 Oct 2026: built, tested (74 tests in `tests/risk_agent`), demo-ready. Tables and rules are configuration files
(`agents/risk_agent/ratings.json`, `agents/compliance_agent/rules.json`, both version `v1`) and can be changed without code.

Where it sits: `Use case → Asset → Threat → Risk → Resistance → Requirement`. The key between the agents is `tid`.

## 1. What it does

For every **approved** threat from the Threat Agent: rate the **impact**, rate how **feasible** the attack is, compute the
**risk**, rank threats **per asset**, record the expert's **treatment** decision and the **residual risk**, then derive the
**required attack resistance** (JIL attack potential, assurance component, SESIP level, CC EAL). AI only suggests ratings;
every number after that comes from fixed rules, and every step needs a named expert.

## 2. Rules (v1)

**Impact.** Four axes (Safety, Financial, Operational, Privacy), each Negligible / Moderate / Major / Severe or not
applicable. Overall impact is the highest axis.

**Attack feasibility.** The five ISO/SAE 21434 §15.5 factors, scored with the Common Criteria CEM:2022 R1 Table B.2 points
(elapsed time 0 to 19 in ten steps, expertise 0/3/6/8, knowledge 0/3/7/11, window of opportunity 0/1/4/10, equipment
0/4/7/9). Total 0 to 13 is High feasibility, 14 to 19 Medium, 20 and above Low (a higher total means a harder attack). The
expert can also give the feasibility level directly.

**Risk matrix (overall impact × feasibility).**

| Impact \ Feasibility | Low | Medium | High |
|---|---|---|---|
| Negligible | Low | Low | Low |
| Moderate | Medium | Medium | Medium |
| Major | Medium | High | High |
| Severe | Medium | High | High |

**Ranking.** Per asset, High risk first, then impact, then feasibility, then `tid` (stable order). The expert's adjusted risk,
if any, is used.

**Treatment and residual risk.**

| Decision | Meaning | Next |
|---|---|---|
| Reduce | add a control | goes to Team 3 as a security requirement; expert states the residual risk and why it remains |
| Share | transfer (supplier, insurance) | recorded with the residual risk |
| Retain | accept | residual risk must equal the current risk; written rationale and approver |
| Avoid | remove the cause | the asset or use case changes upstream |

**Attack resistance (Compliance mapping).** Applies to threats treated with Reduce (option to include all).

| Rule | Condition | Attacker class to resist |
|---|---|---|
| CR-1 | effective risk High | Moderate |
| CR-2 | effective risk Medium | Enhanced-Basic |
| CR-3 | effective risk Low | Basic |
| CR-4 | attack feasibility Low | at least Moderate (the attack already needs a skilled, equipped attacker) |

| Class | JIL attack potential | Assurance component (CEM Table B.3) | SESIP | CC EAL |
|---|---|---|---|---|
| Basic | Enhanced-Basic | AVA_VAN.2 | SESIP 1 | EAL2 |
| Enhanced-Basic | Moderate | AVA_VAN.3 | SESIP 2 | EAL2+ |
| Moderate | High | AVA_VAN.4 | SESIP 3 | EAL4+ |
| High | Beyond High | AVA_VAN.5 | SESIP 4 | EAL5+ |

The expert can override the class (reason mandatory), for example a High-risk threat that is reachable only from Bluetooth range.

## 3. Human in the loop

| Step | The expert can | Recorded in the audit log |
|---|---|---|
| Ratings | accept, edit, reject with a reason (new suggestion; after 3 rejections the agent stops and the expert enters the ratings), skip | `risk_reject`, `risk_edit` |
| Risk | accept or adjust with a mandatory reason | `risk_adjust` |
| Treatment | choose, give the rationale and residual risk | `risk_approve` (with approver) |
| Resistance | confirm, override with a reason, reject with a reason | `compliance_confirm`, `compliance_override`, `compliance_reject` |

Nothing reaches the shared state without a named approver. If an approved threat is retired or regenerated, its risk is flagged
stale; if a risk, its feasibility or its treatment changes, the resistance record is flagged stale.

## 4. Data model

`RiskAssessment` (key `tid`): `risk_id`, `project_id`, `use_case_id`, `asset_id`, `impact`, `overall_impact`,
`feasibility_factors`, `feasibility_points`, `attack_feasibility`, `risk`, `justification`, `adjusted_risk`,
`adjustment_reason`, `effective_risk`, `rank_in_asset`, `treatment`, `treatment_rationale`, `residual_risk`, `residual_basis`,
`ai_suggested`, `suggestion_basis`, `status`, `approved_by`, `rejections_before_approval`, `threat_fingerprint`,
`ratings_version`.
`ComplianceRecord` (key `tid`): `compliance_id`, links, `effective_risk`, `suggested_attacker_class`, `attacker_class`,
`required_resistance`, `jil_attack_potential`, `assurance_component`, `sesip_level`, `cc_eal`, `rule_id`, `overridden`,
`override_reason`, `justification`, `status`, `confirmed_by`, `rules_version`.

## 5. Outputs and interfaces

* **TARA report** per asset (Markdown, CSV, JSON): `python scripts/tara_report.py` or `GET /api/v1/risk-agent/report?format=markdown|csv|json`.
  Lists ranked threats with risk, treatment, residual risk, resistance, the threats that need requirements, residual risk, and
  approved threats not yet scored.
* **Command line:** `scripts/risk_demo.py`, `scripts/compliance_demo.py`.
* **API:** `/api/v1/risk-agent/{ratings,suggest,score,approve,reject,assessments,report,staleness,retire-stale}` and
  `/api/v1/compliance-agent/{rules,propose,confirm,reject,records,staleness,retire-stale}`. Writes need the `X-API-Key` header.
* **Diagrams:** `docs/diagrams/agent_architecture.svg`, `docs/diagrams/security_flow.svg`.

## 6. Limits to state in a demo

* Suggestions: the live model produced real suggestions in a trial (2 of 6 before the API credit ran out); the rule-based
  fallback gives the same feasibility to every threat, so the expert's review matters. Suggestion quality has not been evaluated.
* Residual risk is the expert's judgement; there is no control-effectiveness model.
* Without `TRC_USERS_FILE` the approver is a typed name, marked unverified. See `docs/Operations_Guide.md`.
* Each threat rests on one catalogue pattern. Multi-step chains are rule-based proposals for an expert, not approved results.
