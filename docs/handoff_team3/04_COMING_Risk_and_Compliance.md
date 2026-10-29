# 04 · Risk and Compliance outputs

> **Update 29 Oct 2026:** a first version of the Risk Agent is built (tables are placeholders). Field names and the full design are in `docs/Phase2_Risk_Agent_Design.md` in the repository. This file keeps the original proposal; the built `RiskAssessment` adds `rank_in_asset`, `residual_risk`, `risk_basis` and `approved_by`.

Team 2 owns three agents. Only the **Threat Agent** exists. The next two follow the company document
(Section 2.6 / 2.7, ISO/SAE 21434 §15.5–15.6). **Everything below is a proposal so you can tell us what you need
before we build it.**

## 1. Risk Agent (planned): one record per approved threat

| Attribute | Meaning | Source |
|---|---|---|
| `risk_id` | e.g. `RISK-<tid>` or `RISK-n` (to agree) | us |
| `tid` | the threat assessed (foreign key to the Threat Agent output) | us |
| `impact` | Safety / Financial / Operational / Privacy, each Negligible · Moderate · Major · Severe (or "–" for none) | engineer / AI suggestion, human approved |
| `overall_impact` | the highest of the four axes | computed by rule |
| `feasibility_factors` | elapsed time, expertise, knowledge of the item, window of opportunity, equipment | engineer / AI suggestion |
| `attack_feasibility` | Low / Medium / High (rule-based from the factors) | computed by rule |
| `risk` | Low / Medium / High from a configurable matrix (impact × feasibility) | computed by rule |
| `treatment` | Reduce / Share / Retain / Avoid, with `rationale` | human decision |
| `justification` | short explanation | AI-written, human approved |
| `status`, `validation`, `approved_by` | same lifecycle as threats | us |

The company's six worked rows (T1–T6) will be our acceptance test. We need the company's feasibility tables and
risk matrix to finish this; until then we would use a clearly labelled placeholder.

## 2. Compliance Agent (planned, later)

Maps risk and feasibility to the **required attacker resistance**: JIL attack potential, SESIP level, CC EAL.
By company rule this is a **rule base, not AI inference**. Output would be one record per threat or asset:
`required_resistance`, `jil_attack_potential`, `sesip_level`, `cc_eal`, `rule_id`.

## 3. What this means for Team 3

* The chain becomes `UC → Asset → Threat → Risk → (Compliance) → Requirement`; the key between Threat and Risk is `tid`.
* Your Requirements Agent will need `risk` and `treatment` to decide which threats need a requirement ("Reduce")
  and which are accepted ("Retain").
* **Tell us** which of these attributes you need, which you would rename, and whether you prefer IDs per threat
  or per asset.

## 4. Target timing (rough, depends on the company's tables)

| Step | Estimate |
|---|---|
| Agree attributes with Team 3 | this week |
| Risk engine (rules) + the six-row test | about 2–3 weeks after we get the tables |
| Risk AI suggestions + human gate | +2 weeks |
| Compliance mapping | after Risk |
