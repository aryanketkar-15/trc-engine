# Phase 2 · Risk Agent: design (draft for review)

Status: **first version built, 29 Oct 2026** (see section 11). Written as a proposal on 22 Oct 2026. It extends the earlier proposal in
`docs/handoff_team3/04_COMING_Risk_and_Compliance.md` with what the Infineon review (12 Oct) asked for:
**rank threats per asset, record a treatment decision, and keep residual risk.**

## 1. What the Risk Agent does (one sentence)

For every **approved** threat from the Threat Agent, it works out **how bad** it would be (impact), **how easy** it is
to carry out (attack feasibility), the resulting **risk**, and records the **human decision** on what to do about it
(treatment) and what risk **remains** afterwards (residual risk).

Where it sits: `Use case → Asset → Threat → Risk → (Compliance) → Requirement`. The key to the Threat Agent is `tid`.

## 2. Inputs

| Input | From | Note |
|---|---|---|
| Approved `ThreatScenario` list | SCRS `threat_scenarios` | Only status = approved; carries `project_id`, `use_case_id`, `asset_id`, `tid` |
| Asset facts and yes/no security properties | Team 1 / our input file | Used to suggest which impact axes apply |
| Use case + system model text | Team 1 / our input file | Context for the AI suggestions |
| Rating tables (impact scale, feasibility factors, risk matrix) | Company | **Still open** (see section 7) |

## 3. The calculation: rules, not AI

The company document (section 2.6, ISO/SAE 21434 §15.5/15.6) defines the method. AI only **suggests the ratings**;
the numbers that follow are computed by fixed rules, so the same ratings always give the same risk.

1. **Impact** on four axes: Safety, Financial, Operational, Privacy. Each is Negligible, Moderate, Major or Severe,
   or "-" when the axis does not apply.
2. **Overall impact** = the highest of the four axes. (Matches the company's rows T1, T2, T3 and T6. **It does not match T4 and T5**: both list a Severe axis but give overall impact Moderate. We could not find a rule that fits all six rows, so this is a question for the company; the aggregation rule is a setting in the ratings file.)
3. **Attack feasibility** from five factors: elapsed time, expertise, knowledge of the item, window of opportunity,
   equipment. Combined into Low, Medium or High by a points table (**table needed from the company**).
4. **Risk** (Low, Medium, High) from a matrix of overall impact × feasibility.
5. **Treatment**: Reduce, Share, Retain or Avoid, with a written rationale. **Always a human decision.**
6. **Residual risk**: the risk left after the treatment (see section 5).

### What the company's six rows already tell us about the matrix

| Overall impact | Feasibility | Risk | Source rows |
|---|---|---|---|
| Severe | Medium | High | T1, T2, T3 |
| Moderate | Low | Medium | T4 |
| Moderate | High | Medium | T5 |
| Severe | Low | Medium | T6 |

The matrix has 4 × 3 = 12 cells. **4 are given by the company** (above). **2 are forced** by monotonicity (Moderate × Medium must be Medium because Moderate × Low and Moderate × High are both Medium; Severe × High must be High because Severe × Medium is High). **6 are our own provisional choice** (all Negligible cells = Low; Major × Low = Medium; Major × Medium and Major × High = High).
Every cell in the ratings file carries its source (`company`, `derived`, `provisional`), every assessment records which kind of cell produced its risk (`risk_basis`), and the CLI/API say so. We chose to label provisional values clearly instead of refusing to score, so the tool stays usable; the company's table replaces them. The six rows are the acceptance test.

## 4. Ranking per asset (company request)

* Threats are grouped **per asset** and sorted by risk (High first), then overall impact, then feasibility.
* Output has a rank number per asset, so "the severe ones for AS-1" is a direct query.
* Ties keep a stable order (by `tid`) so repeated runs do not reshuffle.

## 5. Treatment and residual risk

| Decision | Meaning | What happens next |
|---|---|---|
| **Reduce** (mitigate) | Add a control | Goes to Team 3 → a security requirement is derived. Expert states the **expected residual risk** after the control |
| **Share** | Transfer (insurance, supplier, contract) | No requirement by default; recorded with the party it moves to; residual risk recorded |
| **Retain** (accept) | Live with it | Residual risk = current risk; needs a written rationale and the approver's name |
| **Avoid** | Remove the cause (drop the feature) | Flags the asset or use case for change; threat becomes inactive when the input is updated |

Residual risk is entered by the expert (Low, Medium, High) with a reason. We do not compute it from a control
effectiveness table because no such table exists yet; we say so in the output (`residual_basis: "expert judgement"`).
A Reduce decision whose requirement is later verified can lower the residual risk (Phase 3, Requirements agent).

## 6. Data model (proposed)

One `RiskAssessment` per approved threat. IDs and the stamps of the threat are carried so that staleness works the same way.

```json
{
  "risk_id": "RISK-THR-CSDL-100-UC-01-AS-1-001",
  "tid": "THR-...-001",
  "project_id": "CSDL-100",
  "use_case_id": "UC-01",
  "asset_id": "AS-1",
  "impact": {"safety": null, "financial": "Moderate", "operational": "Severe", "privacy": "Moderate"},
  "overall_impact": "Severe",
  "feasibility_factors": {"elapsed_time": "...", "expertise": "...", "knowledge": "...", "window": "...", "equipment": "..."},
  "attack_feasibility": "Medium",
  "risk": "High",
  "rank_in_asset": 1,
  "treatment": "Reduce",
  "treatment_rationale": "...",
  "residual_risk": "Low",
  "residual_basis": "expert judgement",
  "ai_suggested": true,
  "status": "approved",
  "approved_by": "<name>",
  "threat_fingerprint": "<asset/context fingerprint of the threat at scoring time>",
  "ratings_version": "placeholder-v0"
}
```

Lifecycle is the same as threats: AI suggests ratings → rule engine computes → **human gate** (approve, edit, reject
with reason) → written to SCRS (approved only) → audit log entry with the approver's name.

## 7. Open questions for the company (needed before the numbers are final)

1. The five feasibility factors: the point value of each level and the thresholds for Low, Medium, High.
2. The full impact × feasibility risk matrix (they gave 4 of 12 cells; 6 are provisional, section 3).
3. How overall impact is formed: the company's T4 and T5 rows show Moderate although one axis is Severe. Which rule did they use?
3b. Meaning of the impact levels per axis (e.g. what is "Severe" Financial in euros, or Safety in harm terms)?
4. Do they want a numeric risk value or only Low, Medium, High?
5. Is residual risk to be rated on the same matrix, and by whom?
6. Is Share expected to produce a requirement (e.g. on a supplier)?

## 8. Build plan

| Step | Work | Needs |
|---|---|---|
| 1 | Schemas + rule engine with a **placeholder** rating file, labelled `ratings_version` in every output | nothing external |
| 2 | Acceptance test on the company's six rows (four matrix cells) | nothing external |
| 3 | AI suggestion of impact and feasibility factors, using the same safety rules as the Threat Agent (redaction, grounding on the threat text) | step 1 |
| 4 | Human gate in the CLI (approve, edit, reject) and API endpoints under `/api/v1/risk-agent/*` | steps 1-3 |
| 5 | Treatment and residual risk entry; per-asset ranking view | step 4 |
| 6 | Staleness: threat changed or retired → its risk record is flagged and re-scored | existing staleness code |
| 7 | Swap placeholder tables for the company's | company answers |

Steps 1-2 can start at once and are testable without the company.

## 9. Not in scope / honest limits

* Likelihood is **attack feasibility**, not a probability; we do not claim statistical likelihood.
* AI suggestions of impact are proposals; the expert is the quality gate, as with threats.
* No control-effectiveness model, so residual risk is a judgement.
* Compliance mapping (JIL, SESIP, EAL) is a later phase and must be a rule base.

## 10. Decisions we need from our team and Team 3

* Confirm the `RiskAssessment` fields (section 6), especially `rank_in_asset`, `treatment`, `residual_risk`.
* Team 3: do requirements link to `risk_id`, `tid`, or both? (We suggest both.)
* Agree the risk ID format.

## 11. What was built (29 Oct 2026)

| Part | Where |
|---|---|
| Schemas (`RiskInput`, `RiskAssessment`, `TreatmentDecision`) | `agents/risk_agent/schemas.py` |
| Rating tables (placeholder, every cell labelled with its source) | `agents/risk_agent/ratings_placeholder.json` |
| Rule engine (overall impact, feasibility points, matrix, per-asset ranking, treatment, residual risk) | `agents/risk_agent/engine.py` |
| Suggestions: LLM with redaction and a rule-based fallback; always marked `ai_suggested` | `agents/risk_agent/suggester.py` |
| Staleness of risks (threat retired or re-generated) | `agents/risk_agent/staleness.py` |
| API `/api/v1/risk-agent/`: `ratings`, `suggest`, `score`, `approve`*, `assessments`, `staleness`, `retire-stale`* (*needs the API key) | `agents/risk_agent/router.py` |
| SCRS: `risk_assessments` (approved only, with approver) and audit actions `risk_approve`, `risk_stale` | `scrp/` |
| Command line | `python scripts/risk_demo.py` (after `scripts/scrp_demo.py`) |
| Tests (38): six company rows, ranking, treatment rules, suggester fallback, SCRS storage, staleness, all endpoints | `tests/risk_agent/` |

**How it behaves**
* Risk is stored only with a named approver; a Retain must keep the current risk as residual; Reduce and Share must say why risk remains.
* `needs_requirement` lists the Reduce threats for Team 3; `residual` lists everything accepted, shared or avoided.
* If an approved threat is retired or re-generated from changed data, its risk shows up in `/staleness` and can be retired and re-scored.

**Known limits (be honest in the demo)**
* Rating tables are placeholders (section 3); the six company rows are reproduced only by using the company's own overall impact for T4 and T5.
* The rule-based suggestion is deliberately neutral (same feasibility factors for every threat); the LLM suggestion is better but is still a proposal. The expert decides.
* Residual risk is expert judgement; there is no control-effectiveness model.
* The suggestion uses the asset facts only if you pass `--input` (CLI) or `assets` (API).
