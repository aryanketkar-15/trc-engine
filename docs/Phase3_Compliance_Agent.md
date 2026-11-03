# Phase 3: Compliance Agent (required attack resistance)

Our build plan runs in series: Threat Agent, then Risk Agent, then Compliance Agent. This is the third agent, and step 6 of the
workflow in the company document. Steps 7 to 9 (requirements, trace and audit, consistency) belong to Team 3.

| Company document asks | How it is met |
|---|---|
| Input: risk and asset criticality | Approved risk, plus criticality from the asset's required security properties |
| Output: required protection level | Per threat, per asset and for the product |
| Rule base for standards mappings | `agents/compliance_agent/rules.json`; no LLM ever decides a value |
| LLM only for reasoning | An optional written rationale, checked before it is kept |
| Citations on every recommendation | Every record cites CEM Table B.3 and JIL Table 14; each rationale lists the text it used |
| Expert confirms | Confirm, override with a reason, or reject with a reason. All are audited with the person's name |
| Audit of AI use | Each record keeps the evidence, match score, model and prompt version |
| Change handling | A mapping goes stale if its risk, feasibility or treatment changes |

## Rules

| Rule | Condition | Attacker class to resist |
|---|---|---|
| CR-1 | effective risk High | Moderate |
| CR-2 | effective risk Medium | Enhanced-Basic |
| CR-3 | effective risk Low | Basic |
| CR-4 | attack feasibility Low | at least Moderate |
| CR-5 | asset criticality High and effective risk Medium | at least Moderate |

Asset criticality: 3 or 4 required properties (confidentiality, integrity, availability, authenticity) is High, 2 is Medium, and
0 or 1 is Low. Without asset facts it is Unknown and CR-5 does not apply.

| Class | JIL attack potential | Assurance component | SESIP | CC EAL |
|---|---|---|---|---|
| Basic | Enhanced-Basic | AVA_VAN.2 | SESIP 1 | EAL2 |
| Enhanced-Basic | Moderate | AVA_VAN.3 | SESIP 2 | EAL2+ |
| Moderate | High | AVA_VAN.4 | SESIP 3 | EAL4+ |
| High | Beyond High | AVA_VAN.5 | SESIP 4 | EAL5+ |

The protection target of an asset or of the product is the strongest class among its confirmed records.

## The LLM rationale

`agents/compliance_agent/explainer.py` retrieves the closest standards text from the knowledge base and asks the model to explain
the decision. The answer is dropped, and the rule-based justification stays, if it:

* names an EAL, SESIP or AVA_VAN level the record does not hold;
* cites text that was not retrieved, or cites nothing;
* is not valid JSON, or the model or knowledge base is unavailable.

These checks cover levels and citations, not meaning. A rationale can still overstate what a standard says, so the expert reads it
before confirming.

## Using it

```bash
python scripts/compliance_demo.py --input projects/smart_door_lock_multi_use_case.json
```

Add `--no-ai` to skip the rationale, or `--auto --approver "Name"` for a scripted rehearsal.

API under `/api/v1/compliance-agent/`: `rules`, `propose` (body: `assets`, `explain`), `confirm`\*, `reject`\*, `records`,
`targets`, `staleness`, `retire-stale`\* (\* needs the API key). The protection targets are also in the TARA report.

## Limits

* The risk-to-class rules and the SESIP and EAL values for the Basic and High classes are the project's own v1. SESIP text is
  not in our knowledge base, so SESIP levels have no citation.
* Criticality only counts required properties; it does not see how valuable an asset is. The expert can override the class.
* The rationale was tried on the hosted `gpt-4o-mini`, not yet on Ollama. See `docs/Move_Laptop_and_Ollama.md`.
