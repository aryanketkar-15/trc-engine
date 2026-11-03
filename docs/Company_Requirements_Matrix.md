# Company document requirements: status for the TRC agents

Scope: Threat, Risk and Compliance agents (workflow steps 4 to 6). Team 1 owns steps 1 to 3; Team 3 owns steps 7 to 9.
Status is what the code does and what tests or a real run showed.

## Workflow steps

| Step | Company asks | Status | Evidence |
|---|---|---|---|
| 4 Threat identification | Threats with rationale and KB references; expert prunes and adds | Done | `agents/threat_agent/`; CLI `scrp_demo.py`; API `threat-agent/*` |
| 5 Risk analysis | Impact S/F/O/P, feasibility from five factors, risk and justification; expert adjusts | Done | `agents/risk_agent/`; `risk_demo.py`; `tests/risk_agent` |
| 5 Treatment | Reduce / Share / Retain / Avoid with rationale | Done | Same; residual risk and per-asset ranking added at the 12 Oct review |
| 6 Attack-resistance mapping | JIL / SESIP / CC EAL by rule base plus LLM, from risk and asset criticality; expert confirms | Done | `agents/compliance_agent/`; `compliance_demo.py` |
| 10 Change impact | Find affected items when inputs change | Our part done | Threats, risks and mappings go stale; only affected assets are redone |

## Cross-cutting requirements (section 3.4)

| Requirement | Status | How |
|---|---|---|
| Traceability: forward and backward links | Done | `GET /scrs/trace`, with a list of gaps |
| Citations on every recommendation | Done | Threats cite a KB item; resistance records cite CEM and JIL; SESIP text is not in our KB |
| Confidence and review flags | Done | Threat confidence, risk `evidence_confidence`, rationale match score; `needs_review` until approved |
| Non-overwrite: proposed diff for human merge | Done | Changing approved content returns a 409 with the diff and needs a reason; `GET /threat-agent/{run}/diff`; old versions go to the history |
| Auditability: prompts, KB chunks, model and template versions, decisions | Done | `logs/llm_audit.jsonl` (redacted); hash-chained audit log with actor; `GET /scrs/audit/verify` |
| Determinism boundary | Done | Mappings come from `rules.json`; a rationale naming another level is dropped |
| Privacy and secrets: redact before LLM | Done | Applied on all three agents |
| Data residency | Ready | Ollama keeps all text on the machine (the remaining setup step) |
| Explainability: rationale and evidence | Done | Justification on every score and mapping |
| Versioning; change-impact on version bump | Done | `state_version`, table versions, real KB fingerprint, all shown in the report |
| Standards alignment | Partly | Fields follow ISO/SAE 21434 §15.5/15.6 terms; ISO text is not in our KB (the company said it is not required) |

## Other company requests (12 Oct review)

| Request | Status |
|---|---|
| Yes/no security properties | Done |
| Several use cases per product | Done |
| STRIDE only | Done |
| Same example for all teams | Done on our side (`docs/shared_example/`) |
| Rank threats per asset; residual risk | Done |
| Attack paths | Done as proposals: `POST /scrs/chains`, in the TARA report |

## Remaining

| Item | Why it remains | Who |
|---|---|---|
| Ollama setup and comparison | Agreed next step; `docs/Move_Laptop_and_Ollama.md` | Friend's laptop |
| Team 1 adapter | Needs a real session export | Team 1 and us |

## Cannot be closed by code

| Item | What is needed |
|---|---|
| Matches 1 of 6 company reference threats | The company's internal threat patterns. Public catalogues do not contain them |
| Checker wrongly accepts 15.38% and rejects 8.33% | Accepted limit: human approval is the safeguard. Re-measure after Ollama |
| No expert has rated real threats | A real expert review of the door-lock threats |
| T4, T5, T1 and T6 differ from our rules | Company answer at the next meeting. Tables are config files |
| SESIP and EAL for the Basic and High classes | Check against the SESIP and CC text |
| Independent security review | "Industry ready" here means the engineering below. No outside party has tested or certified it |

## Known production limits

* The shared state is one JSON file with a lock, so it suits one host. Several hosts would need a database store.
* API keys are per user with roles. There is no single sign-on or key expiry yet.
* The LLM audit file grows without rotation; rotate it with the host's log tools.
