# Phase 2 demo runbook: Risk Agent and attack-resistance mapping

Same shared example as Phase 1 (connected smart door lock, `docs/shared_example/`). Three commands, one shared file
(`demo_output/SCRS_demo.json`). The database container must be running: `docker start trc-postgres`.

## A. Command line (about 8 minutes)

```bash
python scripts/scrp_demo.py --project 3 --use-case UC-01 --fresh
```
Phase 1: review and approve threats (as in the earlier demo).

```bash
python scripts/risk_demo.py --use-case UC-01 --input projects/smart_door_lock_multi_use_case.json
```
For each approved threat you see the suggested ratings, the computed risk and **why** (justification). Choose:

| Key | What happens |
|---|---|
| `a` accept | the computed risk stands |
| `e` edit | you enter impact per axis (n/m/j/s or `-`) and the five feasibility factors (numbers) |
| `r` reject | you give a reason; a new suggestion is produced; after 3 rejections you must enter the ratings |
| `s` skip | left for later |

Then the per-asset ranking appears, and for each threat you decide the treatment: **Reduce / Share / Retain / Avoid**,
the rationale, the residual risk, and optionally **change the computed risk** (reason mandatory). Result: threats to
Reduce go to Team 3 as requirements; the others are listed as residual risk.

```bash
python scripts/compliance_demo.py
```
For every Reduce threat you see the proposed attacker class and the required JIL attack potential, SESIP level and CC EAL.
`c` confirm, `o` override the class (reason mandatory), `r` reject with a reason, `s` skip.

Rehearsal without questions: add `--auto --approver "Dr. Gaikwad"` to the second and third command.

## B. What to say about the human in the loop

* The AI (or a rule) only **proposes ratings**. The risk, the ranking and the resistance table are computed by fixed rules.
* The expert can accept, edit, reject with a reason, adjust the risk, and confirm or override the resistance. Every one of
  these is written to the audit log with the person's name and the reason.
* Nothing is stored in the shared state without a named approver. Re-opening the run shows what was decided and by whom.
* If the upstream threat changes, the risk and the resistance record built on it are flagged stale and redone.

## C. API (with the server running: `uvicorn main:app`)

Read-only: `GET /api/v1/risk-agent/ratings`, `GET /api/v1/compliance-agent/rules`, `POST /api/v1/risk-agent/suggest`,
`POST /api/v1/risk-agent/score`, `GET /api/v1/risk-agent/assessments`, `POST /api/v1/compliance-agent/propose`.
Need the `X-API-Key` header: `POST /risk-agent/approve`, `/risk-agent/reject`, `/risk-agent/retire-stale`,
`POST /compliance-agent/confirm`, `/compliance-agent/reject`, `/compliance-agent/retire-stale`.

Request bodies: `docs/api_demo/risk_approve.json`, `risk_reject.json`, `compliance_confirm.json`.

## D. Report and diagrams

```bash
python scripts/tara_report.py --use-case UC-01
```
Writes `demo_output/tara_report_UC-01.md` (also `.csv`, `.json`): per asset, ranked threats with risk, treatment, residual risk and
required resistance, the threats that need security requirements, the residual risk, and any approved threat not yet scored.
API: `GET /api/v1/risk-agent/report?use_case_id=UC-01&format=markdown`.

Diagrams for the meeting: `docs/diagrams/agent_architecture.svg` (who produces what and where people decide) and
`docs/diagrams/security_flow.svg` (security objectives to security requirements, with the change loop).

## E. Limits to state in the demo

1. Without a live model key the rule-based suggestion gives every threat the same feasibility, so the expert's edits matter.
2. Residual risk is the expert's judgement; there is no control-effectiveness model.
3. The command line records a typed name, marked unverified. Verified names come from API users (`docs/Operations_Guide.md`).
4. Each threat rests on one catalogue pattern; multi-step chains are proposals for an expert.
