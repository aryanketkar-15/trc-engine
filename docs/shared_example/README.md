# Shared example for all teams: Connected Smart Door Lock (CSDL-100)

**Why this file exists.** In the Infineon review (12 Oct 2026) the company asked that **all teams use the same
example** (the smart door lock) and that one product can have **several use cases**, each with its own
data-flow diagram. This pack fixes the names and IDs so Team 1, Team 2 and Team 3 can exchange data without
translating.

## 1. Files

| File | What it is |
|---|---|
| `smart_door_lock_project.json` | The product: **6 assets (once)** and **4 use cases**, each with its own description, system model and list of assets. This is the format our tools read (a copy lives in `projects/`) |
| `README.md` | This guide: the IDs, the yes/no security properties, the company's reference threats |

## 2. The agreed IDs

### Use cases (UC-01 is the company document's; UC-02 to UC-04 were written by Team 2 as realistic examples)

| ID | Title | Assets involved |
|---|---|---|
| **UC-01** | Remote unlock by homeowner (company document §2.2) | AS-1, AS-2, AS-4, AS-6 |
| UC-02 | Issue a time-bound guest e-key | AS-2, AS-4, AS-5, AS-6 |
| UC-03 | Revoke a lost or stolen e-key | AS-2, AS-4, AS-5 |
| UC-04 | Over-the-air firmware update | AS-3, AS-4, AS-6 |

### Assets (company document §2.4)

| ID | Asset | Location | Confidentiality | Integrity | Availability | Authenticity |
|---|---|---|:-:|:-:|:-:|:-:|
| AS-1 | Unlock command | Cloud↔Lock channel | no | **yes** | **yes** | **yes** |
| AS-2 | E-key credential | Cloud DB, App, Lock | **yes** | **yes** | no | **yes** |
| AS-3 | Firmware image | OTA, Lock flash | no | **yes** | **yes** | **yes** |
| AS-4 | Audit log | Lock, Cloud | no | **yes** | **yes** | no |
| AS-5 | User PII (schedule, address) | Cloud, App | **yes** | no | no | no |
| AS-6 | Cryptographic keys | Secure element | **yes** | **yes** | no | **yes** |

**Security properties are yes/no** ("is this property required for this asset?"), as the company asked, not High/Medium/Low.
The company's own §2.4 table lists C / I / A / Auth the same way; our values above are the ones our demo uses and
may differ in detail from the company's selection. Team 1 should confirm theirs.

### Threats the company document lists for this example (§2.5), for reference

| ID | Asset | Type | Based on |
|---|---|---|---|
| T1 | AS-1 | Spoofing / Tampering | CAPEC-94 (BLE replay, adversary in the middle) |
| T2 | AS-2 | Elevation of privilege | ATT&CK T1078 (valid accounts) |
| T3 | AS-3 | Tampering | CAPEC-186 (malicious software update) |
| T4 | AS-5 | Information disclosure | CAPEC-117 (interception) |
| T5 | AS-1 | Denial of service | CAPEC-125 (flooding) |
| T6 | AS-6 | Tampering / disclosure | cited as CAPEC-189; CAPEC-622 (electromagnetic side-channel) looks closer, **to be confirmed with the company** |

## 3. How each team uses it

| Team | Use |
|---|---|
| **Team 1** | Produce the asset table and one system model **per use case** for these IDs; ratings as yes/no |
| **Team 2 (us)** | `python scripts/scrp_demo.py` → project 3 "Smart Door Lock Multi Use Case" → pick a use case. API: `POST /api/v1/threat-agent/expand-project` returns one ready input per use case |
| **Team 3** | Trace each requirement to `(project_id, use_case_id, asset_id, tid)`. Our threats carry all four |

## 4. Rules so we do not drift apart

1. Keep the IDs above. Add new assets as AS-7 …, new use cases as UC-05 …; never renumber.
2. One run, one result set **per use case** (identified by `project_id` + `use_case_id`).
3. If an asset or a system model changes, bump the asset `version` (or edit the data): our tools detect which approved threats are
   now out of date and offer to re-run only those assets (`POST /staleness`, `POST /retire-stale`, or the CLI prompt).
4. Security properties are always yes/no.
