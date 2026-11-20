# Team 2 to Team 3: what you receive and how to use it

From Team 2 (group TY-A9). For Team 3 (requirements, trace and audit, consistency). This is the entry page; it replaces
`docs/handoff_team3/00_START_HERE.md`, which describes an earlier state. Read `docs/Handover_Known_Limits.md` before you rely on
any content, and ask us if anything is unclear.

## 1. What Team 2 delivers

Three agents. The AI proposes, a named person approves, and only approved results move on.

| Agent | Input | Output |
|---|---|---|
| Threat Agent | Team 1's approved asset table, per use case | Approved threats: STRIDE class, attack, cited catalogue pattern, evidence, confidence |
| Risk Agent | Approved threats | Impact, attack feasibility, risk, rank per asset, treatment (reduce, share, retain, avoid), residual risk |
| Compliance Agent | Risks treated with "reduce" | Required attack resistance: JIL attack potential, assurance component, SESIP level, Common Criteria EAL, with the rule that produced it |

Every record carries the approver's name and time, and every decision is in a tamper-evident audit log.

## 2. How you get the data

One folder per use case, in Team 1's and your field names.

```bash
python scripts/export_team1.py --use-case UC-01 --session-id <Team 1 session id> --import-report projects/imported/import_report.json
```

Or over HTTP: `GET /api/v1/scrs/export?use_case_id=UC-01`.

| File | Content |
|---|---|
| `threats.json` | `id` (`T1`...), `scenario`, `asset_ids`, `stride`, `attack_vector`, `references[{source, reference_id}]` |
| `risks.json` | `threat_id`, `impact`, `overall_impact`, `attack_feasibility`, `risk_level`, `treatment`, `treatment_source` |
| `compliance.json` | `threat_id`, `required_resistance`, `jil_attack_potential`, `sesip_level`, `cc_eal` |
| `versions.json` | version of each artefact (asset, threat, risk, compliance, and Team 1's when the import report is given) |
| `audit_trail.json` | `event_type`, `actor`, `artefact_type`, `detail`, `created_at` |
| `export_notes.json` | gaps and retired threat numbers |

Our own detail is in extra fields (`team2_tid`, `confidence`, `justification`, `residual_risk`, `rank_in_asset`,
`assurance_component`, `approved_by`). A reader that does not know them can ignore them. Full description: `docs/Team1_Integration.md`, Part 2.

## 3. Rules you can rely on

* **Threat numbers never change.** `T1`, `T2`... follow the order of first approval. A retired threat keeps its number and is listed in `export_notes.json`, so links you made stay valid.
* **Versions rise only when the artefact really changed.** Compare them with the versions you used, to find stale results.
* **Only approved results are exported.** Anything unapproved or stale is left out and listed in the notes.
* **Gaps are stated, not hidden.** A threat with no risk yet, or a "reduce" decision with no resistance level, is listed under problems.
* **Field names will not change without notice.** If we have to change one, we tell you before we do it.

## 4. Checked against your kit

Team 1's `handover/team3_starter/contract/check_contract.py` has been run with our exported files in place of its fixtures, for each of
the three smart-door-lock use cases of a live Team 1 session. It reported CONTRACT PASSED for all three, and its stub agents derived one
requirement per "reduce" threat (5, 4 and 4). The kit has no option to point at other files: copy the kit, put our files in
`fixtures/csdl100/` under the same names (our `audit_trail.json` as `audit_trail_sample.json`), and run it from the copy.

This proves the shape of the data. It does not prove the quality of any threat, risk or requirement; the kit's agents are stubs.

## 5. What you will see in the sample data

* **Demo data.** The sample three-use-case export comes from a run in which the asset ratings were entered by an AI reviewer following the project's example answers, the risk and compliance decisions were scripted, and Team 1's approvals are recorded as unverified. No security expert reviewed it.
* **Assets with no approved threat.** In that run 6, 4 and 2 assets (UC-01, UC-02, UC-03) have no approved threat, because cards were discarded. Your orphan check will list them. The TARA report has an "Asset coverage" table that says, for each asset, why there is none (`scripts/tara_report.py --use-case UC-01 --input <project file>`).
* **Impact is nearly uniform** (operational impact "Major" on most threats), so risk is mostly High or Medium.

## 6. Running it yourself

```bash
docker compose up -d
python scripts/scrp_demo.py --input projects/smart_door_lock_multi_use_case.json --use-case all --mode live
python scripts/risk_demo.py --input projects/smart_door_lock_multi_use_case.json
python scripts/compliance_demo.py --input projects/smart_door_lock_multi_use_case.json
python scripts/tara_report.py --use-case UC-01
```

The risk and compliance scripts ask for an approver's name and for each decision. Do not use `--auto` or `--fresh` between use cases: both delete the demo state. Setup of a new machine and of a local model:
`docs/Move_Laptop_and_Ollama.md` and `docs/Ollama_Setup_and_Test.md`. Users, roles and the audit check: `docs/Operations_Guide.md`.

## 7. Still open

* How our results are stored in Team 1's database, and how an approval made in our tool is recorded there, depends on Team 1.
* A real expert review of the threats and ratings has not been done.
* A real expert review of the threats and ratings: `scripts/review_sheet.py` produces the review workbook and counts the answers (see `docs/Handover_Known_Limits.md`, section 6).
* The SESIP levels are not verified against the SESIP methodology (see the limits, section 5).
