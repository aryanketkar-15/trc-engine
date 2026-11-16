# Working with Team 1 and Team 3: import and export

Two directions, both through plain files or HTTP, with no shared code:

1. **Import**: Team 1's approved asset tables become our Threat Agent inputs.
2. **Export**: our approved threats, risks and resistance levels go back in the field names Team 1's hand-over kit uses for
   Team 2, which is what Team 3's agents read.

# Part 1: importing Team 1's approved results

Team 1's pipeline (item definition, use case, modelling, asset) ends with an approved **asset table per use case**. The importer
reads those artefacts and builds one Threat Agent input per use case. It only reads: nothing is written to Team 1's system, and
none of their code is imported (they run Python 3.11 with older packages).

## Use it

From an exported file:

```bash
python scripts/import_team1.py --file team1_export.json --out projects/imported
```

Straight from Team 1's API (read-only requests):

```bash
python scripts/import_team1.py --api http://localhost:8000 --session <session-id> --token <bearer-token>
```

It writes, into `--out`: one input file per use case (`<project>_<UC>.json`), one file with all use cases
(`<project>_project.json`) and `import_report.json`. Then run the agents as usual, for example
`python scripts/scrp_demo.py --input projects/imported/CSDL-100_project.json`.

## Rules

* **Approved only.** Every artefact must arrive with its approval status (the API's `artefact` object does). A pending or rejected
  artefact is refused. Bare content is refused too, because it cannot show whether anyone approved it; `--allow-unapproved` exists
  for test data only.
* **Hand-off needs every use case**, as in Team 1's own `handoff_ready`. `--partial` imports the use cases that are ready and lists
  the rest as skipped. A use case Team 1 dropped is skipped without an error.
* **Asset numbers belong to one use case.** `AS-1` in UC-01 and `AS-1` in UC-02 can be different assets, so each use case keeps its
  own list and results stay separate (project id plus use case id).
* **Nothing is invented.** A property Team 1 has not decided is not turned into "No"; it is listed in the report.

## Bundle format (the file)

```json
{
  "session_id": "…",
  "item_definition": {"artefact_id": "…", "version": 1, "approval_status": "approved", "approved_by": "…", "content": {…}},
  "usecases": {
    "UC-01": {"status": "complete", "usecase": {artefact}, "diagrams": {artefact}, "assets": {artefact}}
  }
}
```

Each `{artefact}` is Team 1's artefact object. A real session export is what the API calls return, so a bundle can also be made
by saving those answers.

## What is mapped

| Team 1 | Ours |
|---|---|
| asset `id`, `name`, `location` | `asset_id`, `name`, `location` |
| `security_attributes` (Yes / No / not decided), or the accepted list in older data | `security_attributes` (four booleans) |
| `damage_scenarios` (with a stated severity, if any) | `damage_scenario` |
| the model elements the asset is made of (flow, store, process) | `asset_type`, written in the model's own words, for example "data flow Cloud Backend to Lock Firmware" |
| protocols of the flows around the asset | `dfd_context.interfaces` |
| trust boundaries of those flows (a crossing becomes "Cloud TB to Device TB") | `dfd_context.trust_zone` |
| names of those flows | `dfd_context.data_flows` |
| security controls stated on those flows | `device_config["security_controls"]` |
| validated CAPEC / ATT&CK / CWE citations | `device_config["known_attack_references"]`, used as retrieval hints (only real catalogue IDs) |
| asset table `version` | `version` (a new Team 1 version marks our earlier threats stale) |
| entities, boundaries, flows | `system_model` text |
| use case and item definition | `use_case` text |

`device_config` is part of the retrieval query, so it holds nothing else. Who approved, which artefact version, which model
elements, what is undecided and what the reviewer approved without are in `import_report.json`.

# Part 2: exporting our approved results

```bash
python scripts/export_team1.py --use-case UC-01 --session-id <Team 1 session id> --import-report projects/imported/import_report.json
```

Or over HTTP: `GET /api/v1/scrs/export?use_case_id=UC-01`. One folder per use case:

| File | Content | Field names |
|---|---|---|
| `threats.json` | approved threats | `id` (`T1`...), `scenario`, `asset_ids`, `stride` (letters), `attack_vector`, `references[{source, reference_id}]` |
| `risks.json` | approved risks | `threat_id`, `impact`, `overall_impact`, `attack_feasibility`, `risk_level`, `treatment`, `treatment_source` |
| `compliance.json` | confirmed resistance levels | `threat_id`, `required_resistance`, `jil_attack_potential`, `sesip_level`, `cc_eal` |
| `versions.json` | version of each artefact | `asset`, `threat`, `risk`, `compliance` (plus Team 1's, when the import report is given) |
| `audit_trail.json` | decisions | `event_type` (`human_approval`, `human_rejection`, `artefact_versioned`), `actor`, `artefact_type`, `detail`, `created_at` |
| `export_notes.json` | gaps and retired threat numbers | |

Our own detail travels in extra fields (`team2_tid`, `confidence`, `justification`, `residual_risk`, `rank_in_asset`,
`assurance_component`, `approved_by` and so on); a reader that does not know them can ignore them.

**Decisions built in**

* **Threat numbers never change.** `T1`, `T2`... follow the order in which threats were first approved, read from the audit log.
  A retired threat keeps its number (listed in `export_notes.json`), so links Team 3 has made stay valid.
* **Citations in Team 1's spelling:** `CAPEC-94`, and `T1078.001` with source `ATT&CK`.
* **`risk_level` is the effective risk** (the expert's adjustment if there is one); the computed value is in `computed_risk_level`.
* **Versions** count the changes to that artefact for that use case, so they rise only when it really changed. This is what
  Team 3's stale-artefact check compares.
* **Gaps are stated, not hidden:** a threat with no risk yet, or a Reduce decision with no resistance level, is listed under
  problems.

**Checked against Team 3's kit.** With our exported files in place of its fixtures, Team 1's `contract/check_contract.py` reports
CONTRACT PASSED, and its stub agents derive one requirement per Reduce threat with no orphan.

**Still to agree with Team 1:** who writes the database functions and pipeline steps that store these files on their side, and how
an approval made in our tool is recorded there. Until then the export carries the approver's name and time in every record.

## Limits

* Assets that are not tied to any data flow (for example ones an engineer named) arrive with no interface and no trust zone; the
  report lists them.
* Tested with Team 1's own classes on their worked example and with fake API servers. It has **not** been run against a live
  Team 1 session yet.
* Neither direction has been run against Team 1's live system; storing our export in their database needs their wiring.
* When the project id is `CSDL-100`, `scripts/scrp_demo.py` replays recorded output by default. Add `--mode live` for imported data.
