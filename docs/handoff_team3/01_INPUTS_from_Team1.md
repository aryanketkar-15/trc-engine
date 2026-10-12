# 01 · Inputs: what Team 1 gives us

## 1. The hand-off object

Team 1's pipeline ends at **`ASSET_DONE`**: after a human expert approves the asset table, Team 2 reads it with

```python
crud.get_latest_asset_for_session(db, session_id)   # returns the newest APPROVED asset artefact, or nothing
```

The row's `content_json` is an **`AssetTable`**. We also read two earlier approved artefacts of the same session
for context: the **`DiagramSet`** (system model) and the **`UseCaseRecord`** (+ item definition).
*(Source: Team 1's Phase 7 branch, `app/schemas/asset_schema.py`, `diagram_schema.py`, `usecase_schema.py`.
The branch was not merged into their `main` when we reviewed it, so field names may still change.)*

## 2. `AssetTable` (table level)

| Attribute | Meaning |
|---|---|
| `session_id` | The TARA session (one session = one use case today) |
| `usecase_id` | e.g. `UC-01` |
| `diagram_id`, `diagram_version` | The exact approved system model the assets were derived from |
| `assets[]` | The asset rows (below) |
| `excluded[]` | Elements considered and **not** taken as assets, with the reason |
| `kb_releases[]` | Which knowledge-base releases Team 1's citations were validated against |
| `version`, `parent_version_id`, `approval_status`, `approved_by`, `approved_at` | Versioning and approval |

## 3. `SecurityAsset` (one row = SRS §2.4 row)

| Attribute | Type | Meaning | Can be empty? |
|---|---|---|---|
| `id` | string | `AS-1`, `AS-2`, … stable across versions | no |
| `name` | string | What is protected, e.g. "Unlock command" | no |
| `location` | string | Where it is held or travels, e.g. "Cloud↔Lock channel" | **yes** (`""` = not established) |
| `attributes` | list of `C` `I` `A` `Auth` | **Accepted** security properties (stated in the model or confirmed by an engineer) | **yes** (= unknown, not "none") |
| `attribute_evidence[]` | list | Per property: status (stated / engineer / engineer_excluded / kb_recommended), level, basis, quote | yes |
| `is_message` | bool | Asset travels in a data flow (the only kind asked about Authenticity) | no |
| `authenticity_required` | bool or null | For messages; null = unanswered | yes |
| `damage_scenarios[]` | list | Engineer's words; `severity` and `impact_categories` only if the engineer stated them | **yes** |
| `kb_citations[]` | list | Validated CAPEC / ATT&CK entries (id, name, release, URL, how chosen) | **yes** |
| `kb_candidates[]` | list | What retrieval offered | yes |
| `source` | object | Where the asset came from: `kind` (entity, flow, payload, engineer, usecase), `element_id` (e.g. `DS2`, `F5`), `element_type`, paths back into the diagram | no |
| `unresolved[]` | list | Which §2.4 facts the reviewer approved the asset **without** | yes |
| `confidence`, `needs_review`, `ai_rationale` | | Team 1's own metadata | |

**Important:** Team 1's rule is *never invent*. A missing attribute, damage scenario or citation means
"nobody stated it", **not** "it does not apply". We treat empty values as *unknown*.

## 4. How we map it to our input (`ThreatAgentInput`)

Our Threat Agent reads a `ThreatAgentInput` (see `schemas/threat_agent_input.schema.json`, samples in
`samples/input_*.json`). The planned **adapter** fills it like this:

| Our field | Comes from | Notes |
|---|---|---|
| `run_id` | `session_id` + table version | |
| `use_case_id` | `AssetTable.usecase_id` | today we derive `UC-<hash>` from the use-case text when none is given |
| `use_case` | approved `UseCaseRecord` (title, product, actor, flow) | |
| `system_model` | approved `DiagramSet` summary (entities, flows, boundaries) | |
| asset `asset_id` | `SecurityAsset.id` | |
| asset `name`, `location` | `name`, `location` | |
| asset `asset_type` | `source.element_type` (data_store / flow / payload / process / external_entity) or "engineer" | derived |
| asset `security_attributes` (4 booleans) | `attributes` (C/I/A/Auth) | all false = unknown |
| asset `damage_scenario` (text) | `damage_scenarios[].scenario` joined | |
| asset `version` | table version | we carry it as `asset_version` on every threat |
| asset `dfd_context.trust_zone` | `source.element_id` → `DiagramSet` entity → trust boundary name | |
| asset `dfd_context.interfaces` | protocols of the flows touching that element | |
| asset `dfd_context.data_flows` | names / payload fields of those flows | |
| asset `device_config` | store sensitivity ratings, flow security controls, `authenticity_required` | |

Assets named only by an engineer (e.g. "User PII") have no diagram element, so they reach us with little
context; their threats will be less specific and are labelled by the same confidence rule.

## 5. Status of this link

| Item | Status |
|---|---|
| Our agent running on hand-prepared inputs in `ThreatAgentInput` shape | **working** (`samples/input_*.json`) |
| Adapter `AssetTable` + `DiagramSet` + `UseCaseRecord` → `ThreatAgentInput` | designed, **not built** |
| Reading Team 1's database / writing `threat_artefacts` | **not built** (needs the Team 2 step in their orchestrator) |
| A real exported session from Team 1 to test with | **requested**, not received |

`samples/team1_asset_table_example.json` shows what an `AssetTable` for the SRS door lock looks like in Team 1's
format. **It is illustrative: written by us from the SRS example and their published schema, not exported
from their system.**

## 6. Why this matters to Team 3

Everything you receive from us is derived from the approved asset table, so the chain is:
`Use case (UC-n) → Asset (AS-n, version) → Threat (THR-…) → …`. We carry `use_case_id` and `asset_version`
on every threat so you can trace back to Team 1's rows, and detect when an asset changed after a threat was
approved.
