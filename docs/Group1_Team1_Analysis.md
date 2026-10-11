# Analysis of Team 1's repository (`ai-threat-modelling-main.zip`)

*Reviewed read-only from the zip; nothing of theirs was run, only their Pydantic schema files were
imported in an isolated process to test them. Their own documents are dated up to 22 Aug 2026.*

## 1. The headline finding

**The zip does not contain the three finished agents.** It contains Team 1's *infrastructure*
(Phases 1-4 of their ten-phase plan). The agent folder is empty and all three agents are placeholders:

| Component | What is in the zip | Evidence |
|---|---|---|
| Use-Case Agent | **Not built** (placeholder) | `app/agents/__init__.py` is 0 bytes; `orchestrator.py` calls `_stub_usecase_output()` |
| Modelling Agent | **Not built** (placeholder) | `_stub_modelling_output()` returns a one-line fake diagram |
| Asset Agent | **Not built** (placeholder) | `_stub_asset_output()` returns one fake asset `AS-STUB` |
| Knowledge base layer | **Not built** | `app/knowledge_base/` is empty; their review calls it "absent" (S-02) |
| API routes | **Not built** | `app/api/` empty; `main.py` only has health endpoints, routers are commented out |
| Their status text | | README: "Phase 5 in progress"; `PROJECT_CONTEXT.md`: "Phase 5 — Not started" |

So the claim "all three agents are done" is **not supported by this zip**. Either there is a newer
branch (their notes mention `feature/usecase-agent`) or the agents are still to come. Ask Team 1 for
the latest branch before relying on any of it.

## 2. What is actually built (and built well)

| Area | What it does | Quality notes |
|---|---|---|
| **Orchestrator** (`orchestrator.py`, 853 lines) | Controls the pipeline for one session: gate -> run agent -> human approve/reject. Claim/produce/persist transaction model with a row lock | Careful design: no DB lock during the slow LLM call; failed runs are recoverable; concurrent callers are blocked |
| **State machine** (`state.py`) | `PipelineStep` 0-18 for all three teams; per-agent state; gates (`can_run_*`) | Clear; but see numbering warning in section 5 |
| **Database** (`models.py`, Alembic `0001`) | 11 tables: sessions, use-case / diagram / asset artefacts (Team 1), **threat / risk / compliance artefacts (Team 2, ours)**, requirement / trace / consistency (Team 3), audit log | Shared `ArtefactMixin`: version, `parent_version_id`, diff, approval + rejection columns, confidence, JSONB payload, indexes, UTC times |
| **Audit log** | Hash-chained (SHA-256, per session) **plus a database trigger rejecting UPDATE/DELETE**; `verify_audit_chain()` | Stronger than our JSON audit file |
| **Versioning** | Re-run after rejection = version N+1 with a stored diff; approved content never overwritten | Matches company "non-overwrite" rule |
| **LLM boundary** (`llm_client.py`) | One entry point; redaction before the call; timeouts; retries; JSON recovery with one repair round-trip; audit metadata (prompt SHA-256 + preview, not full prompt) | Providers: **Ollama and Azure OpenAI only** |
| **Privacy** (`privacy.py`) | Secrets (keys, JWT, bearer, private keys, connection strings, `password=`) + PII (email, phone, card, Aadhaar) | Deliberately does **not** mask IP addresses or protocol versions |
| **Security** (`security.py`) | JWT, roles (analyst / expert reviewer / admin / read-only), `Principal` | Written but **not enforced anywhere yet** (no endpoints, `AUTH_ENABLED=false`) |
| **Schemas** | `UseCaseRecord`, `DiagramSet` (entities, flows, trust boundaries), `AssetTable` | Thoughtful (see 4) |
| **Tests / CI** | `test_phase1-4.py` (5 + 8 + 7 + 12 checks), GitHub Actions with Postgres + Redis | CI runs only phases 3-4 (no model runner); tests use the dev database |
| **Docker** | Postgres (`pgvector/pgvector:pg16`, container `threat_postgres`, port 5432, DB `threat_modelling`), Redis, multi-stage Dockerfile | Same Postgres image as ours |

## 3. Problems and risks found in their code

1. **Contracts are never enforced.** No application code calls `model_validate` on agent output;
   artefacts are stored as raw dicts. Proof: their own placeholder asset output **fails their own
   `AssetTable` schema** (missing the required `source`; it uses `source_entity`/`source_diagram`),
   and the placeholder use-case output fails `UseCaseRecord` (missing `product_description`, `actor`
   is a stub...). When real agents arrive, nothing guarantees they match the schema unless validation is added.
2. **Authentication is not enforced.** `approve_step(approved_by="any string")`: the human checkpoint
   is unverifiable today (their own finding R-13).
3. **LangGraph is pinned but never used** (open decision R-28); SRS and code disagree.
4. **The 4 diagrams cannot be produced yet** and the DFD reference has inconsistencies (F8 labelled
   twice, P3 drawn twice) that Team 1 still has to confirm with their lead.
5. **Planned renumbering of `PipelineStep`.** Today Team 2 = steps 7-12. Their context file plans to
   renumber (Team 1 = 0-9, Team 2 = 10-19, Team 3 = 20-29). Anything of ours that hard-codes 7/8 will break.
6. **Python pinned to 3.11 (not 3.12+)**; ours runs on 3.13/3.14 locally. `fastapi`, `pydantic`
   pins nearly match ours; but they use SQLAlchemy + `psycopg2`, we use `psycopg` 3.
7. **Local dev model is Llama 3 through Ollama**; structured-JSON reliability of a small local model is
   a risk for Phases 5-7 (they know it and added JSON repair).
8. **No evaluation harness yet** for their ">90% asset coverage" KPI (their S-08).

None of these is a flaw in what exists: the infrastructure is solid. The risk is that the *agents on
top of it are still to be written*.

## 4. The hand-off contract to us: `AssetTable`

Producer: Asset Agent. Consumer: **our Threat Agent**, via `crud.get_latest_asset_for_session(db, session_id)`
(returns the newest **approved** asset artefact).

`AssetTable`: `session_id`, `usecase_id`, `diagram_version`, `assets[]`, confidence, versioning, approval.

`SecurityAsset`: `id` (AS-n), `name`, `location`, `description`, `attributes` (C / I / A / Auth),
`damage_scenarios[]` (violated attribute, scenario text, severity Negligible/Moderate/Major/Severe,
impact categories Safety/Financial/Operational/Privacy), **mandatory `kb_citation`** (CAPEC / ATT&CK /
ISO-21434 / STRIDE), `source` (entity / flow / usecase / knowledge_base, with element id and rationale),
`confidence`, `needs_review`, `ai_rationale`.

### 4.1 Mapping to our `ThreatAgentInput`

| Our field | Source in Team 1's data | Status |
|---|---|---|
| `run_id` | `session_id` (+ version) | OK |
| `use_case_id` | `AssetTable.usecase_id` | OK |
| `use_case` (text) | `UseCaseRecord` title + product description + flows (the approved use-case artefact) | OK, needs a second lookup |
| `system_model` (text) | `DiagramSet` summary (entities, flows, boundaries) | OK, needs a third lookup |
| asset `asset_id`, `name`, `location` | `id`, `name`, `location` | direct |
| `security_attributes` | `attributes` C/I/A/Auth -> four booleans | direct |
| `damage_scenario` | `damage_scenarios[]` joined | direct |
| `asset_type` | not present | derive from `source.kind` + element type (process / store / flow), else "unspecified" |
| `dfd_context.trust_zone` | not on the asset | **derivable**: `source.element_id` -> `DiagramSet.entities[].trust_boundary` -> `trust_boundaries[].name` |
| `dfd_context.interfaces` | not on the asset | **derivable** from `DiagramSet.data_flows` touching that element (protocol) |
| `dfd_context.data_flows` | not on the asset | **derivable** from the same flows (names / payload fields) |
| `device_config` | not on the asset | **partly derivable**: flow `security_controls`, store `sensitivity` |

**Important consequence:** the four fields we asked Team 1 for do **not** need to be added to their
asset table. They can be built from the `DiagramSet` they already model, **but only when
`source.element_id` points to a diagram element**. Assets with `source.kind = usecase` or
`knowledge_base` (the SRS example's AS-4 audit log and AS-5 user PII are exactly like this, per their
own review S-12) have no diagram element, so those assets will reach us with weak context and search
quality will drop for them. We need fallbacks (use the location text and the use-case text) and should
mark such assets "low context".

Also useful for Phase 2: their `damage_scenarios[].impact_categories` and `severity` map directly onto
the Risk Agent's S/F/O/P impact axes. Note their scale has **Major**, while the company's §2.6 examples only
print Negligible / Moderate / Severe (their own docs flag this).

## 5. How our Threat Agent plugs into their pipeline

What their design already provides for us: the tables `threat_artefacts` (and risk / compliance) with the
same version/approval/audit spine, the gate concept, the hand-off function, an audit chain, auth roles.

What is missing and must be added (by Team 2 = us, in agreement with Team 1, who do the final integration):

| # | Work | Why |
|---|---|---|
| 1 | CRUD for `ThreatArtefact` (create / get_current / approve / reject / version): **only usecase / diagram / asset exist** | no functions exist for Team 2 tables |
| 2 | Orchestrator step `"threat"`: `_StepConfig`, state fields (`threat_state`, `threat_content`), gate `can_run_threat_agent()` (needs `ASSET_DONE` + approved asset), `PipelineStep` name-based references (not numbers) | gate and step do not exist |
| 3 | An adapter `AssetTable (+UseCaseRecord, DiagramSet) -> ThreatAgentInput` (table in 4.1) | different shapes |
| 4 | LLM calls through **their** `call_llm_for_json_with_meta`, or add an OpenAI-compatible provider (OpenRouter / Groq) to their client: today it supports only Ollama and Azure, and their design rule 1 forbids agents calling vendor SDKs directly | our generator currently uses its own OpenAI-SDK client |
| 5 | Record **who** approved/rejected: our audit log has no actor field; theirs does (authenticated `Principal`) | CRA accountability |
| 6 | Replace our JSON "SCRS" file by their `threat_artefacts` + hash-chained `audit_log` | one source of truth; tamper-evidence |
| 7 | Redaction alignment: we mask IP addresses; they deliberately do not (IPs are architecture facts a threat model needs) | agree one policy, else we blur useful facts |
| 8 | Share our knowledge base with them: their Asset Agent needs a `kb_citation` for every asset and their knowledge-base layer (S-02) is empty | we already have 2,300 patterns + pgvector search |
| 9 | Merge the databases/environments: separate stacks today (`threat_postgres:5432/threat_modelling` vs ours `trc-postgres:5433`), SQLAlchemy+Alembic vs raw psycopg3, dependency pins | one stack for integration |

**Numbering warning:** reference steps by name (`PipelineStep.THREAT_PENDING`), never by number: the
numbers are planned to change.

## 6. Where we are ahead / behind

| | Team 1 (infrastructure) | Us (Threat Agent) |
|---|---|---|
| Working agents | 0 of 3 (placeholders) | 1 of 1 (Threat Agent end to end) |
| Knowledge base | empty | 2,300 patterns + 5,097 standards chunks, benchmarked |
| Audit integrity | hash chain + DB trigger | JSON file, not tamper-evident, no actor |
| Auth / roles | written, not enforced | static API key |
| Versioning + diff | in DB, tested | revision history in JSON |
| Concurrency | row locks, tested | atomic status changes in the run store |
| Schema enforcement | defined, not enforced | enforced by Pydantic at every boundary |
| Redaction | broader secret/PII set | masks IPs, fewer secret types (our secret masking was extended) |

## 7. Questions to raise with Team 1

1. Is there a newer branch with the Use-Case / Modelling / Asset agents? The zip stops at "Phase 5 not started".
2. When will `AssetTable` + `DiagramSet` samples (even hand-written, e.g. the SRS door-lock six assets) be available so we can test the adapter?
3. Will assets with `source.kind = usecase / knowledge_base` get any context (interfaces, trust zone)?
4. Will `PipelineStep` be renumbered, and when? Can we reference steps by name only?
5. Which LLM will be used in the integrated system, and can the OpenAI-compatible provider be added to `llm_client`?
6. Will they enforce schema validation on agent output (their placeholders fail their own schemas)?
7. Do they want our knowledge base as their Phase 6 knowledge-base layer?
8. Who creates the CRUD and orchestrator step for `threat` - us (preferred, in a PR) or them?
9. Authentication: will approvals carry an authenticated principal, and can we log it?
10. One database for the integrated demo: `threat_modelling` on 5432?

## 8. Suggested next steps for us (in order)

1. Ask Team 1 the questions above, especially #1 and #2.
2. Build the **adapter** against a hand-made `AssetTable` + `DiagramSet` for the SRS six assets (we can write it now using their schema files).
3. Add `ThreatArtefact` CRUD and the orchestrator `threat` step in a branch of their repo.
4. Route our LLM calls through their client (or add the provider).
5. Add actor identity to our approvals and migrate the SCRS file to their audit chain.
6. Then start Phase 2 (Risk Agent) on top of the same tables.
