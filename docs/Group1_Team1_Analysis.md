# Analysis of Team 1's work (five branch zips)

*Read-only review of: `fix-environment-and-config-hardening`, `feature-phase1-4-hardening`,
`feature-phase5-grounded-elicitation`, `feature-phase6-live-modelling`, `feature-phase7-asset-agent`.
Nothing of theirs was run. Their documents are dated up to 11 Oct 2026.*

## 0. Correction to my earlier review

My first review looked at one earlier zip (`ai-threat-modelling-main`, the Phase 1-4 snapshot). It is
byte-identical to the `fix-environment-and-config-hardening` branch, and it really did have empty agents.
**The Phase 7 branch changes the answer: Team 1 now has all their agents implemented** (Item-Definition,
Use-Case, Modelling, Asset) plus a security knowledge base, an API and tests. You were right.

## 1. How the five zips relate

```
feature/phase1-4-hardening  (R-01..R-32 fixes from their code review)
        └─ fix/environment-and-config-hardening   (= the earlier "main" zip: stricter SECRET_KEY guard, bcrypt pin)
              └─ feature/phase5-grounded-elicitation   Item Definition + Use-Case agents, clarification loop, API
                    └─ feature/phase6-live-modelling    Modelling Agent, structured system model, 4 diagrams
                          └─ feature/phase7-asset-agent    Asset Agent, §2.4 asset table, security KB   <- latest
```

Each branch contains the previous ones, so **the Phase 7 zip is the only one that matters for integration**;
the other four are earlier states. Size of the Phase 7 branch: about 17,900 lines of application code
(9,450 in `app/agents`), about 8,450 lines of tests, about 29,000 words of documentation.

| Branch | What it adds | Their verification |
|---|---|---|
| hardening | Fixes for 32 review findings: reload bugs, versioning, hash-chained audit log + DB trigger, redaction, timeouts, JSONB, indexes, Alembic, CI | phases 1-4: 5/5, 8/8, 7/7, 12/12 |
| envfix | Production guard rejects every documented placeholder `SECRET_KEY` and keys shorter than 32; `bcrypt` pinned | same |
| phase 5 | Item definition split from use case (own table, own gate); `PipelineStep` renumbered into blocks of ten; **grounded elicitation** (the model may only keep what the text supports; gaps become questions); `/api/v1/sessions` endpoints; JWT roles | 22/22; live 25-26/29 (not green) |
| phase 6 | **Modelling Agent**: structured system model (entities, flows with payload/protocol/controls, trust boundaries with membership, store C/I/A ratings, provenance), four Mermaid diagrams drawn by code from the model | 29/29; live 31/31 |
| phase 7 | **Asset Agent** (§2.4 table) and a **security knowledge base** (official, pinned, hashed ATT&CK 19.2 + CAPEC 3.9); citation validation | 43/43; live 50/50 |

## 2. The pipeline they built

```
INITIALISED
 -> item definition (§2.1) -> human approves -> use case (§2.2) -> approves
 -> system model + 4 diagrams (§2.3) -> approves -> asset table (§2.4) -> approves = ASSET_DONE
                                                                        -> Team 2: get_latest_asset_for_session()
```

Design idea that runs through everything (decisions D1-D41 in their `PROJECT_CONTEXT.md`):
**the model only reads language; code decides what is required, missing, a duplicate or a conflict, and
nothing is ever invented.** Anything the input does not support becomes an *open question* put to an
engineer through `/clarify` and `/finalize`, instead of a default. Examples: an asset's C/I/A attribute exists
only if the approved model states a rating or an engineer says it; Authenticity has no default anywhere;
damage scenarios are stored verbatim from an engineer; severity and impact are never guessed.

### Knowledge base (relevant to us)
* Official files, URL + SHA-256 pinned: ATT&CK **19.2** (enterprise + mobile + ICS, 1,317 entries) and CAPEC
  **3.9** (615). A hash mismatch or wrong version stops the import. Licence text stored. No fallback dataset.
* Tables `kb_releases`, `kb_entries`, `kb_relationships` (only relationships the source states).
* Retrieval is **lexical** (Postgres full text + IDF weighting in code), **no embeddings, pgvector not enabled**.
* `KnowledgeBase.validate()` accepts a citation only if the entry exists, is active, is an attack description
  and (for a model choice) was among the retrieved entries; revoked, deprecated, mitigation, invented IDs refused.
* ISO and INTERNAL families are declared with **no data** (licensed ISO clause catalogue needed).

## 3. What the final contract to us looks like (`AssetTable`)

Retrieved with `crud.get_latest_asset_for_session()` (approved only). Per asset: `id` (stable AS-n),
`name`, `location` (may be empty), `attributes` (accepted C/I/A/Auth only) + `attribute_evidence`,
`is_message`, `authenticity_required`, `damage_scenarios` (engineer's words; severity/impact only if stated),
`kb_citations` (validated, with release/URL/how chosen), `kb_candidates`, `source` (model element(s) or
engineer, with paths back into the diagram set), `unresolved` (which facts the reviewer approved without),
`confidence`. Table level: `usecase_id`, `diagram_id`, `diagram_version`, `excluded`, `kb_releases`.

**Important change from the earlier version:** `kb_citation`, `attributes` and `damage_scenarios` are no
longer mandatory. An asset can reach us with **no attributes, no damage scenario and no citation** if nobody
stated them. Our adapter must treat an empty value as "unknown", not as an error.

## 4. Assessment

### Strengths
1. **Engineering discipline.** Claim/produce/persist transactions with row locks, failure containment,
   hash-chained audit log with a DB trigger, versioning with stored diffs, RBAC roles, Alembic migrations,
   CI with a migration round trip.
2. **No invention by design,** enforced in code and tested (soundness fixture vs accuracy fixture kept apart).
3. **Honest measurement.** Accuracy on the SRS six assets: precision 1.00, coverage 0.67 from the model
   alone and 1.00 with an engineer's answers; locations 0.81 mean; they list their own weak spots
   (citation quality, Phase 5 live failures).
4. **Good ground truth for us:** `tests/fixtures/csdl100/` holds the SRS door-lock data (item definition,
   UC-01, assets AS-1..AS-6, DFD) and the SRS threat references (CAPEC-94/125, T1078, T1566, CAPEC-186,
   CAPEC-117, CAPEC-189). The same data our evaluation uses.
5. **Real-world runs:** six products they had not seen, end to end, 0 failures.

### Weaknesses and risks
1. **Nothing is merged.** Their notes say Phases 5-7 are unmerged into `main` and Phase 7 was "uncommitted at
   the time of writing". The latest work exists only as branches/zips.
2. **Phase 5 live tests are not green** (25/29: `out_scope` not extracted, templated actor fill 5/17). They
   record it as unresolved and ask for a decision on the live thresholds or a stronger model.
3. **Model quality and speed.** Everything was verified with **llama3 8B on CPU** (about 60 s per call,
   about 2 min per asset draft, live suite 18.5 min). Their own reading of one run's 36 citations: about 16
   apt, 10 loose, 10 wrong.
4. **LLM client supports only Ollama and Azure** (`Literal["ollama","azure"]`), and their design rule 1
   forbids agents from using vendor SDKs directly. Our OpenAI-compatible access (OpenRouter/Groq) does not fit
   without a new provider.
5. **Lexical retrieval only,** so a concept worded differently from the catalogue is missed (they say so).
6. **Heavy human-in-the-loop load.** Each gate is an interactive question/answer round; unanswered facts stay
   open. Real tables will often contain assets with `unresolved` facts, which weakens our inputs.
7. **Auth is "enforced but not armed":** roles are checked, but `auth_enabled=false`, no user store, and the
   dev principal is ADMIN.
8. **LangGraph still pinned and unused** (decision pending before final integration).
9. **One use case per session;** Python 3.11 only; SQLAlchemy + psycopg2 stack.
10. **The Team 2 hooks do not exist yet:** only the enum values `THREAT_PENDING=10`, `THREAT_DONE=11` and the
    text "unlocks Team 2 - Threat Agent"; `crud.py` has no functions for `threat_artefacts` /
    `risk_artefacts` / `compliance_artefacts`.

## 5. Integration with our Threat Agent

### 5.1 Mapping `AssetTable` (+ `DiagramSet`, `UseCaseRecord`) -> our `ThreatAgentInput`

| Our field | Their source | Notes |
|---|---|---|
| `run_id` | `session_id` + table version | |
| `use_case_id` | `AssetTable.usecase_id` | |
| `use_case` (text) | approved `UseCaseRecord` title/product/actor/flow + item definition | second lookup |
| `system_model` (text) | approved `DiagramSet` summary (entities, flows, boundaries) | third lookup |
| asset `asset_id`, `name`, `location` | `id`, `name`, `location` | location may be `''` |
| `security_attributes` | `attributes` (accepted C/I/A/Auth) -> four booleans | all false = unknown |
| `damage_scenario` | `damage_scenarios[].scenario` joined | may be empty |
| `asset_type` | `source.element_type` (data_store / flow / payload / process / external_entity) or `engineer` | derive |
| `dfd_context.trust_zone` | `source.element_id` -> `DiagramSet.entities[].trust_boundary` -> `trust_boundaries[].name`; for a flow `from_boundary`/`to_boundary` | derivable |
| `dfd_context.interfaces` | flows touching the element: `protocol`; item-definition interfaces | derivable |
| `dfd_context.data_flows` | flow names + `payload_fields` | derivable |
| `device_config` | store `sensitivity` ratings, flow `security_controls`, `authenticity_required`, `is_message` | derivable |

**So the four fields we asked Team 1 for are already in their data, in the `DiagramSet`.** Team 1 does not have
to add them to the asset table; our adapter reads the approved diagram set. Assets named only by an
engineer (`source.kind = engineer`, e.g. the SRS AS-5 user PII) have no diagram element, so they reach us with
location text only; the adapter must mark them "low context".

### 5.2 Their handling of unknowns vs our pipeline
Our rerank uses `implied_stride(attributes)`; with no accepted attributes it returns nothing. The adapter
should fall back to "all six STRIDE types" (or by `is_message`/store) and flag the scenarios as low-evidence.
Our grounding check requires the exposure to share words with the asset vocabulary; the adapter should
include `location` and the diagram element names in that vocabulary.

### 5.3 Work needed (ordered)

| # | Work | Owner |
|---|---|---|
| 1 | Adapter `AssetTable + DiagramSet + UseCaseRecord -> ThreatAgentInput`, tested on their CSDL-100 fixtures | us |
| 2 | `crud` functions for `ThreatArtefact` (create / get_current / approve / reject / version) | us (in their repo, PR) |
| 3 | Orchestrator step `threat`: `_StepConfig`, state fields, gate (needs `ASSET_DONE` + approved asset), reference steps **by name** (numbers were already renumbered once) | us + Team 1 |
| 4 | LLM: add an OpenAI-compatible provider (OpenRouter/Groq) to `llm_client.py`, or route our generator through `call_llm_for_json_with_meta` | us + Team 1 |
| 5 | Record **who** approved/rejected in our flow (authenticated `Principal`); our audit log has no actor | us |
| 6 | Write scenarios to `threat_artefacts` + the hash-chained audit log instead of our JSON "SCRS" | us |
| 7 | Decide ONE knowledge base: theirs (pinned, hashed, validated, lexical) vs ours (embeddings, CWE, STRIDE, standards chunks) or a merge: their `KnowledgeBase.validate()` for citation checks and our embedding search for retrieval | both |
| 8 | Redaction policy: they deliberately do **not** mask IPs/protocol versions, we do; agree one policy | both |
| 9 | One environment for the integrated demo (their Postgres `threat_modelling` on 5432 vs our `trc_engine_fullkb` on 5433; SQLAlchemy+psycopg2 vs psycopg3; Python 3.11) | both |

### 5.4 Knowledge-base comparison

| | Theirs | Ours |
|---|---|---|
| Sources | ATT&CK 19.2 (3 domains), CAPEC 3.9 | CAPEC, ATT&CK (enterprise + ICS), CWE, STRIDE seed, CC/CEM/JIL/CRA text |
| Size | 1,317 + 615 entries (incl. mitigations, tactics, deprecated/revoked) | 2,300 patterns + 5,097 standards chunks |
| Search | Postgres full text + IDF | sentence embeddings (MiniLM, pgvector) + domain-tag rerank |
| Integrity | SHA-256 pinned releases, version checks, licences stored | files downloaded, MITRE notices stored; no hash pinning |
| Citation validation | exists + active + attack description + among retrieved | cited pattern must be among the retrieved ones; existence check for expert adds |
| Relationships | stated CAPEC<->ATT&CK<->CWE links stored | not stored |

They complement each other: ours adds semantic search, CWE and standards text; theirs adds provenance,
pinning, relationship data and stricter validation.

## 6. Questions for Team 1

1. Which branch is the current baseline, and when will phases 5-7 be merged into `main`?
2. Can we get a **sample approved session export** (`AssetTable`, `DiagramSet`, `UseCaseRecord` JSON) for the
   CSDL-100 so we can test the adapter on real artefacts?
3. Agree the adapter approach: we read the `DiagramSet` for trust zone / interfaces / flows. OK?
4. May we add an OpenAI-compatible provider to `llm_client.py`? Which model will the integrated system use?
5. Who writes `ThreatArtefact` CRUD and the orchestrator `threat` step: us, in a PR?
6. Will `auth_enabled` be armed for the integrated demo, so approvals carry a real identity?
7. Shall we share one knowledge base (merge ours into their `kb_*` tables, or use their `validate()`)?
8. Policy on masking IP addresses and protocol versions?
9. How are unresolved asset facts meant to be shown to the Threat Agent (`unresolved` list), and are
   assets with no attributes acceptable inputs?
10. Confirmation of CAPEC-189 vs CAPEC-622 for the SRS T6 row: their fixture also lists CAPEC-189.

## 7. Suggested next steps for us

1. Send the questions above, especially 2, 4 and 5.
2. Build the adapter against the **CSDL-100 fixtures** in their repo (item definition, UC-01, assets, DFD).
3. Evaluate our Threat Agent on the six SRS assets as Team 1 defines them (their IDs and wording).
4. Branch in their repo: `ThreatArtefact` CRUD + `threat` step + provider.
5. Then Phase 2 (Risk Agent) on the same tables; their `impact_categories` / severity fields feed it
   (stated by an engineer only, never defaulted).
