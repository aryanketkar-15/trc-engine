# 03 · Using the knowledge base without conflicts

Several teams use security knowledge in the same overall system. These rules keep us from breaking each other's data.

## 1. The golden rules

| # | Rule | Why |
|---|---|---|
| 1 | **Put it in its own database** (for example `trc_kb`), never inside another team's database | Other teams manage their databases with migration tools that do not know about our tables |
| 2 | **Read-only.** Do not edit, delete or add rows in `threat_patterns` / `standards_chunks` | Our Threat Agent and its saved results refer to these exact rows |
| 3 | **Same embedding model for queries: `all-MiniLM-L6-v2`, vectors normalised, 384 numbers** | A different model gives numbers that cannot be compared with ours; no error is raised, results are just wrong |
| 4 | **Do not mix versions.** Use this exact package version, or record which one you used | Counts, vectors and IDs change when the sources are re-downloaded |
| 5 | **Keep the notices** in `legal/` with any copy | MITRE's licence requires it |
| 6 | **Put your own patterns in your own table** (for example `internal_patterns`), not in ours | Keeps ours reproducible and avoids ID clashes |
| 7 | **Cite with the `source` + `pattern_id` pair**, never with our numeric `id` column | The numeric id is not stable between rebuilds |
| 8 | **Do not call heuristic fields facts** (`stride_hint`, `domain_tags`) | They are keyword rules, not MITRE data |

## 2. Names that could clash

| Where | Our names | Their possible names | Clash? |
|---|---|---|---|
| Tables in our database | `threat_patterns`, `standards_chunks` (and `threat_agent_runs` for our API runs) | Team 1's knowledge-base tables are `kb_releases`, `kb_entries`, `kb_relationships` | **No table-name clash**, but keep them in separate databases anyway |
| Database names | `trc_engine_fullkb` (full library), `trc_engine` (small seed set used in tests) | Team 1: `threat_modelling` (migration-managed) | No clash if you create a new DB |
| ID text for ATT&CK | `ATT&CK-T1078` | Team 1: `T1078` with family `ATT&CK` | **Convert when exchanging IDs** |
| Ports (local Docker) | 5433 for ours | Team 1: 5432 | Do not start two Postgres containers on the same port |
| Container names | `trc-postgres` | `threat_postgres`, `threat_redis` | No clash |

## 3. Specific advice

### For Team 1 (Use-Case / Modelling / Asset agents)
* Your knowledge base is **ATT&CK 19.2 + CAPEC 3.9** with keyword search. Ours is **the same releases** (ATT&CK 19.2,
  CAPEC 3.9) plus CWE 4.20 and the standards text, with search by meaning. Counts differ because we keep only
  techniques/sub-techniques and attack patterns that are not deprecated or revoked (no mitigations, no Mobile).
* **If you want to reuse ours for asset citations:** restore into a separate database (Route B in `README_START_HERE.md`),
  query it read-only, and **validate** any citation by looking up `(source, pattern_id)`. Your stricter checks
  (entry exists, active, is an attack description, was retrieved for that asset) still apply on top.
* **Do not** put our tables into the migration-managed database `threat_modelling` unless you also tell Alembic to ignore
  them (otherwise `alembic revision --autogenerate` will propose dropping them). A second database avoids this.
* **IDs:** map `ATT&CK-T1078` ↔ `T1078` in one small function and document it.

### For other consuming teams (Requirements, Trace/Audit, Consistency, anyone)
* You normally do **not** need the library itself. You need the **IDs our threats cite** (`kb_reference`). Resolve an ID to
  a title with one lookup (offline: search the JSONL by `pattern_id`).
* If you show citation text to reviewers, show **title + official ID** and keep the MITRE notice in your report.

### For Team 2 members (our own team)
* The application default database is `trc_engine_fullkb`; the tests use the 24-entry seed database `trc_engine`
  (pinned in `tests/conftest.py`). Never run `kb.scripts.build_index` against the full database; it refuses to.

## 4. Safe ways to run it, ranked

1. **Files only (Route A).** Zero risk to any database. Best for prototypes and for teams without Docker.
2. **Separate database on the same server (Route B/C).** Fine and cheap. Create the database, restore, give your apps a read-only user:
   ```sql
   CREATE ROLE kb_reader LOGIN PASSWORD '...';
   GRANT CONNECT ON DATABASE trc_kb TO kb_reader;
   GRANT USAGE ON SCHEMA public TO kb_reader;
   GRANT SELECT ON threat_patterns, standards_chunks TO kb_reader;
   ```
3. **Same database as something else:** avoid. If unavoidable, use a dedicated schema and tell your migration tool to ignore it.

## 5. If you want to extend it

| You want to… | Do this |
|---|---|
| Add your company's patterns | New table with the same columns (`source='INTERNAL'`), embed with the same model, search both tables and merge results |
| Use a newer ATT&CK / CAPEC | Rebuild with our scripts into a **new database name**, record the new version, re-run any evaluation |
| Add ISO 21434 or SESIP text | Only with written permission from the rights holder; put it in a separate table and document the licence |
| Change the model | Re-embed **everything** with the new model into a new table; never mix models in one column |

## 6. Quick compatibility checklist before you integrate

- [ ] I created a **new database** (or I use files only).
- [ ] pgvector is installed (`CREATE EXTENSION vector` works).
- [ ] `verify_package.py` says "package is intact".
- [ ] My queries use `all-MiniLM-L6-v2` with `normalize_embeddings=True`.
- [ ] I cite `source` + `pattern_id`, not our numeric `id`.
- [ ] I keep `legal/` notices with any copy.
- [ ] My own data lives in my own tables.
