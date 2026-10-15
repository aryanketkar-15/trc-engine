# TRC Knowledge Base package: start here

**From:** Team 2, group TY-A9 (Threat Agent). **For:** Team 1 and any other team that wants to use our knowledge base.
**Version:** built 15 Oct 2026 from our live database `trc_engine_fullkb`; every file below was checked after export.

## 1. What this is, in three sentences

It is the library of **known attacks** that our Threat Agent searches: **2,300 attack patterns**
(CAPEC, MITRE ATT&CK, CWE and our six STRIDE rules) and **5,097 pieces of standards text**
(Common Criteria, CEM, JIL, EU Cyber Resilience Act). Every entry also has a **384-number "meaning vector"**, so you can
search **by meaning** instead of by exact words. You can use it **with or without a database**.

## 2. Pick how you want to use it

| You want… | Use | Needs |
|---|---|---|
| Just look things up / prototype, no database | **Route A: files** (`tools/search_offline.py`) | Python, numpy, sentence-transformers |
| A real database like ours | **Route B: restore the SQL dump** (`db/trc_kb_tables.sql.gz`) | PostgreSQL 14+ with the **pgvector** extension |
| A database, but you cannot run the dump | **Route C: import from files** (`tools/import_from_files.py`) | Python, psycopg, pgvector |

All three routes give **identical results** (we tested them: same top matches and scores).

### Route A: no database (2 minutes)
```bash
pip install numpy sentence-transformers
python tools/verify_package.py
python tools/search_offline.py "firmware update over bluetooth without signature check" --top 5
python tools/search_offline.py "key extraction side channel" --source CAPEC --top 5
```

### Route B: PostgreSQL (5 minutes)
Use a **separate, new database** (see `03_USE_WITHOUT_CONFLICT.md` for why).
```bash
# 1. create an empty database and enable pgvector
psql -U <user> -d postgres -c "CREATE DATABASE trc_kb"
psql -U <user> -d trc_kb  -c "CREATE EXTENSION IF NOT EXISTS vector"
# 2. load the dump
gunzip -c db/trc_kb_tables.sql.gz | psql -U <user> -d trc_kb -q
# 3. check
psql -U <user> -d trc_kb -c "SELECT source, count(*) FROM threat_patterns GROUP BY 1"
```
If your Postgres runs in Docker (container name `my-postgres` here):
```bash
docker exec my-postgres psql -U <user> -d postgres -c "CREATE DATABASE trc_kb"
docker exec my-postgres psql -U <user> -d trc_kb -c "CREATE EXTENSION IF NOT EXISTS vector"
gunzip -c db/trc_kb_tables.sql.gz | docker exec -i my-postgres psql -U <user> -d trc_kb -q
```
Expected: `CAPEC 556, CWE 944, ATT&CK 794, STRIDE 6` and `standards_chunks = 5097`.
The image must include pgvector, for example `pgvector/pgvector:pg16`.

### Route C: import from the files
```bash
pip install "psycopg[binary]" pgvector numpy
python tools/import_from_files.py --db postgresql://<user>:<password>@<host>:<port>/trc_kb
```

## 3. What is in the zip

```
README_START_HERE.md              this file
01_KNOWLEDGE_BASE_EXPLAINED.md    where each source came from, what it contains, every field
02_HOW_WE_USE_IT.md               exactly how our Threat Agent searches and uses it, with code
03_USE_WITHOUT_CONFLICT.md        rules so your use does not clash with ours or Team 1's tables
data/
  threat_patterns.jsonl           2,300 attack patterns (text + metadata)
  threat_patterns_embeddings.npy  their 2,300 x 384 vectors, same row order
  standards_chunks.jsonl          5,097 standards text pieces
  standards_chunks_embeddings.npy their 5,097 x 384 vectors, same row order
  MANIFEST.json                   counts, model, source-file hashes, file hashes
db/trc_kb_tables.sql.gz           PostgreSQL dump of the two tables (with vectors)
sql/schema.sql                    the table definitions
tools/                            verify_package.py, search_offline.py, search_postgres.py, import_from_files.py
legal/                            licence notices you must keep with any copy
```

## 4. Five facts to remember

1. **Free sources only.** ISO/SAE 21434, SESIP, IEC 62443 and ISO 27001 are **not** included (paid or unclear terms).
2. **It is general knowledge,** not your company's internal patterns. Quality on hardware-specific questions is limited.
3. **The vectors come from one model, `all-MiniLM-L6-v2` (384 numbers).** Query with the same model or the numbers are meaningless.
4. **Treat it as read-only reference data.** Do not edit rows or add your own rows to these tables.
5. **Keep the licence notices** (`legal/`) with any copy. MITRE's material is free to use but must carry its notice.

## 5. Size and checks

About 27 MB zipped, 34 MB unpacked (16 MB SQL dump, 18 MB data files). `python tools/verify_package.py` checks every data file
against the hashes in `MANIFEST.json` and checks that rows and vectors line up.
