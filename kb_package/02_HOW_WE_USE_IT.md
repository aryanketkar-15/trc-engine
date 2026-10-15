# 02 · How our Threat Agent uses the knowledge base

This is the exact recipe, so you can use the library the same way and get comparable results.

## 1. The five-line summary

1. Turn each asset into a **query sentence**.
2. Turn that sentence into **384 numbers** with the model `all-MiniLM-L6-v2` (unit length).
3. Find the **closest patterns** by cosine similarity (pgvector `<=>`), across all four catalogues.
4. **Re-rank** a little using topic tags (a small bonus for matching topics, a small penalty for hardware-only patterns on software assets).
5. Each of the best patterns becomes one **attack path**; the AI may cite **only** those patterns, and code checks it.

## 2. Step by step

### 2.1 The query sentence (from `agents/threat_agent/retrieval.py`)
```text
<asset name> <asset type> <interface 1> <interface 2> ... <key: value device settings> <trust zone>
```
Example (firmware asset): `Firmware Image embedded firmware BLE OTA UART update_auth: no-verify untrusted`

### 2.2 The embedding
* Model: **`all-MiniLM-L6-v2`** (sentence-transformers), 384 dimensions, **normalised** (length 1).
* For patterns, the text that was embedded is `title + description (+ stride hint) (+ ATT&CK tactic IDs)`.
* For standards pieces: `doc + locator + title + text`.
* Because every vector has length 1, **cosine similarity = dot product**.

### 2.3 The search (PostgreSQL)
```sql
SELECT pattern_id, source, title, metadata,
       1 - (embedding <=> %(q)s) AS similarity        -- <=> is pgvector cosine distance
FROM   threat_patterns
WHERE  source = ANY(%(sources)s)                       -- ['CAPEC','ATT&CK','CWE','STRIDE']
ORDER  BY embedding <=> %(q)s
LIMIT  60;                                             -- candidate pool, then re-ranked
```
Offline (no database) the same thing is `similarity = embeddings @ q` followed by sorting
(`tools/search_offline.py`).

### 2.4 Re-ranking (small, deterministic, no AI)
```text
score = similarity + 0.02 x (number of topic tags shared by the asset and the pattern, at most 2)
        - 0.03 if the pattern is tagged "hardware" and the asset has none of the tags hardware / firmware / physical
```
The tags come from keyword rules (`common/domain_tags.py`), the same rules at build time (for patterns) and at query
time (for assets). The top **10 per asset** are kept after re-ranking.
Settings: `RETRIEVAL_RERANK_BOOST=0.02`, `RETRIEVAL_RERANK_HW_PENALTY=0.03`, `RETRIEVAL_POOL_SIZE=60`.

### 2.5 From pattern to scenario
* Each kept pattern + its asset becomes an **attack path** (single step; multi-step chaining is not built).
* The AI receives the asset facts and the pattern text, and must write a scenario that **cites that pattern**.
* **Grounding check (code, not AI):** the scenario's `kb_reference` must be one of the patterns retrieved for that
  path, the asset must exist, and the exposure must relate to the asset. Otherwise the scenario is rejected and retried.
* **Expert-added scenarios:** the cited ID must **exist** in `threat_patterns` (`kb_reference_exists`).

## 3. How we cite entries

| What you cite | Format we store | Check |
|---|---|---|
| A CAPEC pattern | `CAPEC-665` | `source='CAPEC' AND pattern_id='CAPEC-665'` |
| An ATT&CK technique | `ATT&CK-T1542.002` | `source='ATT&CK'` |
| A CWE | `CWE-1277` | `source='CWE'` |
| A STRIDE rule | `STRIDE-T-001` | `source='STRIDE'` |

(Team 1's own knowledge base writes ATT&CK ids as `T1078`; ours prefixes them with `ATT&CK-`. Convert when you
exchange IDs.)

## 4. Python: minimal reusable function

```python
import numpy as np, psycopg
from pgvector.psycopg import register_vector
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("all-MiniLM-L6-v2")

def build_query(name, asset_type, interfaces, config, trust_zone):
    parts = [name, asset_type, *interfaces, *[f"{k}: {v}" for k, v in config.items()], trust_zone]
    return " ".join(p for p in parts if p and p != "unspecified")

def search(conn, query, top=10, sources=("CAPEC", "ATT&CK", "CWE", "STRIDE")):
    q = model.encode([query], normalize_embeddings=True)[0].astype(np.float32)
    return conn.execute(
        """SELECT pattern_id, source, title, 1 - (embedding <=> %s) AS sim
           FROM threat_patterns WHERE source = ANY(%s) ORDER BY embedding <=> %s LIMIT %s""",
        (q, list(sources), q, top)).fetchall()

with psycopg.connect("postgresql://USER:PASS@HOST:PORT/trc_kb") as conn:
    register_vector(conn)
    for pid, src, title, sim in search(conn, build_query(
            "Firmware Image", "embedded firmware", ["BLE OTA", "UART"], {"update_auth": "no-verify"}, "untrusted")):
        print(f"{sim:.3f} {pid:<18} {src:<7} {title}")
```

## 5. Ready-made results you can compare against

| Query | Top results (offline and PostgreSQL gave identical output) |
|---|---|
| `firmware update over bluetooth without signature check` | `ATT&CK-T1693.001` System Firmware (0.489) · `CAPEC-667` Bluetooth Impersonation AttackS (0.485) · `CWE-1277` Firmware Not Updateable (0.469) · `CAPEC-668` KNOB (0.446) |

If your numbers differ, check: same model name, vectors normalised, same table contents (`verify_package.py`).

## 6. What we measured (so you know what to expect)

* Domain-tag re-ranking was the one change that helped our benchmark consistently; other ideas (keyword search, a
  re-ranking model, other embedding models, AI query rewriting) did not, so we did not adopt them.
* On the company's six door-lock reference threats our system matches 1 of 6; two more are close. The limit is the
  library's coverage of hardware/internal knowledge, not the search recipe.
