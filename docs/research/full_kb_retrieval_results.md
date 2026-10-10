# Full-KB retrieval: rerank, benchmark and what it shows

**Branch:** `feat/full-kb-ingestion` | **Date:** 2026-10-10
Data: `retrieval_fullkb_eval_baseline.json`, `retrieval_fullkb_eval_full.json`.
Reproduce: `python tests/threat_agent/research/evaluate_retrieval_fullkb.py baseline|full`.

## Bottom line (read this first)

1. **The full KB scores LOWER than the curated 24-entry seed KB on every split of our own benchmark.**
   Reranking recovers only a small part of the gap. We do not have evidence that the full KB
   improves threat identification yet.
2. Three effects are mixed together in these numbers and cannot be separated without expert judgments:
   - **Seed advantage.** The 24 seed descriptions were written around our demo systems
     ("BLE smart lock", "OTA", "infusion pump"), so they match our test assets unusually well.
   - **Generic text.** MITRE's descriptions are generic; our keyword-style queries match them poorly.
   - **Sparse labels.** Labels are conservative (expert-cited or MITRE-linked). Correct results such as
     `Component Firmware` for a firmware asset count as misses because MITRE does not link them to `CAPEC-186`.
3. Therefore the metrics below are **lower bounds on quality**, not a verdict. A fair number needs
   expert relevance judgments: `retrieval_judgment_sheet.csv` (192 pooled results) is ready for an expert.

## What was built (step 2)

- Deterministic domain tags (`common/domain_tags.py`): keyword rules label every KB entry at build time
  and every asset at query time (hardware, firmware, wireless, network, web, cloud, mobile, ics,
  automotive, crypto, credentials, physical). No model is involved.
- Rerank (`agents/threat_agent/rerank.py`, wired into `retrieval.fetch_candidates`):
  `score = cosine + boost * min(shared tags, 2) - penalty (hardware pattern on an asset with no
  hardware/firmware/physical tag)`. It is **inactive on a KB without tags** (the 24-entry baseline is
  byte-for-byte unchanged) and the reported `retrieval_score` stays the cosine-based value, so
  confidence scores are unaffected. Production and evaluator rankings were checked identical on all 17 queries.
- Defaults (`config/settings.py`): boost 0.02 (selected on the dev split), hardware penalty 0.03.
  **The 0.03 is a post-hoc choice**: dev is indifferent to the penalty (dev assets have no hardware
  noise), and the sensitivity grid shows >= 0.03 helps the held-out split. Held-out numbers for this
  setting are therefore slightly optimistic.

## The benchmark (step 5)

17 queries, graded relevance (2 = expert-cited, 1 = MITRE cross-reference neighbour), labels committed
**before** any tuning (`164d92e`). Splits: **dev** (6 original queries; used to choose weights),
**company** (the company document's threats T1-T6 on the smart door lock; not tuned on),
**held-out** (vehicle gateway ECU and industrial PLC, 6 assets; not tuned on).
**Limitation:** the held-out seeds are engineer-authored and need expert review.

## Results (K = 10)

| KB / setting | Split | nDCG | Seed recall | Hit | MRR | P@10 |
|---|---|---:|---:|---:|---:|---:|
| Seed KB (24), cosine | dev | 0.634 | 0.742 | 1.00 | 0.889 | 0.550 |
| | company | 0.149 | 0.400 | 0.60 | 0.367 | 0.060 |
| | held-out | 0.267 | 0.233 | 1.00 | 0.833 | 0.183 |
| Full KB (2,300), cosine | dev | 0.179 | 0.132 | 0.83 | 0.583 | 0.150 |
| | company | 0.046 | 0.100 | 0.40 | 0.073 | 0.060 |
| | held-out | 0.117 | 0.083 | 0.67 | 0.307 | 0.150 |
| Full KB + rerank (deployed) | dev | 0.208 | 0.132 | 0.83 | 0.750 | 0.150 |
| | company | 0.042 | 0.100 | 0.40 | 0.090 | 0.040 |
| | held-out | 0.136 | 0.083 | 0.83 | 0.342 | 0.183 |

**Company document's own references** (strict recall of `CAPEC-94`, `CAPEC-125`, `ATT&CK-T1078/T1566`,
`CAPEC-186`, `CAPEC-117`, `CAPEC-189`): seed KB **0.40**, full KB **0.00** (with or without rerank).
The cited patterns do not even appear in the top-60 candidates of the full KB for their assets.
(`CAPEC-622`, the actual side-channel pattern, does appear for the key-storage asset.)

**Rerank effect:** nDCG +0.029 on dev, +0.019 on held-out, about 0 on company. These are small, from 17
queries, and no significance test was run; treat them as "not worse, possibly slightly better".

## What we tried that did NOT give a consistent gain

Exploratory, in memory, nDCG dev / company / held-out (no code committed for these runs; strict company recall was 0.00 for all):

| Strategy | dev | company | held-out |
|---|---:|---:|---:|
| Dense, current query (reference) | 0.179 | 0.046 | 0.117 |
| Natural-language query rewrite | 0.148 | 0.034 | 0.171 |
| BM25 keyword only | 0.188 | 0.043 | 0.091 |
| Dense + BM25 fusion (RRF) | 0.210 | 0.043 | 0.114 |
| Cross-encoder rerank over fusion | 0.245 | 0.023 | 0.121 |
| Embedding model all-MiniLM-L12-v2 | 0.229 | 0.010 | 0.143 |
| Embedding model bge-small-en-v1.5 | 0.178 | 0.000 | 0.107 |
| Embedding model e5-small-v2 | 0.199 | 0.026 | 0.108 |

Some help on dev but none helps consistently across splits, so none was adopted (a cross-encoder or a
bigger model adds cost for an unproven gain).

## Next steps (in order of value)

1. **Expert judgments** on `retrieval_judgment_sheet.csv`, then recompute metrics on those judgments. This is the only way to get a fair quality number.
2. **Company domain patterns** (their internal / hardware attack patterns): descriptions that match real assets are what made the seed KB work.
3. Re-evaluate cross-encoder / hybrid retrieval only after step 1 gives reliable labels.
4. Expert review of the held-out seeds; confirm `CAPEC-189` vs `CAPEC-622` for the company's T6.
