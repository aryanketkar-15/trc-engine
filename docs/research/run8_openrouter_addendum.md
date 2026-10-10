# Run 8 addendum (separate run; Run 4 and Run 5 files are untouched)

Model `openai/gpt-4o-mini` via OpenRouter (same model as Run 4), improved pipeline
(grounding checks, retry-only-failed, connection and rate-limit retries), 24-entry seed KB.

| Metric | Run 8 | Run 4 |
|---|---|---|
| Expert threats matched (cos >= 0.75) | 1 / 6 (T3, 0.879) | 2 / 6 |
| T1 best similarity | 0.753 (CAPEC-60, borderline) | - |
| Precision / Recall / F1 | 0.017 / 0.167 / 0.030 | - |
| Scenarios | 60 (30 passed, 30 escalated_after_retries) | - |
| Template fallbacks | 4 of 60 | - |
| LLM calls / prompt / completion tokens | 137 / 238,707 / 18,825 | - |
| Time | 406 s | - |

Reading: this is the first run with almost no fallback text, so the numbers are a fair test of the
generator. Matching did NOT improve over Run 4. Half the scenarios were escalated: the grounding
checks (CITATION_MISMATCH 47, EXPOSURE_NOT_GROUNDED 45 failure events) are strict and drove many
retries. Some are genuine (citation naming a different pattern than kb_reference); the exposure
check may be too strict and should be reviewed.
