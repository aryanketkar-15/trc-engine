# Final run: six company threats on the FULL knowledge base (default configuration)

Model `openai/gpt-4o-mini` via OpenRouter (same model as Run 4), full KB (`trc_engine_fullkb`,
2,300 MITRE entries + STRIDE), current pipeline (grounding, retry-only-failed, rate-limit/connection
retries). Separate from Runs 4, 5 and 8; no earlier file was changed.

| Metric | Final (full KB) | Run 8 (24-entry KB) | Run 4 (24-entry KB, old pipeline) |
|---|---|---|---|
| Expert threats matched (cos >= 0.75) | 1 / 6 (T3, 0.832) | 1 / 6 | 2 / 6 |
| Near misses (0.70-0.75) | T6 0.745 (CAPEC-622), T2 0.703 | T1 0.753 | - |
| Precision / Recall / F1 | 0.067 / 0.167 / 0.095 | 0.017 / 0.167 / 0.030 | - |
| Scenarios | 60 (36 passed, 24 escalated) | 60 (30 / 30) | - |
| Template fallbacks | 6 of 60 | 4 of 60 | - |
| Calls / prompt / completion tokens | 133 / 222,740 / 18,398 | 137 / 238,707 / 18,825 | - |
| Time | 405 s | 406 s | - |

Reading: moving to the full KB did not lower the matched count and raised precision and the number of
near-misses (T6 now lands on CAPEC-622, the pattern the company's own row should cite). Citation
mismatches (59 events) remain the main reason scenarios are escalated for human review.
The cosine threshold is fixed at 0.75 as in Run 4; with one run per configuration these differences
are small and should not be over-interpreted.
