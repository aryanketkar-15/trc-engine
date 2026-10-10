# Run 5 addendum (separate run; Run 4 files are untouched)

Model `openai/gpt-oss-120b` on Groq (free tier), pipeline with grounding + retry-only-failed, 24-entry seed KB.
NOT comparable with Run 4 (gpt-4o-mini, 2/6 matched).

| Metric | Value |
|---|---|
| Scenarios | 60 (all marked passed after 2 retries) |
| Expert threats matched (cos >= 0.75) | 1 / 6 (T3) |
| Precision / Recall / F1 | 0.017 / 0.167 / 0.030 |
| LLM calls / prompt / completion tokens | 65 / 75,466 / 37,250 |
| Time | 840 s |
| Connection errors | 26 (APIConnectionError) |

**Run is contaminated:** 26 of 60 scenarios are the deterministic template fallback
("Exploitation of ... via ...") because the Groq connection failed for those paths.
Only 34 scenarios are real LLM output. Do not quote the 1/6 as a quality result; rerun when the connection is stable.
