# Phase 1 demonstration (company walkthrough)

`scripts/scrp_demo.py` runs the real Phase 1 pipeline end to end, stage by stage:
Perceive (with redaction) -> Knowledge base and retrieval -> Attack paths -> Generation ->
Validation + grounding -> Scenario review -> Human gate -> Shared state (SCRS) and audit trail.
Everything it writes goes to `demo_output/` (never to the real `SCRS_state.json`).

## Prerequisites (once)

```bash
docker compose up -d                       # PostgreSQL + pgvector (container trc-postgres)
pip install -e .                           # if not already installed (uses pyproject.toml)
```

`.env` must point `DATABASE_URL` at the full knowledge base (`.../trc_engine_fullkb`; the default).
Live mode also needs a funded key in `OPENAI_API_KEY` (and `OPENAI_BASE_URL` / `OPENAI_MODEL` for
OpenRouter). Replay mode needs no key and no internet.

## Run it

| Command | What you get |
|---|---|
| `python scripts/scrp_demo.py` | Interactive. Recorded real model output (no network). Pauses between stages. |
| `python scripts/scrp_demo.py --auto` | Scripted walkthrough (reject, prune, failed + valid expert add, approve). No typing. |
| `python scripts/scrp_demo.py --mode live` | Calls the configured model; rejected scenarios are really regenerated. |
| `python scripts/scrp_demo.py --mode live --auto` | Fully scripted live run. |
| `python scripts/scrp_demo.py --fixture pump --mode live` | Infusion pump instead of the door lock (live only). |
| `--max-paths N` | Attack paths to take through generation (default 12). Live time is ~7 s per path. |
| `--no-pause`, `--detail N`, `--verbose` | No pauses / scenarios shown in full / show internal logs. |

Use a wide terminal (120+ columns) for the cleanest tables.

## Reviewer commands (interactive human gate)

`v N` view scenario N | `r N` reject N with feedback (live: regenerates it) | `p N` prune with a
reason | `a` add an expert scenario | `l` list | `ok` approve everything remaining and write to
the SCRS | `q` quit without writing.

## Suggested talk track (about 10 minutes)

1. Perceive: the input is schema-validated; secrets and PII are masked before any model call.
2. Knowledge base: 2,300 patterns from free CAPEC / ATT&CK / CWE plus STRIDE, 5,097 standards chunks.
3. Generation: one scenario per attack path, each citing a pattern that retrieval really returned.
4. Validation: four protocol invariants plus grounding rules; failures are retried per path only.
5. Human gate: reject with feedback, prune with a reason, add an expert scenario (validated and
   checked against the knowledge base). Nothing is written without an approval.
6. SCRS: show the audit log and revision history (rejected and pruned content is never deleted).
7. Last table: what is complete and what is waiting (Team 1 fields, company expert input,
   ISO / SESIP catalogues, multi-step chaining, Phase 2).

## Honest notes for the audience

* Scenarios flagged `ESCALATED` failed an automatic check after the retries and are shown to the
  human reviewer on purpose; AI output is a recommendation only.
* Multi-step kill-chain ordering is not implemented yet; each retrieved pattern is one attack path.
* Accuracy against the company's six reference threats is 1 of 6 at the 0.75 similarity threshold
  (see `docs/research/final_fullkb_addendum.md`).

## Troubleshooting

* `Knowledge base unreachable` -> `docker compose up -d`, then check `DATABASE_URL`.
* Live mode HTTP 402 / 429 -> the key has no credit / is rate limited; use replay mode.
* First retrieval takes ~30 s while the embedding model loads.
