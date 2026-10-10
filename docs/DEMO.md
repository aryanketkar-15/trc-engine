# Phase 1 command line

`scripts/scrp_demo.py` is the interactive Threat Agent: pick a project, generate threat scenarios,
approve or reject each one. A rejected scenario asks for your reason and is regenerated; this repeats
until you approve it or reach 3 rejections. Approved scenarios are written to the shared state (SCRS)
with an audit log. Output goes to `demo_output/` (the real `SCRS_state.json` is never touched).

## Setup (once)

```bash
docker compose up -d        # PostgreSQL + pgvector
pip install -e .            # if not installed yet
```

`.env` must contain `DATABASE_URL=.../trc_engine_fullkb` (the default) and a funded `OPENAI_API_KEY`
(plus `OPENAI_BASE_URL` / `OPENAI_MODEL` for OpenRouter).

## Run

```bash
python scripts/scrp_demo.py                        # menu: choose a project
python scripts/scrp_demo.py --project 1            # skip the menu
python scripts/scrp_demo.py --input my_project.json   # your own project JSON
python scripts/scrp_demo.py --mode live            # always call the language model
python scripts/scrp_demo.py --auto                 # scripted answers, for rehearsal
```

Projects offered: every `tests/threat_agent/e2e/fixtures/*/input.json` plus any `*.json` placed in a
`projects/` folder. For the Smart Door Lock the default is recorded real model output (no network);
other projects call the model. `--max-paths N` sets how many scenarios are generated (default 6). The output explains each step the
agent takes (understand the system, plan the search, search the knowledge base, build attack paths,
generate, check, your review); add `--quiet` for short output.

## At each scenario

| Answer | Effect |
|---|---|
| `y` (Enter) | approve |
| `n` | reject; type a reason; the scenario is regenerated and shown again (max 3 rejections) |
| `x` | discard with a reason (kept in the audit log) |
| `a` | approve all remaining |
| `q` | stop reviewing |

After the last scenario you may add an expert scenario of your own (validated, and its pattern id is
checked against the knowledge base). Approved scenarios are then written to the SCRS.

## Notes

* Scenarios marked `flagged` failed an automatic check after the retries; they are shown on purpose.
* Recorded mode cannot use your rejection reason (it shows the next recorded alternative); `--mode live`
  regenerates from your reason.
* Each attack path is a single retrieved pattern; multi-step chaining is not implemented yet.
* First retrieval takes about 30-50 s while the embedding model loads.
