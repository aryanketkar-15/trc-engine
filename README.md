# TRC Engine: Threat, Risk and Compliance agents

> **State-Aware Cybersecurity Reasoning Protocol (SCRP)** for explainable, audit-ready AI-assisted
> Threat-Risk-Compliance engineering. Group TY-A9, Vishwakarma Institute of Technology, Pune.

The engine takes a product's assets and use cases and produces, with a named expert approving every step:

1. **Threats** (Threat Agent): STRIDE scenarios built from a vector knowledge base (CAPEC, ATT&CK, CWE, STRIDE) with evidence and citations.
2. **Risks** (Risk Agent): impact and attack feasibility rated by fixed rules (ISO/SAE 21434, Common Criteria method), ranked per asset, with the treatment decision and the residual risk.
3. **Required attack resistance** (Compliance Agent): JIL attack potential, assurance component, SESIP level and Common Criteria EAL by a rule base, with a cited rationale.

A language model (hosted, or local through Ollama) drafts scenarios, suggests ratings and explains decisions. It never decides a risk
level, a resistance level or an approval. Every output is checked, approved by a named person and written to a shared, versioned
state with a hash-chained audit log.

## Status

All three agents are built and tested (about 630 automated tests) and run end to end on the shared smart-door-lock example with three use
cases. They have **not** been reviewed by a security expert, and some quality limits are known and measured: read
[docs/Handover_Known_Limits.md](docs/Handover_Known_Limits.md) before relying on any content.

## Where to start

| You are... | Read |
|---|---|
| Team 3 (receiving our results) | [docs/Handover_For_Team3.md](docs/Handover_For_Team3.md) |
| Team 1 (sending us asset tables) | [docs/Team1_Integration.md](docs/Team1_Integration.md) |
| Setting up a machine or a local model | [docs/Move_Laptop_and_Ollama.md](docs/Move_Laptop_and_Ollama.md), [docs/Ollama_Setup_and_Test.md](docs/Ollama_Setup_and_Test.md) |
| Running or operating it (users, roles, audit, recovery) | [docs/Operations_Guide.md](docs/Operations_Guide.md) |
| Looking for what was asked and what is done | [docs/Company_Requirements_Matrix.md](docs/Company_Requirements_Matrix.md) |
| Running a demo | [docs/Phase2_Demo_Runbook.md](docs/Phase2_Demo_Runbook.md) |

## How it fits together

```
Team 1: approved asset table per use case
        │  import (file or API, approved only)
        ▼
 ┌────────────┐   ┌────────────┐   ┌──────────────────┐
 │Threat Agent│──▶│ Risk Agent │──▶│ Compliance Agent │
 └─────┬──────┘   └─────┬──────┘   └────────┬─────────┘
       │ knowledge base │  fixed rule tables │  rule base + cited rationale
       ▼                ▼                    ▼
   SCRS: shared state, versions, hash-chained audit log, traceability, stale flags
        │  export (approved only, in Team 1 and Team 3 field names)
        ▼
Team 3: requirements, trace and audit, consistency
```

The threat pipeline: retrieval plan per asset, pgvector search, attack-path chaining, model scenario, Protocol Invariant Validator
(at most three retries, only for failed paths), human approval gate.

## Team

| Member | Domain |
|--------|--------|
| Aryan | KB ingestion, pgvector DB, retrieval, attack chain |
| Chetan | Threat generator, confidence scorer, prompts |
| Shriraj | Protocol Invariant Validator, retry loop, SCRS write |
| Manthan | API layer, LLM client, logging, config, CI |

Guide: Dr. Vidya Gaikwad.

## Quickstart

```bash
docker compose up -d                       # PostgreSQL with pgvector (reads credentials from .env)
pip install -e .
python -m kb.scripts.build_index           # the small seed knowledge base used by the tests
python scripts/demo_cli.py                 # a first demo
```

The full knowledge base (2,300 catalogue entries and 5,097 standards passages) is not in Git; restore it as described in
`docs/Move_Laptop_and_Ollama.md`. The application uses it by default (`DATABASE_URL=…/trc_engine_fullkb`); the 24-entry seed
knowledge base (`…/trc_engine`) is used by the automated tests only (`tests/conftest.py`, override with `TRC_TEST_DATABASE_URL`).

```bash
pytest tests/ -v                                           # unit tests
TRC_INTEGRATION_TESTS=1 pytest tests/ -q                   # also the database tests (Docker must be running)
python scripts/live_agents_check.py                        # does the configured model work in all three agents?
python scripts/measure_first_pass.py --project <file>      # how often is a threat card right at the first attempt?
ruff check .
```

The data contract is frozen in `agents/threat_agent/schemas.py`; all modules depend on it, never the reverse.

## Branches

`main` (stable) and `develop` (integration). Work is done on feature branches and merged into `develop`. Commit messages are
`type(scope): message`.

## Licence

Academic project, VIT Pune. MITRE catalogue data is used under MITRE's royalty-free licence (`kb/NOTICE_MITRE.md`).
