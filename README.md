# TRC Engine: Threat, Risk and Compliance agents

> **AI-Assisted Threat–Risk–Compliance Engine**  
> Built on the State-Aware Cybersecurity Reasoning Protocol (SCRP)

## Overview

The TRC Engine takes a product's assets and use cases, identifies threats (Threat Agent), assesses and ranks risk (Risk Agent) and
maps the required attack resistance (Compliance Agent). The AI proposes, a named expert decides, and only approved results reach
the shared state.

| Read this | For |
|---|---|
| `docs/Company_Requirements_Matrix.md` | What the company document asks, its status, and the known limits |
| `docs/Operations_Guide.md` | Running it, users and roles, audit, recovery |
| `docs/Move_Laptop_and_Ollama.md` | Setting up a new machine and switching to a local model |
| `docs/Phase2_Demo_Runbook.md` | The demo |

The threat pipeline:

```
Use Case + System Model
        │
        ▼
  ┌─────────────┐     ┌──────────────┐     ┌───────────────────┐
  │ KB/pgvector │────▶│ Attack Chain │────▶│ Threat Scenario    │
  │  Retrieval  │     │  Analysis    │     │ Generator (LLM)    │
  └─────────────┘     └──────────────┘     └────────┬──────────┘
                                                    │
                                          ┌─────────▼──────────┐
                                          │ Protocol Invariant  │
                                          │ Validator (≤3 retry)│
                                          └─────────┬──────────┘
                                                    │
                                          ┌─────────▼──────────┐
                                          │ Human-in-the-Loop   │
                                          │ Approval Gate       │
                                          └─────────┬──────────┘
                                                    │
                                                    ▼
                                     SCRS (Shared Reasoning State)
                                     → consumed by Risk Agent (Phase 2)
```

## Team

| Member | Domain |
|--------|--------|
| Aryan | KB Ingestion, pgvector DB, Retrieval, Attack Chain |
| Chetan | Threat Generator, Confidence Scorer, Prompts |
| Shriraj | Protocol Invariant Validator, Retry Loop, SCRS Write |
| Manthan | API Layer, LLM Client, Logging, Config, CI |

## Branch Structure

```
main
 └── develop
      ├── feature/threat-agent-retrieval        (Aryan)
      ├── feature/retrieval-pgvector-migration  (Aryan)
      ├── feature/threat-agent-generator        (Chetan)
      ├── feature/threat-agent-validator        (Shriraj)
      └── feature/threat-agent-api-tests        (Manthan)
```

## Quickstart

### 1. Start PostgreSQL with pgvector

```bash
# Requires Docker. Reads credentials from .env
docker compose up -d
```

### 2. Populate the Knowledge Base

```bash
# Embeds seed JSONs and upserts into the threat_patterns table.
# Idempotent — safe to re-run after adding new seed entries.
python -m kb.scripts.build_index
```

### 3. Run the CLI demo

```bash
python scripts/demo_cli.py
```

### 4. Run the test suite

```bash
pytest tests/ -v
```

> **Integration tests** (live pgvector) are skipped by default.  
> To run them: `TRC_INTEGRATION_TESTS=1 pytest tests/threat_agent/integration/ -v`

## Day-1 Contract

The data contract is frozen in [`agents/threat_agent/schemas.py`](agents/threat_agent/schemas.py).  
All modules depend on this schema — never the reverse.

## Linter

```bash
ruff check .
ruff format .
```

## License

Academic — TRC Engine, Phase 1. All rights reserved.

## Knowledge base selection

The application uses the **full knowledge base** by default (`DATABASE_URL=…/trc_engine_fullkb`:
CAPEC, ATT&CK, CWE, STRIDE plus standards chunks).  The 24-entry seed KB (`…/trc_engine`) is used by
the automated tests only (`tests/conftest.py` points them there; override with
`TRC_TEST_DATABASE_URL`).  `python -m kb.scripts.build_index` builds the seed KB and refuses to run
against the full-KB database; `build_full_index` / `build_standards_index` refuse the seed database.
