# TRC Engine — Phase 1: Threat Agent

> **AI-Assisted Threat–Risk–Compliance Engine**  
> Built on the State-Aware Cybersecurity Reasoning Protocol (SCRP)

## Overview

The TRC Engine is a multi-agent AI pipeline for structured, evidence-backed threat modelling.  
**Phase 1 (this repo)** implements the **Threat Agent** — the entry point of the full SCRP pipeline.

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
