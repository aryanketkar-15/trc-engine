# TRC Engine: Comprehensive Technical Architecture, Methodology & Project Evolution Reference

**Project**: Threat-Risk-Compliance Engine (TRC Engine)  
**Component**: Phase 1 & Phase 2 Threat Agent (`agents/threat_agent`)  
**Scope**: Full architectural history, implementation methodology, design decisions, evolution changelog, and current system state.  
**Audience**: Engineering teammates, Risk Agent builders, faculty reviewers, and external evaluators.

---

## Table of Contents
1. [Executive Summary & Purpose](#1-executive-summary--purpose)
2. [End-to-End Methodology: The SCRP Architecture](#2-end-to-end-methodology-the-scrp-architecture)
3. [Chronological Evolution & Architectural Decision Log](#3-chronological-evolution--architectural-decision-log)
   - [Stage 1: Initial Foundation & FAISS Vector Index](#stage-1-initial-foundation--faiss-vector-index)
   - [Stage 2: Migration from FAISS to pgvector (PostgreSQL 16)](#stage-2-migration-from-faiss-to-pgvector-postgresql-16)
   - [Stage 3: Live LLM Wiring & Prompt Engineering](#stage-3-live-llm-wiring--prompt-engineering)
   - [Stage 4: Outbound PII Redaction Middleware](#stage-4-outbound-pii-redaction-middleware)
   - [Stage 5: Confidence Scorer Extraction & Mathematical Grounding](#stage-5-confidence-scorer-extraction--mathematical-grounding)
   - [Stage 6: Router State Machine, Concurrency Locks & Persistent Run Store](#stage-6-router-state-machine-concurrency-locks--persistent-run-store)
   - [Stage 7: Restoring the Automated Invariant Retry Loop](#stage-7-restoring-the-automated-invariant-retry-loop)
   - [Stage 8: API-Key Authentication on State-Changing Endpoints](#stage-8-api-key-authentication-on-state-changing-endpoints)
   - [Stage 9: Domain-Neutral E2E Validation on Safety-Critical Infusion Pump](#stage-9-domain-neutral-e2e-validation-on-safety-critical-infusion-pump)
4. [Component-by-Component Technical Breakdown](#4-component-by-component-technical-breakdown)
   - [Input Parsing & Perception Layer](#input-parsing--perception-layer)
   - [Vector Retrieval & Multi-KB Grounding](#vector-retrieval--multi-kb-grounding)
   - [Multi-Step Attack Chaining](#multi-step-attack-chaining)
   - [Generation & Prompt Construction](#generation--prompt-construction)
   - [Protocol Invariant Validator](#protocol-invariant-validator)
   - [Orchestration & Automated Self-Correction](#orchestration--automated-self-correction)
   - [Human Approval Gate & SCRS Persistence](#human-approval-gate--scrs-persistence)
5. [Real-World Bugs Encountered & Engineering Solutions](#5-real-world-bugs-encountered--engineering-solutions)
6. [Current Codebase Verification, Test Suite & Invariants](#6-current-codebase-verification-test-suite--invariants)
7. [Downstream Hand-off: Guidance for the Risk Agent](#7-downstream-hand-off-guidance-for-the-risk-agent)

---

## 1. Executive Summary & Purpose

The **Threat-Risk-Compliance (TRC) Engine** is an automated, AI-assisted security engineering platform designed to eliminate the bottlenecks, inconsistencies, and hallucinations typical of manual threat modeling (TARA / STRIDE).

Modern systems (IoT door locks, medical devices, automotive ECUs) require rigorous threat modeling aligned with standards like **ISO/SAE 21434**, **NIST SP 800-53**, **CAPEC**, **MITRE ATT&CK**, and **CWE**. Manual analysis is slow, and unconstrained LLMs generate hallucinations without verifiable evidence.

The Threat Agent addresses this by implementing an **evidence-first, constrained agentic workflow**:
1. It ingests formal data-flow diagrams and asset definitions.
2. It queries a grounded vector knowledge base containing verified security taxonomies.
3. It chains atomic security weaknesses into realistic multi-step attack paths.
4. It synthesizes concrete threat scenarios via an LLM constrained by strict schema requirements.
5. It validates every scenario against automated protocol invariants with automated self-correcting retry loops.
6. It enforces a strict human-in-the-loop approval gate before committing scenarios to the downstream Single Source of Risk and Compliance (SCRS).

---

## 2. End-to-End Methodology: The SCRP Architecture

The Threat Agent operates according to the **SCRP** (Sense/Perceive → Plan → Fetch → Chain → Observe → Validate → Human Gate → Produce) execution pipeline:

```
                  ┌─────────────────────────────────────┐
                  │ 1. PERCEIVE: ThreatAgentInput       │
                  │    - System Model & DFD Context     │
                  │    - Asset & Security Attributes    │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 2. PLAN: build_retrieval_plan()     │
                  │    - Decompose assets & interfaces  │
                  │    - STRIDE category mapping        │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 3. FETCH: fetch_candidates()        │
                  │    - pgvector Cosine Similarity (<=>)
                  │    - CAPEC / ATT&CK / CWE / STRIDE   │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 4. CHAIN: build_paths()             │
                  │    - Multi-step attack tree assembly│
                  │    - Entry point to target asset    │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 5. OBSERVE: generate_scenarios()    │
                  │    - PII Redaction Middleware       │
                  │    - Prompt injection detection     │
                  │    - OpenAI / OpenRouter Call       │
                  │    - Fallback to deterministic synth│
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 6. VALIDATE: Validator().validate() ◄────────────┐
                  │    - Citation Presence Check        │            │
                  │    - Schema Completeness Check      │    Auto-Retry Loop
                  │    - STRIDE Consistency Check       │    (Max 3 attempts
                  │    - Non-generic Evidence Check     │    with injected
                  └──────────────────┬──────────────────┘    failure context)
                                     │                               │
                      Passed / Retries Exhausted                     │
                                     │                               │
                                     ▼                               │
                  ┌─────────────────────────────────────┐            │
                  │ 7. ORCHESTRATE: Self-Correction     │────────────┘
                  │    - Re-fetches + Re-generates      │
                  │    - "passed" or "escalated"        │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 8. HUMAN GATE: /approve or /reject  │
                  │    - Analyst Review                 │
                  │    - Rejection triggers re-reasoning│
                  └──────────────────┬──────────────────┘
                                     │
                              Approve (200 OK)
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ 9. PRODUCE: Write to SCRS           │
                  │    - Immutable JSON / SCRS State    │
                  │    - Ready for downstream Risk Agent│
                  └─────────────────────────────────────┘
```

---

## 3. Chronological Evolution & Architectural Decision Log

### Stage 1: Initial Foundation & FAISS Vector Index
* **Initial State**: Early prototypes utilized `faiss-cpu` to index local embeddings (`all-MiniLM-L6-v2`) in an in-memory FlatIP/IndexFlatL2 index. The generator was largely a deterministic stub returning mock scenarios.
* **Limitations**:
  - FAISS index was purely in-memory: every process restart required reloading and re-indexing all vectors from scratch.
  - No transactional consistency, ACID compliance, or ability to join vector data with relational threat tables.
  - Multi-threaded or multi-worker deployments could not safely share state.

### Stage 2: Migration from FAISS to pgvector (PostgreSQL 16)
* **Commits**: `5cc0861` -> `b942c11` -> `c1b5ab4`
* **Why**: To achieve enterprise durability, relational joins, ACID transactions, and persistent indexing in a single unified storage engine.
* **Technical Changes**:
  - Introduced PostgreSQL 16 container with `pgvector/pgvector:pg16` extension in `docker-compose.yml`.
  - Migrated `kb/scripts/build_index.py` from FAISS `.index` files to relational tables (`kb_chunks` with `vector(384)`).
  - Implemented SQL-level cosine distance queries using pgvector's `<=>` operator:
    ```sql
    SELECT pattern_id, source, title, description,
           1 - (embedding <=> %(query_embedding)s) AS retrieval_score
    FROM kb_chunks
    ORDER BY embedding <=> %(query_embedding)s
    LIMIT %(top_k)s;
    ```
  - Handled container port conflicts by mapping external port `5433` -> internal port `5432` on Windows developer machines.

### Stage 3: Live LLM Wiring & Prompt Engineering
* **Commits**: `9379673` -> `5adb602`
* **Why**: Threat generation required real contextual reasoning over domain-specific assets and multi-step attack graphs rather than static mock templates.
* **Technical Changes**:
  - Implemented `common/llm_client.py` using `openai.OpenAI`, pre-configured for OpenRouter (`https://openrouter.ai/api/v1`) when API keys match `sk-or-v1-*`.
  - Added resilient HTTP handling: exponential backoff retry on transient errors (429, 500, 502, 503, 504), configurable request timeouts, and structured `llm_call_start` / `llm_call_complete` audit events.
  - Implemented `_deterministic_fallback_for_path()` in `generator.py`: if the live API is unreachable or rate-limited, the engine automatically engages a deterministic generator guaranteed to satisfy protocol invariants, ensuring zero system outages during pipeline runs.

### Stage 4: Outbound PII Redaction Middleware
* **Commits**: `0b50730` -> `c9f1a69`
* **Why**: Security compliance. Engineering inputs often contain developer names, email addresses, corporate IPv4 addresses, and internal network hostnames. These must never be transmitted to external LLM providers.
* **Technical Changes**:
  - Created `agents/threat_agent/pii.py` with compiled regex sanitizers:
    - Email addresses (`[\w.+-]+@[\w-]+\.[\w.-]+`) -> `[REDACTED_EMAIL]`
    - IPv4 addresses (`\b\d{1,3}(\.\d{1,3}){3}\b`) -> `[REDACTED_IP]`
    - Developer names / identities -> `[REDACTED_NAME]`
  - Wired into `_build_user_prompt()` before prompt assembly.
  - Emitted structured `pii_redacted_in_prompt` audit event recording the exact number of redacted items without ever logging the sensitive tokens.

### Stage 5: Confidence Scorer Extraction & Mathematical Grounding
* **Commits**: `f641d3d` -> `b034322`
* **Why**: The generator module was overcrowded. Calculating confidence scores requires an independent, mathematically validated signal formula that could be unit-tested in isolation.
* **Technical Changes**:
  - Extracted `compute_confidence_score()` into `agents/threat_agent/scorer.py`.
  - Formula:
    $$\text{Score} = \frac{1}{K} \sum_{k=1}^K \text{retrieval\_score}_k$$
  - Bound checking guaranteed strictly within $[0.0, 1.0]$.
  - Added dedicated unit tests in `tests/threat_agent/unit/test_scorer.py`.

### Stage 6: Router State Machine, Concurrency Locks & Persistent Run Store
* **Commits**: `d675044` -> `16e1e58` -> `d750d0e` -> `141ccf5`
* **Why**: The initial FastAPI router held state in an in-memory dictionary. If two reviewers hit `/approve` simultaneously across worker threads, race conditions occurred. Furthermore, restarting the backend wiped all running analyses.
* **Technical Changes**:
  - Defined strict state transitions: `pending_test` → `pending_human` → (`approved` | `rejected`).
  - Added HTTP `404 Not Found` for non-existent run IDs.
  - Added HTTP `409 Conflict` invariants:
    - Double approval on already-approved runs.
    - Double rejection on already-rejected runs.
    - Attempting to approve a rejected run, or reject an approved run.
  - Implemented `PostgresRunRegistryStore` backed by `threat_agent_runs` table with JSONB serialization.
  - Enforced atomic SQL-level conditional updates:
    ```sql
    UPDATE threat_agent_runs
    SET status = %(new_status)s, updated_at = now()
    WHERE run_id = %(run_id)s AND status = %(expected_status)s
    RETURNING *;
    ```
  - Retained `InMemoryRunRegistryStore` with `threading.Lock()` exclusively for lightning-fast unit tests (1.2 seconds) via FastAPI's `dependency_overrides`.

### Stage 7: Restoring the Automated Invariant Retry Loop
* **Commits**: `2fa35d4` -> `d5206a6` -> `5a07c07`
* **Why**: Foundational architectural requirement: *A threat scenario must pass automated protocol invariant checks before a human reviewer ever sees it.* An audit revealed that while `validator.py` had a retry helper, `router.py` only validated once and immediately surfaced failures to the user.
* **Technical Changes**:
  - Created `generate_and_validate_with_retry()` in `agents/threat_agent/orchestrator.py`.
  - Re-invokes **both** retrieval and generation when validation fails, prepending the validator's failure reason to the prompt so the LLM knows what to fix.
  - Capped at 3 automatic attempts (`MAX_VALIDATION_ATTEMPTS`).
  - Separated `validator_retry_count` (machine self-correction) from `human_rejection_count` (human feedback).
  - Added `validation_status`: `"passed"` vs `"escalated_after_retries"`.
  - Added `validator_retries_exhausted` structured audit event.

### Stage 8: API-Key Authentication on State-Changing Endpoints
* **Commits**: `de7863f` -> `3ff0b98`
* **Why**: Prevent unauthorized execution of expensive LLM queries and unauthenticated state mutations on the core pipeline.
* **Technical Changes**:
  - Added `THREAT_AGENT_API_KEY: SecretStr` to `config/settings.py` and `.env`.
  - Created `verify_api_key` FastAPI dependency using `secrets.compare_digest()` to prevent timing attacks.
  - Applied authentication dependency to:
    - `POST /api/v1/threat-agent/analyze`
    - `POST /api/v1/threat-agent/{run_id}/approve`
    - `POST /api/v1/threat-agent/{run_id}/reject`
  - Kept read-only endpoints (`GET /status`, `GET /scenarios`) open without auth for unprivileged telemetry and dashboard polling.
  - Emits HTTP `401 Unauthorized` with `{"detail": "Missing or invalid API key."}` on failure.

### Stage 9: Domain-Neutral E2E Validation on Safety-Critical Infusion Pump
* **Commits**: `4c71579` -> `f712998`
* **Why**: Prove the engine's domain-neutrality claim by running real, unmocked generation on an ISO 21434 / SIL-2 safety-critical medical device fixture (`tests/threat_agent/e2e/fixtures/infusion_pump/input.json`).
* **Technical Changes**:
  - Full execution of 20 live attack paths against both embedded firmware (`AS-1`) and hospital network interface (`AS-2`).
  - Uncovered and fixed two live LLM formatting edge cases:
    1. Unescaped JSON control characters (`\n`, `\t`) inside LLM string values -> fixed by adding `strict=False` to `json.loads()`.
    2. STRIDE Spoofing vocabulary gap: LLM generated "fabricated session credentials", which failed consistency check -> added `"fabricat"`, `"fabricated"` to `STRIDE_VECTOR_VOCABULARY[STRIDECategory.SPOOFING]`.
  - Created a permanent 11-assertion automated E2E test file: `tests/threat_agent/e2e/test_infusion_pump_e2e.py`.

---

## 4. Component-by-Component Technical Breakdown

### Input Parsing & Perception Layer
* **Module**: `agents/threat_agent/perceive.py` & `schemas.py`
* **Data Contract**: `ThreatAgentInput` contains:
  - `run_id`: Unique tracking ID (`RUN-xxx`).
  - `use_case`: System mission statement.
  - `system_model`: DFD JSON string defining data flows and trust boundaries.
  - `assets`: List of `AssetModel` records, capturing:
    - `interfaces`: Communication channels (e.g. `["BLE", "UART", "CAN bus", "Ethernet"]`).
    - `trust_zone`: Exposure level (`trusted`, `internal`, `external`, `untrusted`).
    - `security_attributes`: Boolean requirements for Confidentiality, Integrity, Availability, Authenticity.
    - `damage_scenario`: Safety, operational, or privacy impact.
* **Invariants**: Input models are validated by Pydantic before any downstream processing occurs. Schema errors immediately yield `422 Unprocessable Entity`.

### Vector Retrieval & Multi-KB Grounding
* **Module**: `agents/threat_agent/retrieval.py`
* **Taxonomies Indexed**:
  1. **CAPEC**: Common Attack Pattern Enumerations and Classifications (mechanisms of attack).
  2. **MITRE ATT&CK**: Enterprise and ICS tactics, techniques, and procedures (TTPs).
  3. **CWE**: Common Weakness Enumeration (underlying software and hardware flaws).
  4. **STRIDE Seed Rules**: Foundational mapping definitions.
* **Execution**:
  - `build_retrieval_plan()` maps asset security goals and interfaces to semantic queries.
  - `fetch_candidates()` executes pgvector similarity searches. If the database is unreachable, it logs a `retrieval_fallback_engaged` audit event and falls back to deterministic candidate stubs.

### Multi-Step Attack Chaining
* **Module**: `agents/threat_agent/attack_chain.py`
* **Algorithm**: Chaining connects external attack surface interfaces (e.g., `HL7 FHIR API`, `BLE`) to internal safety-critical assets (e.g., `Dosage Control Firmware`, `Sil-2 Motor Lock`).
* **Output**: Immutable `AttackPath` objects carrying ordered steps, pattern IDs, and chaining reasoning.

### Generation & Prompt Construction
* **Module**: `agents/threat_agent/generator.py`
* **Prompt Assembly**:
  - **System Prompt**: Enforces cybersecurity domain expertise, strict JSON array formatting, and prohibits hallucinations.
  - **User Prompt**: Injects redacted use case, redacted DFD context, target asset definitions, and the specific attack path sequence.
  - **Retry Context**: On automated retries, prepends:
    `IMPORTANT — THIS IS A RETRY. The previous generation attempt failed the Protocol Invariant Validator...`
* **Parser Robustness**:
  - Strips markdown triple-backtick fences (````json ... ````).
  - Uses `json.loads(clean_raw, strict=False)` to prevent crashes from literal whitespace control characters.
  - Validates all required keys: `asset_id`, `stride_category`, `attack_vector`, `kb_reference`, `exposure`, `matched_pattern`, `applicability_reason`, `citation`.

### Protocol Invariant Validator
* **Module**: `agents/threat_agent/validator.py`
* **The Four Mandatory Checks**:
  1. **Citation Presence (`CHECK_CITATION_MISSING`)**: Confirms `evidence_chain.citation` is non-empty and not a placeholder (`"tbd"`, `"none"`, `"n/a"`).
  2. **Schema Completeness (`CHECK_SCHEMA_INCOMPLETE`)**: Verifies required fields and validates that `applicability_reason` has $\ge 20$ characters.
  3. **STRIDE Consistency (`CHECK_CONSISTENCY_MISMATCH`)**: Compares `stride_category` against `attack_vector` vocabulary. If an attack vector says *"eavesdropping"* but the category is set to *Tampering*, it is flagged.
  4. **Non-Generic Evidence (`CHECK_EVIDENCE_GENERIC`)**: Detects boilerplate phrases like *"This vulnerability applies to this device."*

### Orchestration & Automated Self-Correction
* **Module**: `agents/threat_agent/orchestrator.py`
* **Loop Mechanics**:
  - Maximum 3 attempts.
  - If attempt 1 fails, `val.retry_with_context()` extracts the exact check ID and error message.
  - Both retrieval and generation are re-executed with failure context injected.
  - If valid: returns `status: "passed"` with `validator_retry_count: N`.
  - If 3 attempts exhaust: returns `status: "escalated_after_retries"` with `validator_retries_exhausted` audit event logged.

### Human Approval Gate & SCRS Persistence
* **Module**: `agents/threat_agent/router.py` & `scrp/state_manager.py`
* **API Endpoints**:
  - `POST /api/v1/threat-agent/{run_id}/approve`: Validates that the run is in `pending_human`. Commits scenarios to `SCRS_state.json` via `StateManager`. Moves state to `approved`.
  - `POST /api/v1/threat-agent/{run_id}/reject`: Requires `{ "reason": "..." }`. Increments `human_rejection_count`. Moves state to `rejected`.

---

## 5. Real-World Bugs Encountered & Engineering Solutions

| Bug / Challenge | Manifestation | Root Cause | Engineering Solution |
| :--- | :--- | :--- | :--- |
| **Windows Port Collision** | Postgres failed to start (`docker compose up`) | Local Windows host had a local PostgreSQL service bound to port `5432`. | Remapped external host port to `5433:5432` in `docker-compose.yml` and updated `DATABASE_URL` default. |
| **Circular Import / Incomplete Refactor** | `AttributeError: module generator has no attribute ...` | Legacy Phase 1 generator contained a `__getattr__` module shim masking missing symbols. | Completely removed `__getattr__`, audited symbol imports, and established strict typing. |
| **Missing Invariant Retry Loop** | Scenarios with validator errors were shown to human reviewers immediately. | Automated retry logic in `validator.py` was never invoked by `router.py`. | Created `generate_and_validate_with_retry()` in `orchestrator.py` to gate all generation before human exposure. |
| **Counter Conflation** | Machine validation retries overwrote human feedback counts. | Single `retry_count` integer tracked both machine retries and human rejections. | Split into `validator_retry_count` and `human_rejection_count` in PostgreSQL schema with backward-compatible aliases. |
| **State Transition Race Conditions** | Concurrent HTTP approvals could result in duplicate SCRS commits. | Application-level check-then-set logic (`if run.status == ...: run.status = ...`). | Implemented atomic SQL updates using `UPDATE threat_agent_runs ... WHERE status = 'pending_human' RETURNING *`. |
| **LLM Control Character Crash** | `JSONDecodeError: Invalid control character` during Infusion Pump run. | LLM generated literal unescaped `\n` or `\t` inside `applicability_reason`. | Added `strict=False` in `json.loads(clean_raw, strict=False)`. |
| **Natural Language Vocabulary Gap** | `CONSISTENCY_MISMATCH` on "fabricated session credentials". | `STRIDE_VECTOR_VOCABULARY[SPOOFING]` contained "forged", "spoof", but omitted "fabricated". | Added `"fabricat"` and `"fabricated"` to the Spoofing keyword vocabulary. |

---

## 6. Current Codebase Verification, Test Suite & Invariants

### Current Test Suite Health
* **Fast Test Suite (`pytest tests/ -q`)**:
  - **Status**: **232 passed, 9 skipped** (~35 seconds).
  - **Scope**: All unit tests, PII masking, validator rules, confidence calculations, mock generator fallback, and in-memory router lifecycle tests. Zero Docker dependencies required.
* **Live Integration Suite (`$env:TRC_INTEGRATION_TESTS="1"; pytest tests/ -q`)**:
  - **Status**: **252 passed, 0 skipped** (~75 seconds).
  - **Scope**: Live pgvector similarity search, PostgreSQL run store persistence, thread concurrency race conditions, and full Infusion Pump E2E execution.
* **Linter (`ruff check`)**:
  - **Status**: `All checks passed!` across `agents/`, `config/`, `scripts/`, and `tests/`.

### Verified Security Invariants
1. **Never Log Secrets**: `OPENAI_API_KEY`, `POSTGRES_PASSWORD`, and `THREAT_AGENT_API_KEY` are typed as Pydantic `SecretStr`. They cannot be leaked into stdout or logs via standard printing.
2. **Never Log Outbound PII**: Prompts containing system descriptions and user context are sanitized via `redact_pii_with_count()` before transmission to external model endpoints.
3. **No Unvalidated Scenarios Reach Humans**: Every scenario reaching `pending_human` has passed all 4 validator invariants, or carries the explicit flag `"escalated_after_retries"`.
4. **State Machine Immutability**: Terminal states (`approved`, `rejected`) are immutable. Calling `/approve` on an `approved` run strictly raises `409 Conflict`.

---

## 7. Downstream Hand-off: Guidance for the Risk Agent

The **Risk Agent** consumes the output of the Threat Agent once a run reaches the `approved` state. Here is what the Risk Agent engineer needs to know:

### Consuming Approved Threat Scenarios
Scenarios can be retrieved either via:
1. **API**: `GET /api/v1/threat-agent/{run_id}/scenarios`
2. **SCRS Store**: Reading the persisted entries in `SCRS_state.json` under key `SCRS-{run_id}`.

### Expected Data Fields per Scenario (`ThreatScenario`)
```json
{
  "tid": "THR-PATH-C3A33292-001",
  "asset_id": "AS-1",
  "stride_category": "Tampering",
  "attack_vector": "Exploitation of CAPEC-186 (Malicious Software Update) via injection targeting Dosage Control Firmware",
  "kb_reference": "CAPEC-186",
  "evidence_chain": {
    "exposure": "UART interface (trusted trust zone)",
    "matched_pattern": "CAPEC-186",
    "applicability_reason": "The asset 'Dosage Control Firmware' exposes UART interfaces in trusted zone, allowing an adversary to execute CAPEC-186 via injection.",
    "citation": "CAPEC-186: Malicious Software Update (CAPEC)"
  },
  "confidence_score": 0.7686,
  "status": "pending_test",
  "validation_status": "passed",
  "run_id": "RUN-INF-E2E-001"
}
```

### Key Considerations for Risk Modeling (Phase 2):
1. **Confidence Score as Risk Multiplier**: Scenarios include a normalized `confidence_score` $\in [0.0, 1.0]$. The Risk Agent can directly weight risk likelihood by this score.
2. **Escalation Flag Awareness**: If `validation_status == "escalated_after_retries"`, the scenario passed to the human after the machine struggled to satisfy protocol invariants. The Risk Agent should flag these for heightened human review.
3. **Asset Impact Mapping**: Every scenario links to a validated `asset_id`. The Risk Agent should look up the corresponding `AssetModel.damage_scenario` and `security_attributes` from the original input model to assess impact severity (Safety, Financial, Operational).
