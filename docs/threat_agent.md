# Threat Agent — Internal Technical Documentation
**TRC Engine | Phase 1 Implementation Reference**  
*Document Version: 1.1 — Current as of main commit `2cf8d89`*

---

## 1. Overview

The **Threat Agent** is the foundational reasoning engine of Phase 1 of the TRC (Threat-Risk-Compliance) Engine. Its objective is to ingest a structured system model (hardware/software assets, network interfaces, trust boundaries, and communication flows), identify realistic threat vectors using authoritative vulnerability databases, synthesize end-to-end multi-step attack scenarios, validate those scenarios against formal protocol invariants, and present them for human approval before persisting approved scenarios to the **Shared Cybersecurity Reasoning State (SCRS)**.

### Architecture & Pipeline Stages
The design of the Threat Agent is executed as a closed-loop reasoning and validation cycle:
$$\text{Perceive} \longrightarrow \text{Reason \& Plan} \longrightarrow \text{Act / Fetch} \longrightarrow \text{Observe / Synthesize} \longrightarrow \text{Validate} \overset{\text{Auto-Retry (up to 3)}}{\longleftarrow\!\!\longrightarrow} \text{Human Gate} \longrightarrow \text{Produce}$$

The pipeline stages are orchestrated end-to-end:

1. **Perceive** (`agents/threat_agent/router.py`, `agents/threat_agent/schemas.py`): Validates raw JSON payloads against `ThreatAgentInput` using strict Pydantic schemas, normalizing asset interfaces, security attributes, and device configurations.
2. **Reason & Plan** (`agents/threat_agent/retrieval.py`): Deterministically derives target KB sources and builds an optimized semantic search query string for each asset based on trust zone and interface classification.
3. **Act / Fetch** (`agents/threat_agent/retrieval.py`): Executes pgvector cosine-distance queries against the PostgreSQL `threat_patterns` table, retrieving top-$k$ candidates.
4. **Attack Chaining** (`agents/threat_agent/attack_chain.py`): Synthesizes graph paths (`AttackPath`) connecting candidate threats from ingress points across trust zones to sensitive target assets.
5. **Observe / Synthesize** (`agents/threat_agent/generator.py`): Prompts an LLM (or deterministic fallback) with redacted asset and path context to generate structured `ThreatScenario` instances. Scored via `agents/threat_agent/scorer.py`.
6. **Validate & Automated Self-Correction Loop** (`agents/threat_agent/orchestrator.py`, `agents/threat_agent/validator.py`): Runs four independent invariant checks. If any scenario fails, `generate_and_validate_with_retry()` in `orchestrator.py` automatically re-invokes **both** evidence retrieval and generation with the failure context prepended, capped at 3 attempts, before human review.
7. **Produce & Human Gate** (`agents/threat_agent/router.py`, `scrp/state_manager.py`): Human reviewer inspects verified scenarios (with escalation flags visible if retries were exhausted), approves or rejects, and approved runs persist scenarios to the Shared Cybersecurity Reasoning State (SCRS).

#### Automated Invariant Validation & Retry Loop
The automated retry loop is implemented in `agents/threat_agent/orchestrator.py` via `generate_and_validate_with_retry()`:
* **Pre-human Invariant Gate**: Every scenario must pass the automated Protocol Invariant Validator before a human reviewer ever sees it.
* **Closed-Loop Self-Correction**: If validation fails on attempt 1, `validator.retry_with_context()` captures the failure details and emits the `validator_retry_triggered` audit event. The orchestrator re-executes both retrieval/chaining and generation, passing `validation_failure_context` directly to the LLM prompt so the model corrects the exact identified defects.
* **Capped Escalation**: The self-correction loop attempts up to 3 generation + validation iterations. If scenarios pass within 3 attempts, `validation_status` is marked `"passed"` and `validator_pass` is emitted. If still failing after 3 attempts, retries terminate, `validator_retries_exhausted` is emitted, and the run enters `pending_human` flagged with `validation_status: "escalated_after_retries"` so analysts immediately see that automated reasoning struggled.

---

## 2. Input Schema

The authoritative data contract for the Threat Agent input is defined in the **Group 1 Interface Contract** (`group1_interface_contract.md`, aligned with ISO 21434 / TARA system modeling standards).

### Ingestion Contract (`ThreatAgentInput`)
Defined in `agents/threat_agent/schemas.py`:
* `run_id`: `str` — Unique tracking identifier for this execution (e.g., `"RUN-SDL-001"`).
* `use_case`: `str` — High-level description of the system under analysis.
* `system_model`: `str` — Raw architectural model (DFD descriptions, trust boundary declarations, or Mermaid/PlantUML strings).
* `assets`: `list[AssetModel]` — Collection of target assets. Each `AssetModel` strictly requires:
  * `asset_id`: `str` — Sequential format `AS-{n}` (e.g., `"AS-1"`, `"AS-2"`). This acts as the foreign key for the Traceability Matrix.
  * `name`: `str` — Human-readable asset name (e.g., `"BLE Controller"`).
  * `location`: `str` — Physical or logical location (e.g., `"on-device"`, `"cloud-hosted"`).
  * `security_attributes`: `SecurityAttributes` — Four boolean CIAA flags:
    * `confidentiality`: `bool`
    * `integrity`: `bool`
    * `availability`: `bool`
    * `authenticity`: `bool`
  * `damage_scenario`: `str` — Worst-case consequence if compromised (used downstream by Risk Agent).
  * `dfd_context`: `DFDContext` — Data flow context:
    * `interfaces`: `list[str]` — Protocols and buses (e.g., `["BLE 5.0", "GATT"]`, `["UART", "CAN bus"]`).
    * `trust_zone`: `str` — Boundary classification (`"trusted"`, `"untrusted"`, `"external"`).
    * `data_flows`: `list[str]` — Flows terminating at or originating from this asset.
  * `device_config`: `dict[str, Any]` — Technical configurations (e.g., `{"auth": "PIN-only", "pairing": "unauthenticated"}`).

> [!WARNING]
> **Integration Status:** Group 1's automated system modeling output is **not yet integrated**. The engine currently executes against hand-authored reference fixtures located in `tests/threat_agent/e2e/fixtures/`:
> 1. `smart_door_lock/input.json` (Consumer BLE/Cloud smart lock)
> 2. `infusion_pump/input.json` (Connected medical drug delivery pump)

---

## 3. Knowledge Base & Vector Retrieval

The knowledge base consolidates four industry-standard taxonomies to provide defense-in-depth threat identification:

| Knowledge Base | Contribution to Threat Agent | Typical Scope |
| :--- | :--- | :--- |
| **STRIDE** | Core threat categorization (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). | Foundational threat taxonomy. |
| **CAPEC** | Common Attack Pattern Enumeration and Classification; maps attacker mechanisms and execution steps. | Exploit mechanisms, update tampering, sniffing. |
| **MITRE ATT&CK**| Real-world adversary tactics, techniques, and procedures (TTPs). | Network perimeter, cloud infrastructure, post-exploitation. |
| **CWE** | Common Weakness Enumeration; underlying architectural software/hardware flaws. | Missing authentication, buffer overflows, hardcoded keys. |

### Current Storage Engine: PostgreSQL + `pgvector`
The original Day-1 local FAISS flat binary index (`.bin`) has been **fully retired**. All embeddings are stored and queried live in PostgreSQL using the `pgvector` extension.

#### Table Schema (`threat_patterns`)
```sql
CREATE TABLE IF NOT EXISTS threat_patterns (
    id          SERIAL PRIMARY KEY,
    source      TEXT NOT NULL,           -- 'STRIDE' | 'CAPEC' | 'ATT&CK' | 'CWE'
    pattern_id  TEXT NOT NULL,           -- e.g. 'CWE-306', 'CAPEC-186'
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    embedding   vector(384) NOT NULL,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (source, pattern_id)
);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_source ON threat_patterns (source);
```

### Trust-Zone & Interface KB Filtering
Querying all four KBs for every asset produces noisy, irrelevant candidates (e.g., searching enterprise network attack techniques for a sealed cryptographic chip). `agents/threat_agent/retrieval.py` applies deterministic heuristics (`_select_kb_sources`) before searching:
* **Core Sources (`CAPEC`, `STRIDE`)**: Always included for every asset.
* **`ATT&CK`**: Added only if the asset is network-facing (keywords: `"api"`, `"rest"`, `"cloud"`, `"http"`, `"backend"`, `"endpoint"`).
* **`CWE`**: Added for programmable or firmware assets (keywords: `"firmware"`, `"embedded"`, `"ota"`, `"driver"`, `"software"`).
* **Wireless Triggers**: Any wireless interface (`"ble"`, `"wifi"`, `"zigbee"`, `"cellular"`) forces both `ATT&CK` and `CWE` inclusion.
* **Untrusted Trust Zones**: Assets in `"untrusted"` or `"external"` zones automatically search all 4 sources.
* **Sealed / Trusted Hardware**: For a trusted hardware asset with no wireless or network interfaces (e.g., `AS-2: Secure Element` on `I2C/SPI`), `ATT&CK` and `CWE` are **skipped**. The engine queries only `CAPEC` and `STRIDE` because post-exploitation enterprise techniques and software CWEs are irrelevant to a physical security module.

### Embedding Model & Distance Metric
* **Model**: `sentence-transformers/all-MiniLM-L6-v2` generating 384-dimensional unit-normalized embeddings.
* **Similarity Metric**: Cosine distance using pgvector's `<=>` operator:
  $$\text{Cosine Similarity} = 1.0 - (\vec{u} \Leftrightarrow \vec{v})$$
  Because vectors are $L_2$-normalized, cosine distance is strictly in $[0.0, 2.0]$, and similarity evaluates cleanly to $[0.0, 1.0]$.

### Graceful Fallback & Audit Trail (`retrieval_fallback_engaged`)
If PostgreSQL or the `pgvector` store is unreachable during pipeline orchestration (e.g. running offline unit tests without Docker or during infrastructure network outages), `_execute_retrieval_and_chaining()` in `agents/threat_agent/orchestrator.py` catches `KBStoreUnreachableError`.

To guarantee that a degraded run **never looks identical to a normal run in the audit trail**:
1. It immediately records a structured audit event:
   ```json
   {
     "step": "retrieval_fallback_engaged",
     "run_id": "RUN-SDL-001",
     "payload": {
       "error_type": "KBStoreUnreachableError",
       "reason": "Connection refused",
       "query_count": 2
     }
   }
   ```
2. It synthesizes structured fallback candidate stubs mapped to each asset query so pipeline execution can continue deterministically without unhandled crashes.

---

## 4. Scenario Generation & LLM Client

Threat scenario synthesis is performed by `agents/threat_agent/generator.py` using `common/llm_client.py`.

### OpenRouter Integration (Documented Deviation from Synopsis)
The original project synopsis cited direct OpenAI integration (`gpt-4o`). The implementation has deliberately deviated to use **OpenRouter** (`https://openrouter.ai/api/v1`) via the OpenAI-compatible SDK client:
* **Rationale**: Sourcing LLM completions through OpenRouter decouples the engine from a single vendor, allowing flexible model routing (e.g., DeepSeek, Claude 3.5 Haiku, Llama 3) based on cost, reasoning capability, and availability, without requiring application code changes.
* **Implementation**: If `settings.OPENAI_API_KEY` starts with `sk-or-`, `common/llm_client.py` automatically redirects the base URL to `https://openrouter.ai/api/v1`.
* **Configured Default Model**: Sourced via the `TRC_LLM_MODEL` environment variable or `settings.OPENAI_MODEL`, defaulting to `gpt-4o-mini` (`agents/threat_agent/generator.py:83`). The low-level fallback constant `_DEFAULT_MODEL = "gpt-4o"` in `common/llm_client.py:106` applies only when the client is invoked without an explicit model parameter.

### `USE_LIVE_LLM` Operating Modes
Controlled via `config/settings.py` or the `USE_LIVE_LLM` environment variable:
* `USE_LIVE_LLM=true` (Default): Sends redacted prompts to the live LLM API.
* `USE_LIVE_LLM=false`: Engages `_deterministic_fallback_for_path()` in `generator.py`. This uses deterministic templates to assemble valid, schema-compliant `ThreatScenario` objects. Designed for offline testing, CI environments, and presentation stability.

### Graceful Fallback & Audit Trail
If live LLM generation fails due to:
1. Network timeouts (`LLMTimeoutError` after 30s)
2. Rate limits or transient API errors (`429`, `5xx`) after 3 exponential backoff attempts (1s, 2s, 4s)
3. Malformed JSON returned by the model

The generator **does not crash**. It catches the exception, logs a structured audit event `llm_fallback_engaged` with the error detail, and automatically engages the deterministic fallback generator to produce valid scenarios.

---

## 5. Privacy & Outbound PII Redaction

The TRC Engine maintains a strict dual-boundary security model for sensitive data:

```
+-------------------------------------------------------------------------------+
| Outbound Prompt Path (common/pii_redaction.py)                                 |
| Raw Input -> Regex Scrubbing -> Masked Text -> External LLM Provider (Cloud) |
+-------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------+
| Application Log Path (common/logging.py)                                      |
| Internal Execution -> Key-Name Scrubbing -> "***REDACTED***" -> Local Disk   |
+-------------------------------------------------------------------------------+
```

These are two distinct mechanisms built for different threat surfaces:
1. **Outbound PII Redaction (`common/pii_redaction.py`)**: Prevents customer intellectual property, private networks, and credentials from escaping the local perimeter to external cloud LLM APIs.
2. **Log Redaction (`common/logging.py`)**: Prevents passwords, tokens, and secret keys from being written into local disk logs or forwarded to central log aggregators.

### Redacted Entities
Before prompts are dispatched to OpenRouter, `common/pii_redaction.py` scans all free-text fields (`use_case`, `system_model`, `damage_scenario`, and `device_config` structures):
* **Email Addresses**: RFC 5322 regex $\rightarrow$ `[REDACTED_EMAIL]`
* **Phone Numbers & Numeric Strings**: Punctuated phone formats and raw 10–12 digit numeric strings $\rightarrow$ `[REDACTED_PHONE]`
* **Government IDs / SSN**: 9-digit hyphenated patterns $\rightarrow$ `[REDACTED_GOV_ID]`
* **IPv4 Addresses**: Standard 4-octet dot notation $\rightarrow$ `[REDACTED_IP]`

### The Numeric-String False-Positive Tradeoff
The regex `\b\+?\d{10,12}\b` conservatively classifies raw 10–12 digit numbers as phone numbers. In IoT device configurations, hardware serial numbers or chip identifiers matching this length will be masked as `[REDACTED_PHONE]`.
* **Current Status**: Both canonical fixtures (`smart_door_lock` and `infusion_pump`) were audited and confirmed free of 10–12 digit numeric strings.
* **Documented Limitation**: If future system models declare raw 10-digit serial numbers in `device_config`, they will be redacted. This is an accepted engineering tradeoff: false-positive redaction of a serial number is preferable to leaking private contact information to a third-party LLM API.

### Audit Invariant
When redactions occur, `generator.py` emits an audit event:
```json
{
  "step": "pii_redacted_in_prompt",
  "run_id": "RUN-SDL-001",
  "payload": { "path_id": "PATH-45B30109", "redaction_count": 2 }
}
```
**Audit invariant:** The logger records *only the integer count* of redacted items, never the sensitive text itself.

---

## 6. Confidence Scoring

Confidence scoring logic is isolated in `agents/threat_agent/scorer.py`.

### Current Derivation (Code Reality)
In the current code baseline, `compute_confidence_score()` calculates the arithmetic mean of the `retrieval_score` values across all steps in the scenario's underlying `AttackPath`:
$$\text{Confidence Score} = \text{clamp}_{[0.0, 1.0]}\left(\frac{1}{N} \sum_{i=1}^{N} \text{retrieval\_score}_i\right)$$
* If steps or scores are missing, it defaults safely to `0.0`.
* Float results are clamped defensively to $[0.0, 1.0]$ via `max(0.0, min(1.0, float(raw_mean)))`.
* `LOW_CONFIDENCE_THRESHOLD = 0.4` (in `scorer.py`).

> [!NOTE]
> **Future Expansion Formula:** The multi-signal formula ($0.4 \cdot \text{retrieval} + 0.4 \cdot \text{consistency} + 0.2 \cdot \text{completeness}$) described in §2.6 of the build plan remains documented in `scorer.py` comments for integration once multi-pass LLM self-consistency is wired in Phase 2.

### Deliberate Design: Validator Does NOT Gate on Confidence
The Protocol Invariant Validator intentionally does **not** reject scenarios with low confidence scores.
* **Why**: A low retrieval score does not mean a threat is invalid; it may mean the device uses a novel or proprietary architecture with low semantic similarity to existing CVE descriptions.
* **Human-in-the-Loop Contract**: The confidence score is computed, attached to `ThreatScenario.confidence_score`, and explicitly presented to the human reviewer at Stage 6 with a warning flag if below threshold. The decision to accept or reject an unusual or low-similarity threat is strictly reserved for the human security analyst.

---

## 7. Protocol Invariant Validator

Located in `agents/threat_agent/validator.py`, the validator gates scenarios before they reach the human approval step. All checks are pure, stateless functions returning `(bool, FailedCheck | None)`.

### The 4 Implemented Invariant Checks

| Check ID | Method | Invariant Enforced |
| :--- | :--- | :--- |
| `CITATION_MISSING` | `citation_presence_check()` | `evidence_chain.citation` must be non-empty and cannot be a generic placeholder (`"n/a"`, `"tbd"`, `"none"`, `"unknown"`). |
| `SCHEMA_INCOMPLETE` | `schema_completeness_check()`| All 5 core fields must be populated with non-whitespace strings: `tid`, `asset_id`, `stride_category`, `attack_vector`, `kb_reference`. |
| `CONSISTENCY_MISMATCH`| `consistency_check()` | The lowercased `attack_vector` string must contain at least one recognized keyword fragment corresponding to its `stride_category` from `STRIDE_VECTOR_VOCABULARY`. |
| `EVIDENCE_GENERIC` | `evidence_completeness_check()`| `evidence_chain.exposure` and `matched_pattern` must be non-empty. `applicability_reason` cannot be a placeholder and must be $\ge 20$ characters. |

### Retry & Escalation Behavior
When validation fails:
1. All failures are collected into a `ValidationResult(passed=False, failed_checks=[...])`.
2. Automated retry orchestration is executed by `generate_and_validate_with_retry()` in `agents/threat_agent/orchestrator.py`:
   - **Attempts 1–2**: `validator.retry_with_context()` extracts failure reasons, the orchestrator logs the `validator_retry_triggered` audit event, and automatically re-invokes **both** evidence retrieval and scenario generation with `validation_failure_context` injected into the prompt.
   - **Successful attempt**: When all scenarios satisfy invariants within 3 attempts, `validation_status` is marked `"passed"`, each scenario receives `validation_status = "passed"`, and the orchestrator emits the `validator_pass` audit event.
   - **Exhausted retries (3 failed attempts)**: If validation still fails on attempt 3, retries terminate. The orchestrator emits the `validator_retries_exhausted` audit event with the full list of failed checks, sets `validation_status = "escalated_after_retries"` on the run record and on each scenario, and routes the run to `pending_human`. Human reviewers can immediately see that automated reasoning struggled and inspect the flagged failure details.

### Metric Disambiguation: Validator Retries vs. Human Rejections
The engine strictly disambiguates automated self-correction cycles from human decisions:
* **`validator_retry_count`**: Integer ($0 \le n \le 3$) recording the number of automated retry loops executed during the pre-human generation and validation phase.
* **`human_rejection_count`**: Integer recording how many times a human security analyst called `POST /reject` to send the run back for revision.
* **`retry_count`**: Maintained as an explicit alias to `human_rejection_count` across API responses and database models for full backward compatibility.

---

## 8. Run Lifecycle & FastAPI REST API

The threat analysis lifecycle is governed by the state machine implemented across `agents/threat_agent/schemas.py`, `agents/threat_agent/run_store.py`, and `agents/threat_agent/router.py`.

### Lifecycle State Machine (`ThreatStatus`)
The lifecycle states defined in `ThreatStatus(StrEnum)` are:
* `pending_test`: Run accepted, analysis/validation in progress.
* `pending_human`: Invariant validation passed; scenarios are staged awaiting human approval.
* `approved`: Terminal state; human approved run, scenarios persisted to SCRS.
* `rejected`: Terminal state; human rejected run with a reason string.

```
                  ┌──────────────┐
                  │ POST /analyze│
                  └──────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ pending_test  │
                 └───────┬───────┘
                         │
                         ▼ (Validator pass)
                ┌────────────────┐
                │ pending_human  │
                └───┬────────┬───┘
     Approve (y)    │        │    Reject (n)
   ┌────────────────┘        └────────────────┐
   ▼                                          ▼
┌──────────────┐                       ┌──────────────┐
│   approved   │                       │   rejected   │
│(Writes SCRS) │                       │ (Terminated) │
└──────────────┘                       └──────────────┘
```

### Endpoints Specification

| Method & Path | Purpose | Request Body | Headers | Response (Success) | Error Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/threat-agent/analyze` | Initiates threat analysis run. | `ThreatAgentInput` | `X-API-Key` (Required) | `202 Accepted` (`AnalyzeResponse` with `run_id`, `status: pending_test`) | `401` (Unauthorized), `422` (Schema error), `500` |
| `GET /api/v1/threat-agent/{run_id}/status` | Polls current run status. | None | None (Open) | `200 OK` (`RunStatusResponse` with `run_id`, `status`, `validator_retry_count`, `human_rejection_count`, `validation_status`) | `404` (Unknown run), `500` |
| `GET /api/v1/threat-agent/{run_id}/scenarios` | Retrieves generated scenarios. | None | None (Open) | `200 OK` (`ScenariosResponse` with `run_id`, `scenarios: list`) | `404` (Unknown run), `500` |
| `POST /api/v1/threat-agent/{run_id}/approve` | Approves run; commits to SCRS. | None | `X-API-Key` (Required) | `200 OK` (`ApproveResponse` with `status: approved`, `scrs_entry_id`) | `401` (Unauthorized), `404`, `409` (Conflict), `500` |
| `POST /api/v1/threat-agent/{run_id}/reject` | Rejects run with documented reason. | `RejectRequest` (`reason: str`) | `X-API-Key` (Required) | `200 OK` (`RejectResponse` with `status: rejected`, `retry_count`, `human_rejection_count`) | `401` (Unauthorized), `404`, `409` (Conflict), `422`, `500` |

### Authentication & Protected Endpoints

* **Authentication Scheme**: Shared secret API key passed via the `X-API-Key` HTTP header. Sourced from the application configuration (`THREAT_AGENT_API_KEY` typed as `SecretStr` in `config/settings.py` / `.env`).
* **Protected Endpoints (`POST /analyze`, `POST /{run_id}/approve`, `POST /{run_id}/reject`)**: State-changing and model-invoking operations enforce authentication via FastAPI dependency `verify_api_key`. Constant-time comparison (`secrets.compare_digest`) prevents timing attacks.
* **Open Endpoints (`GET /{run_id}/status`, `GET /{run_id}/scenarios`)**: Read-only polling endpoints remain unauthenticated. This allows frontend polling loops, status monitoring dashboards, and telemetry scrapers to query run progression without exposing or distributing privileged administrative API keys.
* **Failure Response**: Any unauthenticated or invalidly authenticated request to a protected endpoint immediately yields `401 Unauthorized` with `{"detail": "Missing or invalid API key."}` and `WWW-Authenticate: ApiKey`.

### Error Contract: 404 vs. 409 Invariants
* **HTTP 404 (Not Found)**: Returned whenever operations reference a `run_id` that does not exist in the database or historical state store.
* **HTTP 409 (Conflict)**: Enforces the state machine. Raised under three strict conditions:
  1. **Double Approval**: Calling `/approve` on a run already in `approved`.
  2. **Double Rejection**: Calling `/reject` on a run already in `rejected`.
  3. **Cross-Terminal Transitions**: Calling `/approve` on a `rejected` run, or `/reject` on an `approved` run.

### Persistent Storage & SQL-Level Atomicity
* **Default Store (`PostgresRunRegistryStore`)**: The production app in `main.py` defaults directly to `PostgresRunRegistryStore` with zero dependency overrides. Active runs, retry counters, validation statuses, and scenario trees are persisted in the `threat_agent_runs` table:
  ```sql
  CREATE TABLE IF NOT EXISTS threat_agent_runs (
      run_id                TEXT PRIMARY KEY,
      status                TEXT NOT NULL,
      scenarios             JSONB NOT NULL DEFAULT '[]'::jsonb,
      retry_count           INTEGER NOT NULL DEFAULT 0,
      validator_retry_count INTEGER NOT NULL DEFAULT 0,
      human_rejection_count INTEGER NOT NULL DEFAULT 0,
      validation_status     TEXT,
      scrs_entry_id         TEXT,
      created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  ```
  Schema migrations are applied idempotently on engine startup via `ALTER TABLE threat_agent_runs ADD COLUMN IF NOT EXISTS ...` to support zero-downtime rolling upgrades.
* **Process-Restart Durability**: Because scenarios are stored as `JSONB`, all generated scenarios and metadata survive application crashes and server restarts.
* **SQL-Level Atomicity**: State transitions avoid application-level check-then-set race conditions by executing as a single atomic query:
  ```sql
  UPDATE threat_agent_runs
  SET status = %(new_status)s, scrs_entry_id = %(scrs_entry_id)s, updated_at = now()
  WHERE run_id = %(run_id)s AND status = %(expected_status)s
  RETURNING *;
  ```
  If two reviewers hit `/approve` simultaneously across worker processes, exactly one transaction succeeds (`200 OK`) and the other returns `409 Conflict`.
* **Testing Store (`InMemoryRunRegistryStore`)**: Exists solely to allow fast unit and integration tests (`tests/threat_agent/integration/test_router.py`) to run in ~1.2 seconds without requiring a live PostgreSQL instance, wired via FastAPI's `app.dependency_overrides`.

---

## 9. Downstream Consumption Contract: Guide for the Risk Agent

This section defines how the **Risk Agent** (Phase 2) must consume Threat Agent outputs.

### 1. Where to Find Approved Threats
Approved scenarios are located in two places:
1. **Primary SCRS Store**: Managed by `scrp/state_manager.py`. Calling `StateManager().get_threat_scenarios()` returns a dictionary of scenarios keyed by `tid`.
2. **Postgres Run Registry**: Querying `threat_agent_runs` where `status = 'approved'` retrieves the `scenarios` JSONB array for any specific `run_id`.

### 2. Filtering Contract
The Risk Agent **must filter strictly on `status == ThreatStatus.APPROVED` (`"approved"`)**. Scenarios in `pending_test` or `pending_human` have not received human authorization and must never be used for risk calculation or compliance reporting.

### 3. Scenario Field Guarantees
Every approved `ThreatScenario` guaranteed by the Protocol Invariant Validator contains:

| Field Name | Type | Invariant Guarantee | Usage in Risk Agent |
| :--- | :--- | :--- | :--- |
| `tid` | `str` | Unique string (format `THR-<run_id>-<seq>`). | Primary key in Risk Register. |
| `asset_id` | `str` | Matches `AS-{n}` from input model. | Foreign key to Asset Table for impact evaluation. |
| `stride_category` | `STRIDECategory` | Valid STRIDE enum value. | Determines threat classification and threat event type. |
| `attack_vector` | `str` | Non-empty specific description. | Used to determine attack likelihood and exploit feasibility. |
| `kb_reference` | `str` | Valid ID (e.g., `"CWE-306"`, `"CAPEC-186"`). | Cross-references external vulnerability databases for CVSS/scoring. |
| `evidence_chain` | `EvidenceChain` | Object containing `exposure`, `matched_pattern`, `applicability_reason`, `citation`. | Feeds into risk justification and audit reporting. |
| `confidence_score`| `float` | Guaranteed float clamped to $[0.0, 1.0]$. | Weighting factor for likelihood calculation. |
| `validation_status` | `str \| None` | `"passed"` when all invariants passed on first or retry attempt; `"escalated_after_retries"` when 3 automated retry attempts were exhausted before human review. | Risk Agent **must** treat `"escalated_after_retries"` scenarios with the same or greater scrutiny as low-confidence ones — both signals indicate the system itself was not fully confident about the scenario's quality or correctness without additional context. |
| `status` | `ThreatStatus` | Guaranteed to be `ThreatStatus.APPROVED`. | Gatekeeper check. |
| `created_at` | `datetime` | UTC timestamp. | Audit trail timestamp. |
| `run_id` | `str` | Associated run identifier. | Traceability across reasoning loops. |

### 4. Handling Confidence Scores in Risk Modeling
Because the Threat Agent deliberately does not filter out low-confidence threats (leaving that judgment to the human reviewer), the Risk Agent should define its own policy:
* **High Confidence ($\ge 0.70$)**: Standard automated likelihood scoring based on KB metrics.
* **Low Confidence ($< 0.70$)**: The Risk Agent may apply a discount factor to threat likelihood or flag the resulting risk scenario for mandatory senior risk officer review.
* **Escalated Scenarios (`validation_status == "escalated_after_retries"`)**: The Threat Agent's automated validator loop exhausted all 3 retry attempts before the scenario reached the human reviewer. The Risk Agent should treat these scenarios with the same or greater scrutiny as low-confidence ones (`confidence_score < 0.70`), since both signals — low retrieval confidence and validator-exhausted escalation — indicate the system itself was uncertain about the scenario's quality and correctness.

---


## 10. Known Limitations

1. **Group 1 Automated Model Extraction Not Integrated**: The pipeline runs exclusively against hand-authored JSON fixtures (`smart_door_lock`, `infusion_pump`). Parsing automated DFD diagrams from Group 1 remains an outstanding integration task.
2. **Model Vendor Routing via OpenRouter**: As documented in Section 4, the engine uses OpenRouter instead of direct OpenAI APIs.
3. **PII Redaction False-Positive Tradeoff**: Serial numbers or hardware addresses consisting of 10 to 12 contiguous digits are conservatively masked as `[REDACTED_PHONE]`.
4. **Synchronous Single-Process Execution**: The FastAPI endpoint `/analyze` initiates execution synchronously in the local thread rather than dispatching to an asynchronous Celery/Redis task queue. Under heavy load, worker processes could block.
5. **Flat-File SCRS Default**: While run metadata is persisted in PostgreSQL (`threat_agent_runs`), the legacy `StateManager` still defaults to writing approved scenarios to `SCRS_state.json` on disk. Unifying the SCRS store fully into PostgreSQL relational tables is scheduled for Phase 2.

---

## 11. Test Suite & Verification Reference

The codebase maintains strict separation between fast unit tests and containerized integration tests.

### Test Split Overview
* **Fast Test Suite (Zero Docker required)**:
  * Runs all unit tests, PII scrubbing tests, validator rules, confidence scorer tests, API authentication guards, and router lifecycle tests (using `InMemoryRunRegistryStore`).
  * Execution time: **~28 to 42 seconds** (234 passed, 20 skipped).
* **Live Integration Suite (`TRC_INTEGRATION_TESTS=1`)**:
  * Executes live pgvector similarity searches against PostgreSQL, tests table migrations, and runs multi-threaded concurrent race-condition tests against `threat_agent_runs`.
  * Execution time: **~75 to 90 seconds** (254 passed).

### Local Execution Commands

#### 1. Running the Fast Suite (No Docker)
```powershell
pytest tests/ -q
```

#### 2. Running the Full Integration Suite (with Docker)
Ensure the PostgreSQL container is started:
```powershell
docker compose up -d postgres
```
Run the complete suite with the integration gate enabled:
```powershell
python -c "import os, subprocess, sys; env = dict(os.environ, TRC_INTEGRATION_TESTS='1'); res = subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-q'], env=env); sys.exit(res.returncode)"
```
Shut down containers when finished:
```powershell
docker compose down
```
