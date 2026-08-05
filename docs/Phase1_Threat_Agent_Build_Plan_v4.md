# TRC Engine — Phase 1: Threat Agent
### SCRP-Based Threat–Risk–Compliance Engine | Build Plan (v4 — Industry-Hardened)

Building in series: **Threat Agent (this phase) → Risk Agent → Compliance Agent**. No work starts on Phase 2 until Phase 1 clears its Definition of Done below.

> **What changed in v4:** second domain fixture added (generality proof), confidence-scoring method defined, reproducibility stance documented, cross-domain KB/prompt testing added, secrets/config management added, LLM cost & rate controls added, structured logging format specified, Shriraj's workload rebalanced, week-by-week milestones added, dependency versions pinned, and two markdown formatting bugs from v3 fixed.

---

## 1. Goal

**What we're building:** The Threat Agent — the first stage of the TRC Engine. It takes a use case + system model (assets, data flows, trust boundaries) as input, retrieves relevant threat patterns from STRIDE/CAPEC/MITRE ATT&CK/CWE, proposes structured threat scenarios with evidence and confidence scores, validates its own output against a test-case gate (Protocol Invariant Validator), and — once it passes both that gate and human approval — writes the result into the Shared Cybersecurity Reasoning State (SCRS) for the Risk Agent to consume.

**Why it's required:** It's the entry point of the whole SCRP pipeline. Every downstream agent (Risk, Compliance) depends on the Threat Agent's output being well-formed, evidence-backed, and already validated — so getting this phase right is what makes the rest of the pipeline trustworthy rather than just fast.

**Critical design constraint (new):** This agent must work on **any** connected/cyber-physical system, not just the Smart Door Lock reference case. Smart Door Lock is a *test fixture*, never a target. Nothing in `prompts.py`, `retrieval.py`, or the KB schema may assume lock/BLE/IoT-specific structure. This is enforced in Section 6 via a second, deliberately different domain fixture.

---

## 2. System Design

### 2.1 Architecture (this phase's slice of the full system)

```
                 ┌─────────────────────────────────────────────┐
                 │              THREAT AGENT                    │
                 │                                               │
  Use Case  ───▶ │  ┌──────────────┐   ┌────────────────────┐  │
  System Model   │  │  Knowledge    │──▶│  Attack Chain       │  │
  (DFD/UML)      │  │  Retrieval    │   │  Analysis           │  │
                 │  └──────────────┘   └──────────┬───────────┘  │
                 │        ▲                        │              │
                 │        │                        ▼              │
                 │  ┌──────────────┐   ┌────────────────────┐  │
                 │  │  KB Store     │   │  Threat Scenario    │  │
                 │  │  STRIDE/CAPEC │   │  Generator (LLM)    │  │
                 │  │  ATT&CK/CWE   │   └──────────┬───────────┘  │
                 │  └──────────────┘              │              │
                 │                                 ▼              │
                 │                    ┌────────────────────────┐│
                 │                    │ Evidence & Confidence   ││
                 │                    │ Scorer                  ││
                 │                    └──────────┬─────────────┘│
                 │                                ▼               │
                 │                    ┌────────────────────────┐│
                 │                    │ Protocol Invariant      ││
                 │                    │ Validator (test gate)   ││
                 │                    └───────┬────────┬────────┘│
                 │                       pass  │        │ fail    │
                 │                            ▼        ▼         │
                 │                  ┌──────────┐  ┌────────────┐│
                 │                  │  Human    │  │  Retry loop ││
                 │                  │  Approval │  │  (Act+Reason)│
                 │                  └─────┬─────┘  └────────────┘│
                 └────────────────────────┼──────────────────────┘
                                           ▼
                              SCRS (Shared Reasoning State)
                          writes: threat_scenarios, evidence,
                          confidence_scores, audit_log entry
```

### 2.2 Data Flow

1. Orchestrator sends `{use_case, system_model, assets}` to Threat Agent.
2. **Perceive**: normalize input, redact any PII fields before anything touches the LLM.
3. **Reason & Plan**: identify which KB categories are relevant per asset/flow.
4. **Act/Fetch**: retrieve candidate patterns from KB store (STRIDE/CAPEC/ATT&CK/CWE), then run Attack Chain Analysis to link candidates into plausible multi-step paths.
5. **Observe**: LLM proposes threat scenarios with citations; Evidence & Confidence Scorer attaches a score to each using the defined methodology (Section 2.6).
6. **Produce**: assemble structured output → Protocol Invariant Validator runs test cases.
   - **Pass** → send to Human-in-the-Loop checkpoint.
   - **Fail** → retry: re-invoke Act/Fetch + Reason & Plan with failure reason as context (max 3 attempts, then escalate to human as flagged failure).
7. On human approval → write to SCRS → unblock Risk Agent.

### 2.3 Folder Structure

```
trc-engine/
├── agents/
│   └── threat_agent/
│       ├── __init__.py
│       ├── retrieval.py          # KB retrieval layer
│       ├── attack_chain.py       # Attack chain analysis (multi-step pathing)
│       ├── generator.py          # LLM threat scenario generation
│       ├── prompts.py            # LLM prompt templates (version controlled, multi-domain tested)
│       ├── scorer.py             # evidence & confidence scoring (method defined in 2.6)
│       ├── validator.py          # Protocol Invariant Validator (test gate)
│       ├── schemas.py            # Pydantic models for this agent's I/O
│       └── router.py             # FastAPI routes for this agent
├── scrp/
│   ├── state_manager.py          # SCRS read/write, versioning
│   ├── schemas.py                # shared state schema (all agents depend on this)
│   └── audit_logger.py
├── kb/
│   ├── loaders/                  # STRIDE/CAPEC/ATT&CK/CWE ingestion scripts
│   └── data/                     # raw + processed KB files (multi-domain coverage, not IoT-only)
├── config/
│   ├── settings.py               # pydantic-settings based config loader
│   └── .env.example              # documents required env vars, never committed with real values
├── tests/
│   └── threat_agent/
│       ├── unit/
│       ├── integration/
│       ├── e2e/
│       │   ├── fixtures/smart_door_lock/       # Fixture 1 — embedded/IoT domain
│       │   └── fixtures/infusion_pump/         # Fixture 2 — different domain (see 2.7)
├── common/
│   ├── llm_client.py             # OpenAI API wrapper; timeout, backoff, cost ceiling (2.8)
│   └── logging.py                # structured JSON logging (2.9)
└── docs/
    └── threat_agent.md           # includes scoring method, reproducibility stance, KB coverage notes
```

### 2.4 Class Design (core interfaces)

```python
class ThreatScenario(BaseModel):
    tid: str
    asset_id: str
    stride_category: str
    attack_vector: str
    kb_reference: str          # CAPEC/ATT&CK id
    evidence_chain: EvidenceChain
    confidence_score: float    # 0.0–1.0, derived per method in 2.6
    status: Literal["pending_test", "pending_human", "approved", "rejected"]

class EvidenceChain(BaseModel):
    exposure: str               # asset attribute creating exposure
    matched_pattern: str        # KB pattern id
    applicability_reason: str   # LLM-generated prose explicitly explaining WHY this pattern applies (crucial for explainability)
    citation: str

class ValidationResult(BaseModel):
    passed: bool
    failed_checks: list[str]
    retry_count: int = Field(le=3, description="Strictly capped at 3 retries to prevent infinite LLM loops")

class ThreatAgent:
    def perceive(self, input: ThreatAgentInput) -> NormalizedInput: ...
    def plan(self, input: NormalizedInput) -> RetrievalPlan: ...
    def fetch(self, plan: RetrievalPlan) -> list[KBCandidate]: ...
    def chain(self, candidates: list[KBCandidate]) -> list[AttackPath]: ...
    def observe(self, paths: list[AttackPath]) -> list[ThreatScenario]: ...
    def validate(self, scenarios: list[ThreatScenario]) -> ValidationResult: ...
    def retry(self, scenarios, failure: ValidationResult) -> list[ThreatScenario]: ...
    def produce(self, scenarios: list[ThreatScenario]) -> SCRSWriteResult: ...
```

### 2.5 API Design

| Endpoint | Method | Purpose |
|---|---|---|
| `/threat-agent/analyze` | POST | Submit use case + system model, run full Perceive→Produce loop |
| `/threat-agent/{run_id}/status` | GET | Poll run status (pending_test / pending_human / approved / rejected) |
| `/threat-agent/{run_id}/approve` | POST | Human approval action |
| `/threat-agent/{run_id}/reject` | POST | Human rejection + reason (triggers retry or escalation) |
| `/threat-agent/{run_id}/scenarios` | GET | Retrieve current threat scenario list for review |

### 2.6 Confidence Scoring Methodology (new — must be agreed before `scorer.py` is written)

Confidence is **not** a free-floating LLM guess. It is computed as a weighted combination of three deterministic-ish signals, so it is explainable and defensible in review:

1. **Retrieval-match strength (40%)** — similarity score between the asset/flow and the matched KB pattern (from FAISS distance, normalized to 0–1).
2. **Self-consistency (40%)** — generate the scenario N=3 times at low temperature; score = fraction of runs that agree on the same `stride_category` + `kb_reference` pair.
3. **Evidence completeness (20%)** — binary/graded check that `evidence_chain` has a non-empty `exposure`, `matched_pattern`, and a non-generic `applicability_reason` (checked by the Validator, not the LLM itself).

Final score = `0.4*retrieval_strength + 0.4*self_consistency + 0.2*evidence_completeness`, clamped to [0,1]. This formula, and the retrieval/self-consistency computation, must be documented in `docs/threat_agent.md` with a worked numeric example.

### 2.7 Reproducibility Stance (new — decide and document, don't leave implicit)

- `generator.py` calls the LLM at a **fixed low temperature (0–0.2)** to reduce run-to-run variance.
- Every run logs: prompt template version, model version string, KB snapshot version/hash, and the full input — enabling any output to be regenerated and audited later.
- Documented position for reviewers: *"Threat scenarios are evidence-grounded, cited, and human-approved. Exact wording is not guaranteed to be bit-identical across runs, but the underlying threat coverage and citations are consistent given the same KB snapshot and low-temperature generation."* This sentence goes verbatim into `docs/threat_agent.md` so the team has a ready, honest answer rather than an exposed gap.

### 2.8 LLM Client Hardening (new)

`common/llm_client.py` must implement, not just wrap the OpenAI API call:
- Request timeout (e.g. 30s) with a clear, typed exception on expiry.
- Retry-with-exponential-backoff on rate-limit/5xx errors (transport-level — distinct from the Validator's reasoning-level retry loop).
- A **per-run token/cost ceiling**; if exceeded, the run fails closed with a logged reason rather than looping silently.

### 2.9 Structured Logging Format (new)

All logging (`common/logging.py`) is JSON, one line per event, minimum fields on every entry:
```json
{"run_id": "...", "module": "generator", "step": "observe", "attempt": 1, "latency_ms": 842, "status": "ok", "timestamp": "..."}
```
This becomes queryable audit evidence beyond the SCRS `audit_log`, and satisfies Doc 1's "log prompts, retrieved KB chunks, model and prompt-template versions" requirement directly.

### 2.10 Secrets & Config Management (new)

- All secrets (OpenAI API key, DB credentials) loaded via `config/settings.py` using `pydantic-settings`, sourced from environment variables.
- `.env` is git-ignored; `.env.example` documents required variable names with placeholder values only.
- No secret ever appears in code, logs, or committed test fixtures.

---

## 3. Task Distribution — Phase 1 (Threat Agent)

| Member | Responsibilities | Deliverables | Files Owned | Collaboration Points |
|---|---|---|---|---|
| **Aryan** | Knowledge Base ingestion & retrieval layer + Attack Chain Analysis | Working `kb/loaders/` for STRIDE, CAPEC, ATT&CK, CWE covering **multiple domains** (not just embedded/IoT); FAISS vector DB for embeddings; `retrieval.py` returning ranked candidates given asset attributes; `attack_chain.py` linking candidates into multi-step paths | `kb/loaders/*`, `agents/threat_agent/retrieval.py`, `agents/threat_agent/attack_chain.py` | Confirms KB candidate schema with Chetan (consumed by generator.py); confirms KB-reference format with Chetan and Shriraj |
| **Chetan** | Threat Scenario Generator + Evidence & Confidence Scorer (LLM layer), tuned/tested across **both** fixtures | `generator.py` producing structured `ThreatScenario` objects; `scorer.py` implementing the Section 2.6 formula; `prompts.py` validated against both domain fixtures | `agents/threat_agent/generator.py`, `agents/threat_agent/scorer.py`, `agents/threat_agent/schemas.py`, `agents/threat_agent/prompts.py` | Depends on Aryan's retrieval/chain output format; hands validated-shape output to Shriraj's validator |
| **Shriraj** | Protocol Invariant Validator + retry loop + SCRS write interface for this agent | `validator.py` (test cases: citation presence, schema completeness, consistency checks, evidence-completeness scoring input); retry orchestration; `scrp/state_manager.py` write path for Threat Agent | `agents/threat_agent/validator.py`, `scrp/state_manager.py` (Threat Agent's write methods) | Defines the shared `ValidationResult` and SCRS write contract used by Risk Agent in Phase 2; syncs schema with Manthan |
| **Manthan** | API layer, PII Redaction Middleware, Human-in-the-Loop endpoints, config/secrets management, LLM client hardening, structured logging, test infra, CI/lint | `router.py` (FastAPI routes above); `middleware.py` (input sanitization before LLM invocation); `config/settings.py`; `common/llm_client.py` (timeout/backoff/cost ceiling); `common/logging.py` (JSON structured logs); approval/rejection endpoints; `tests/threat_agent/` scaffolding incl. both fixtures; CI pipeline (lint + test run on PR) | `agents/threat_agent/router.py`, `config/*`, `common/llm_client.py`, `common/logging.py`, `tests/threat_agent/*`, `.github/workflows/ci.yml` | Needs Shriraj's `ValidationResult` shape and Chetan's `ThreatScenario` shape to build endpoints and tests against |

> **Note on Cross-Run Learning:** the vector-DB reranking of human overrides (originally on Shriraj) is moved to a **Phase 1 stretch goal**, explicitly not required for the Definition of Done. It's genuinely a separate ML feature layered on top of a working validator/retry loop, and bundling it into Phase 1's critical path risked getting rushed near deadline. If time allows after DoD is green, Shriraj (or whoever finishes first) picks it up; otherwise it's the first item in Phase 1.5 / early Phase 2 prep.

### Day-1 Standalone Kickoff (before any code is written)

- [ ] Whole team agrees on `schemas.py` (Pydantic models: `ThreatScenario`, `EvidenceChain`, `ValidationResult`) together — freezes the data contract.
- [ ] Agree on and configure the linter (`ruff` for Python).
- [ ] Confirm `llm_client.py` strictly wraps the OpenAI API (no drift to unsupported local LLMs).
- [ ] Agree on the confidence-scoring formula (Section 2.6) and write it into `docs/threat_agent.md`.
- [ ] Agree on the reproducibility statement (Section 2.7) and write it into `docs/threat_agent.md`.
- [ ] Pick and document the second domain fixture (Section 2.11) so Aryan's KB ingestion and Chetan's prompt testing can target it from day 1, not bolt it on at the end.

**Sequencing within the phase:** Aryan and Manthan's foundational work (KB loaders, API scaffolding, config, test scaffolding) can start immediately in parallel. Chetan's generator depends on Aryan's retrieval interface being stubbed (function signature only) by day 2. Shriraj's validator depends on Chetan's `ThreatScenario` schema being finalized.

**No one is idle:** while waiting on a dependency, each member works on their own unit tests against their own module using mocked inputs matching the agreed schema, rather than blocking.

---

## 2.11 Second Domain Fixture (new — required, not optional)

Smart Door Lock alone cannot demonstrate the system is general-purpose — a single fixture proves nothing about generality, only that one path works. Add one more use case from a **meaningfully different domain**, e.g.:

- **Connected medical infusion pump** (BLE + hospital network + dosage-control firmware), or
- **Vehicle ECU / telematics unit** (CAN bus + cellular backend + OTA)

Requirements for the second fixture:
- Its own `{use_case, system_model, assets}` input, structured identically to Smart Door Lock's.
- KB coverage in `kb/data/` sufficient to surface real, relevant threats for it (not just embedded/IoT patterns) — verified as its own checklist item, distinct from "the code doesn't crash on it."
- `prompts.py` validated against **both** fixtures side-by-side; if the second fixture's output looks noticeably more generic or lower-quality, that's a prompt-engineering defect to fix before Phase 1 closes, not an acceptable gap.
- A dedicated e2e test (`tests/threat_agent/e2e/fixtures/infusion_pump/` or equivalent) required to pass for Phase 1 DoD, same as Smart Door Lock.

---

## 4. Git Workflow

### Branch Structure
```
main
 └── develop
      ├── feature/threat-agent-retrieval        (Aryan)
      ├── feature/threat-agent-generator         (Chetan)
      ├── feature/threat-agent-validator         (Shriraj)
      └── feature/threat-agent-api-tests         (Manthan)
```
Each feature branch merges into `develop` via PR. `develop` merges into `main` only at the end of Phase 1, once Definition of Done (Section 7) is met.

### Commit Message Convention (Conventional Commits)
```
feat(threat-retrieval): add CAPEC candidate ranking by asset attributes
feat(threat-chain): link candidates into multi-step attack paths
feat(threat-generator): implement structured threat scenario prompting
feat(threat-scorer): implement weighted confidence formula (retrieval+consistency+evidence)
feat(threat-validator): implement citation-presence test case
feat(scrp): define shared reasoning state schema for threat scenarios
feat(threat-api): add /threat-agent/analyze endpoint
feat(config): add pydantic-settings based secrets loading
feat(llm-client): add timeout, backoff, and cost ceiling
test(threat-retrieval): add unit tests for CAPEC ranking
test(threat-agent): add second-domain (infusion pump) e2e fixture
test(threat-validator): add edge cases for malformed evidence chains
fix(threat-generator): handle empty KB candidate list
docs(threat-agent): document confidence scoring and reproducibility stance
refactor(threat-scorer): extract calibration logic into separate function
```
No vague commits (`final`, `done`, `update`, `fix stuff`). Every commit describes what changed and in which module.

### Pull Request Rules
- All tests pass (unit + integration for that module) before requesting review.
- Linting passes (`ruff`, agreed day 1).
- At least one teammate reviews and approves before merge — reviewer should be someone whose module touches the same interface where possible (e.g. Manthan reviews Shriraj's validator since the API layer consumes it).
- No self-merges.

---

## 5. Coding Standards

- **SOLID + Clean Architecture**: each module (retrieval, attack chain, generator, scorer, validator, API) depends on interfaces (Pydantic schemas), not on each other's internals — so any one module can be reworked without breaking the others, as long as the schema contract holds.
- **Type safety**: full type hints, Pydantic models for all cross-module data.
- **Logging**: structured JSON logging (Section 2.9) at each of the 6 loop steps (Perceive/Plan/Fetch/Chain/Observe/Produce) — this becomes your audit trail for free.
- **Error handling**: every external call (LLM, KB store) wrapped with explicit handling for timeout, malformed response, and empty result — required given this is cybersecurity-adjacent and silent failures are unacceptable.
- **No duplicate code**: KB loading logic shared across STRIDE/CAPEC/ATT&CK/CWE loaders via a common base loader class.
- **No hardcoded secrets**: enforced via `config/settings.py`; CI should include a basic secret-scan step.
- **Dependency pinning**: `pyproject.toml`/`requirements.txt` pins exact versions for FastAPI, LangGraph, LangChain, FAISS, Pydantic — no floating ranges, to avoid four people building against silently different library versions.

---

## 6. Testing Requirements

### Unit Tests (per module, per owner)
| Module | Key test cases |
|---|---|
| Retrieval (Aryan) | Correct ranking given known asset attributes across **multiple domains**; empty KB match returns empty list, not an error; malformed asset input rejected with clear error |
| Attack Chain (Aryan) | Correctly links 2+ candidates into a plausible path; rejects/flags candidates with no plausible chain rather than forcing one |
| Generator (Chetan) | Produces valid `ThreatScenario` schema on **both** fixtures; handles LLM returning malformed JSON; handles LLM timeout |
| Scorer (Chetan) | Confidence score in valid 0–1 range; matches the Section 2.6 formula exactly (unit test with known inputs and expected output); low-evidence input yields low confidence, not a crash |
| Validator (Shriraj) | Each individual test case (citation presence, schema completeness, consistency, evidence completeness) independently triggers pass/fail correctly; retry counter increments correctly and caps at 3 |
| API (Manthan) | All endpoints return correct status codes; approval/rejection endpoints correctly transition state; config loader fails closed if required secret missing |
| LLM Client (Manthan) | Timeout raises typed exception; backoff triggers on simulated 429; cost ceiling halts run with logged reason |

### Integration Tests (interaction with SCRS)
- Threat Agent output correctly written to shared state after human approval, not before.
- Rejected output does **not** appear in shared state.
- Retry loop correctly re-invokes Fetch + Reason with prior failure context (verify the failure reason actually appears in the retry's input).

### End-to-End Tests (now two fixtures, not one)
- **Fixture 1 — Smart Door Lock**: use case in → threat list out → validator pass → human approval → SCRS write.
- **Fixture 2 — second domain (e.g. infusion pump)**: same full flow, independently verified — this is the generality proof, not a repeat of fixture 1.
- Full flow with an intentionally injected test-gate failure → confirm retry → confirm eventual pass or correct escalation to human after 3 failed attempts.

### Edge Cases (mandatory — cybersecurity project, no skipped cases)
- Invalid/malformed input JSON
- Missing required asset fields
- KB store unreachable (network failure simulation)
- LLM API failure / timeout / rate limit
- LLM returns a threat scenario referencing a non-existent asset
- Empty KB match (genuinely novel component with no pattern match)
- Duplicate threat proposals for the same asset/vector
- Confidence score at exact threshold boundary
- Run exceeding the token/cost ceiling

### Acceptance Criteria (per threat scenario output)
- **Input**: `{use_case, system_model, assets}` conforming to `schemas.py`, from either fixture domain
- **Expected Output**: list of `ThreatScenario` objects, each with a non-empty `evidence_chain`, a `confidence_score` in [0,1] computed per Section 2.6, and a `kb_reference` resolving to a real KB entry
- **Validation Rule**: no `ThreatScenario` reaches the human-approval stage without first passing all Validator checks

---

## 7. Definition of Done — Phase 1 (Threat Agent)

Phase 1 is complete, and Phase 2 (Risk Agent) may begin, only when **all** of the following hold:

- [ ] Retrieval, Attack Chain, Generator, Scorer, Validator, and API modules implemented per the schemas agreed on day 1
- [ ] Confidence-scoring formula (2.6) implemented exactly as documented, with a worked example in `docs/threat_agent.md`
- [ ] Reproducibility stance (2.7) documented in `docs/threat_agent.md`
- [ ] All unit tests passing for all modules, including multi-domain retrieval/prompt tests
- [ ] All integration tests passing (SCRS read/write behavior verified)
- [ ] **Both** end-to-end fixtures passing (Smart Door Lock **and** the second domain fixture)
- [ ] All edge cases above covered by tests, not just handled informally
- [ ] Secrets/config management in place — no credentials in code, logs, or commits
- [ ] LLM client hardening in place (timeout, backoff, cost ceiling) with tests
- [ ] Structured JSON logging in place across all loop steps
- [ ] Every feature branch code-reviewed and merged into `develop`
- [ ] Documentation (`docs/threat_agent.md`) describing the module, its schema, scoring method, reproducibility stance, KB domain coverage, and how Risk Agent should consume its SCRS output
- [ ] No critical/open bugs
- [ ] `develop` merged into `main` and tagged (e.g. `v0.1-threat-agent`)

Only after this checklist is fully green does Phase 2 (Risk Agent) start.

---

## 8. Suggested Week-by-Week Milestones (new — Phase 1 internal schedule)

| Week | Milestone |
|---|---|
| Week 1 | Day-1 kickoff complete (schemas frozen, scoring formula + reproducibility stance documented, second fixture chosen); KB loader + API scaffolding stubs in place; each member's module has a mocked-input unit test skeleton |
| Week 2 | Retrieval + Attack Chain functional against Fixture 1; Generator producing valid schema against Fixture 1; Validator implemented against mocked Generator output; config/secrets + LLM client hardening in place |
| Week 3 | Full pipeline integrated end-to-end on Fixture 1; Fixture 2 KB data + use case added; prompts tuned/tested against both fixtures; structured logging wired through all steps |
| Week 4 | Fixture 2 e2e passing; all edge cases covered; documentation complete; code review + merge to `main`; DoD checklist fully green |

If Week 2 checkpoint isn't met, treat Cross-Run Learning (moved to stretch goal) as officially deprioritized rather than letting it silently eat into Week 3/4 buffer.
