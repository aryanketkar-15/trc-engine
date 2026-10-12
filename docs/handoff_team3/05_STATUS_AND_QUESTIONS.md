# 05 · Honest status, limits, and what we need from Team 3

## 1. Status (12 Oct 2026)

| Area | Status |
|---|---|
| Threat Agent core (search → generate → check → human approve/reject/discard/add → store) | **working**, over 300 automatic tests pass |
| Knowledge base | 2,300 patterns from free MITRE catalogues (CAPEC 556, ATT&CK 794, CWE 944, STRIDE 6) + 5,097 standards text pieces |
| Safety rules | redaction of secrets/PII before the AI call; no invented citations; every decision logged |
| Command-line demo | `python scripts/scrp_demo.py` (pick a project, review scenarios, approve/reject, run again) |
| REST API | working (`/api/v1/threat-agent/...`) |
| Link to Team 1 (real asset tables) | **not built**: needs their latest branches merged and an adapter (file 01) |
| Writing results into Team 1's database and audit chain | **not built** |
| Risk Agent / Compliance Agent | **not built** (file 04 is a proposal) |
| Multi-step attack chains | **not built**: each scenario is based on a single catalogue pattern |

## 2. Quality: what we can and cannot say

* On the company's own six reference threats for the door lock we match **1 of 6** at our similarity threshold
  (two more are close). The free catalogues are generic; the company's internal patterns are not in them.
* The automatic checker wrongly accepts 15.38 % and wrongly rejects 8.33 % of a 50-scenario test set.
* So: **treat every scenario as a reviewed proposal, not a fact.** The human approval is the quality gate.
* We do not claim complete threat coverage of an asset.

## 3. Known limits that affect you

1. `confidence_score` is evidence-match strength, not likelihood.
2. `use_case_id` is derived from the use-case text until Team 1's `usecase_id` is wired in.
3. `kb_snapshot_version` is a label (`latest`), not a content hash.
4. The audit log is a plain file, not tamper-evident, and has no approver identity yet.
5. Threats for assets with little context (for example engineer-named assets such as user PII) will be less specific.
6. Sample data is for the smart door lock and an infusion pump only.

## 4. Questions for Team 3

1. Which of our attributes do you need that we do not have (name, meaning, which agent needs it)?
2. How should requirements reference threats: by `tid`, by `kb_reference`, or by asset? (We suggest `tid`.)
3. How do you want to receive data: REST API, the shared database table, or exported JSON files?
4. Do you need only approved threats, or also rejected / pruned ones for the audit report?
5. What ID format will your requirements use (`SR-01` as in the company document)? We will keep it in our links.
6. Do you want us to add a field for "treatment decision" now (from Risk) or later?
7. When Team 1's real asset tables are available, can you share the integrated test session with us?
8. Is there a template for the TARA report so we can shape `evidence_chain` text to what you can quote?

## 5. What we will do next

1. Get Team 1's latest branch / a sample session; build the adapter and test on the door-lock example.
2. Write results into the shared database and audit chain (with approver identity).
3. Risk Agent design with the company's tables; agree attributes with you first (file 04).
