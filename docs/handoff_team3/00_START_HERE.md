# Team 2 (Threat · Risk · Compliance) → Team 3: handoff package

*From: Team 2, group TY-A9 (VIT Pune, guide Dr. Vidya Gaikwad). For: Team 3 (Requirements, Trace/Audit,
Consistency). Date: 12 Oct 2026. Please tell us if anything here is unclear or missing.*

You asked for three things: **what we receive from Team 1, what we produce, and which attributes.**
This package answers exactly that, with real sample data. Read the files in this order:

| # | File | What you get | Time |
|---|---|---|---|
| 1 | `00_START_HERE.md` (this file) | The big picture, where we are, how to run the check script | 5 min |
| 2 | `01_INPUTS_from_Team1.md` | What Team 1 hands us and how we turn it into our input | 10 min |
| 3 | `02_OUTPUTS_Threat_Agent.md` | **Every attribute we produce**, meaning, allowed values, examples | 15 min |
| 4 | `03_TRACEABILITY_AND_AUDIT.md` | IDs to link on, audit log, rules you must follow when reading our data | 10 min |
| 5 | `04_COMING_Risk_and_Compliance.md` | What Risk / Compliance will add next (proposal, please comment) | 5 min |
| 6 | `05_STATUS_AND_QUESTIONS.md` | Honest status, limits, and what we need from you | 5 min |
| – | `samples/`, `schemas/`, `tools/` | Ready-to-use files (see section 4) | |

## 1. The pipeline in one picture

```
 Team 1                                  Team 2 (us)                              Team 3 (you)
 ─────────────────────────────────       ───────────────────────────────          ───────────────────────────
 Item definition → Use case               Threat Agent        (WORKING)           Requirements Agent
   → System model + diagrams       ──►    Risk Agent          (PLANNED)    ──►    Trace/Audit Agent
   → ASSET TABLE  (approved)              Compliance Agent    (LATER)             Consistency Agent
   hand-off = AssetTable                  hand-off = approved threats
                                          (+ risk, + required resistance)
```

Rule that holds everywhere: **the AI proposes, a human approves, and only approved results move on.**

## 2. Inputs → outputs, in one table

| | Team 1 → Team 2 (what we receive) | Team 2 → Team 3 (what we produce) |
|---|---|---|
| **Main object** | `AssetTable` (approved) | list of `ThreatScenario` (approved) |
| **Unit** | one **asset** `AS-n` | one **threat scenario** `THR-…` |
| **Linked to** | use case `UC-n`, diagram set version | asset `AS-n`, run `RUN-…`, KB entry (CAPEC / ATT&CK / CWE / STRIDE) |
| **Key attributes** | name, location, C/I/A/Auth, damage scenarios, KB citations, source | attack vector, STRIDE type, evidence chain, confidence, status, validation status |
| **Where you read it** | Team 1's database (`get_latest_asset_for_session`) | our API, the SCRS file, later Team 2's `threat_artefacts` table |

## 3. What is real today and what is not (please read)

* **Working and demonstrable:** the Threat Agent: from an asset list it produces cited threat scenarios, runs
  automatic checks, lets a human approve / reject / discard / add, and stores approved scenarios with an audit
  log. over 300 automatic tests pass. All samples in this package come from that real code.
* **Not yet connected:** the live link to Team 1's database. Team 1's latest code is on feature branches and
  not merged; our input today is a JSON file **in our own shape** (`ThreatAgentInput`). An adapter from
  Team 1's `AssetTable` to that shape is designed (file 01) but not built.
* **Not yet built:** Risk and Compliance agents (file 04 is a proposal, not a contract).
* **Accuracy:** against the company's six reference threats we match 1 of 6 at our similarity threshold;
  the human reviewer is the quality gate. Every scenario carries its evidence so a reviewer can judge it.

## 4. What is in this package

```
samples/
  input_smart_door_lock.json / input_infusion_pump.json   what our agent consumes today
  team1_asset_table_example.json                          ILLUSTRATIVE Team 1 AssetTable (door lock, SRS §2.4)
  output_threat_scenarios_sample.json / .csv              12 approved scenarios, all attributes (real output)
  output_scrs_state_sample.json                           shared state: scenarios + audit log + history
  output_example_flagged_scenario.json                    a scenario that failed an automatic check
schemas/
  threat_schemas.py, scrs_schemas.py                      the exact Pydantic models (import them)
  *.schema.json                                           the same as JSON Schema (any language)
tools/
  check_handoff.py                                        validates the samples and prints a trace matrix
```

Quick check (Python 3.11+, `pip install pydantic`):

```bash
python tools/check_handoff.py
```

It validates every sample against the schemas and prints counts, the approved-only filter and a small
UC → Asset → Threat trace matrix, so you can see how to consume the data in about 30 lines of code.

## 5. Contacts and how to reach us

Ask our team (TY-A9, Team 2) for anything in this package. If you need an attribute we do not have,
tell us the name, meaning and which agent needs it; adding an optional field is cheap, changing an existing
one is not.
