# Phase 1 Complete Guide: Explanation, Demo Script and Phase 2 Plan

*For Group TY-A9. Read in this order: Part A (understand the screen), Part B (understand Phase 1),
Part C (the scripts to speak). Everything is written the way a teacher would explain it to a class:
simple words, one idea at a time, with examples.*

## Contents

**Part A. Understand the CLI output (read this first)**
1. The big picture in one story
2. The pipeline and the tools behind each stage
3. The output explained, screen by screen
4. How to read the numbers (similarity, confidence, flagged)
5. What happens inside when you press `n` (reject)
6. Recorded mode vs live mode

**Part B. Phase 1 in full**
7. What the company asked for
8. How we built it, in the order we built it
9. Every tool we used and why (explained simply)
10. The important ideas, explained like a lesson
11. What we achieved: the evidence and numbers
12. Difficulties we faced and how we solved them
13. What is not done
14. Questions WE should ask the company
15. Questions THEY may ask us, with answers

**Part C. Scripts to speak**
16. Script 1: the CLI demo (10-12 minutes)
17. Script 2: the Phase 1 explanation talk (8-10 minutes)

**Part D. Phase 2 (Risk Agent) plan**
18. The plan

**Part E.** 19. Small dictionary

---

# PART A. UNDERSTAND THE CLI OUTPUT

## 1. The big picture in one story

Imagine a company is about to sell a **smart door lock**. The law (the EU **Cyber Resilience Act**,
CRA) says: *find out how hackers could attack it, and keep proof that you did.*

Normally a **senior security expert** sits for days and does this by hand. Our system is like giving
that expert a **very fast junior assistant**:

* The junior has a **huge library** of known attacks (our *knowledge base*).
* The junior reads the product description and **looks up** the attacks that fit each part.
* The junior **writes a short report** for each attack: what, why it applies, and *which book in the
  library says so*.
* A **checker** (a fixed program, not AI) makes sure the junior did not invent anything.
* The **senior expert reads each report and says yes or no**. If no, the junior must try again using
  the senior's comment.
* Only the **approved** reports are filed, with a diary of every decision.

That is exactly what you see on the CLI. **The AI proposes, the human decides.**

## 2. The pipeline and the tools behind each stage

```
 project JSON ──► 1 Understand ──► 2 Plan search ──► 3 Search library ──► 4 Attack paths
                                                                              │
 saved + audit ◄── 7 Human review ◄── 6 Automatic checks ◄── 5 AI writes ◄───┘
```

| Stage on screen | What the program does | Tool used | Is AI used? |
|---|---|---|---|
| Project menu | Finds the project JSON files | Python file handling | No |
| **1 Understanding** | Reads and **validates** the asset sheet (rejects bad input); hides secrets and personal data | **Pydantic** (data validation), our redaction module (regex) | No |
| **2 Planning** | Builds a search sentence per asset; works out which STRIDE types apply | Our rules in Python | No |
| **3 Searching** | Turns text into 384 numbers and finds the closest attack patterns | **sentence-transformers** (model `all-MiniLM-L6-v2`), **PostgreSQL + pgvector** | A small embedding model, not a chatbot |
| **4 Attack paths** | Pairs each found pattern with its asset, ranks by similarity | Our Python code | No |
| **5 Generating** | Writes the attack story and evidence | **A language model** (gpt-4o-mini through OpenRouter) via the **OpenAI Python library** | **Yes (the only creative part)** |
| **6 Checking** | 5 fixed checks, retries only failed scenarios | Our validator + grounding rules | No |
| **7 Review** | You approve / reject / discard / add | **rich** library for the screen, our review loop | No |
| Saving | Writes approved scenarios + audit diary | Our `StateManager` writing `SCRS` JSON | No |

**Notice:** only *one* stage uses the chatbot-style AI. Everything that decides "is this acceptable?"
is a **fixed rule**. This is what the company calls the **determinism boundary**.

The same program also runs as a **web service** (FastAPI) with the same workflow, backed by a
database; the CLI is just the friendliest way to show it.

## 3. The output explained, screen by screen

Run: `python scripts/scrp_demo.py`

### Screen 1: header and project menu

```
SCRP Threat Agent  Phase 1

Available projects:
  #   Project           Assets   File
  1   Smart Door Lock        6   ...\smart_door_lock\input.json
  2   Infusion Pump          2   ...\infusion_pump\input.json
Select a project (1-2, default 1):
```

* **What it shows:** every project file the program found.
* **Assets column:** how many things-to-protect are in that file.
* **Why it matters:** the program is **not built only for door locks**. Give it any project JSON and
  it works. Two different products prove this.
* **After you choose:** `Project Smart Door Lock  6 assets  knowledge base trc_engine_fullkb  recorded
  model output`. This line tells you *which library* is used (the big one, `fullkb`) and *where the AI
  text comes from* (recorded or a live model).

### Screen 2: Step 1/7, Understanding the system

```
Asset  Name              Must protect                              Interfaces
AS-1   Unlock Command    Integrity, Availability, Authenticity     BLE 5.0, GATT, Cloud API
...
Privacy: 0 credential / personal item(s) masked before anything is sent to the model.
```

* **Asset** = a thing worth protecting. `AS-1` is just its ID.
* **Must protect** = the four security goals (called **C-I-A + Authenticity**):
  * **Confidentiality**: kept secret (a password).
  * **Integrity**: not changed by attackers (firmware).
  * **Availability**: always works (the unlock function).
  * **Authenticity**: really comes from the right person/device.
* **Interfaces** = the doors an attacker could knock on (Bluetooth, cloud API, a memory chip bus).
* **Privacy line:** before any text goes to the AI, the program hides emails, phone numbers, IP
  addresses, passwords, API keys and tokens. If your asset sheet contained `password: abc123` it
  would say "1 item masked" and the AI would see `[REDACTED_SECRET]` instead.

### Screen 3: Step 2/7, Planning the search

```
Asset  Search text                    Topic tags               STRIDE to look for
AS-3   Firmware Image embedded ...    crypto, firmware, wireless  Spoofing, Tampering, DenialOfService
```

* **Search text** = the sentence the program will look up in the library (asset name + type +
  interfaces + settings).
* **Topic tags** = areas this asset belongs to (cloud, firmware, crypto, hardware ...). They help the
  search prefer relevant patterns.
* **STRIDE to look for** = which of the six attack types matter, taken from what the asset must
  protect: integrity -> Tampering, authenticity -> Spoofing, confidentiality -> Information
  disclosure, availability -> Denial of service.

> **STRIDE in one table**
>
> | Letter | Name | Everyday example |
> |---|---|---|
> | S | Spoofing | pretending to be the owner (replaying an unlock signal) |
> | T | Tampering | changing something (a fake firmware update) |
> | R | Repudiation | denying you did it (deleting the log) |
> | I | Information disclosure | a secret leaks (sniffing traffic) |
> | D | Denial of service | making it stop working |
> | E | Elevation of privilege | getting more power than allowed |

### Screen 4: Step 3/7, Searching the knowledge base

```
ok  60 patterns retrieved in 21s (ATT&CK 26, CAPEC 18, STRIDE 11, CWE 5)
Best matches per asset
Asset  Pattern            Source   Similarity  Title
AS-3   ATT&CK-T1542.002   ATT&CK   0.75        Component Firmware
AS-3   CWE-1277           CWE      0.75        Firmware Not Updateable
```

* **Patterns retrieved:** the library has **2,300** attack patterns; the search brought back the 60
  best (10 per asset). The counts show which catalogues they came from.
* **Source:** where the pattern comes from.
  * **CAPEC**: attack patterns ("how attackers usually do X").
  * **ATT&CK**: real techniques seen in real attacks.
  * **CWE**: software/hardware *weaknesses* (the mistakes that attacks exploit).
  * **STRIDE**: our six basic types.
* **Similarity** (0 to 1): how close the pattern's meaning is to the asset description. 0.75 means
  "quite close". It is **not** a probability that the attack is real.
* **How it works (teacher explanation):** every pattern in the library was converted once into a list
  of **384 numbers** that represent its meaning. The asset description is converted the same way.
  Texts with similar meaning get similar numbers, so we can find the closest ones with maths
  (**cosine similarity**), even if they share no exact words. Searching "BLE OTA update with no
  signature check" finds "Component Firmware" because the *meaning* is near.
* **Why 21 seconds?** The first search loads the embedding model into memory.

### Screen 5: Step 4/7, Building attack paths

```
Path            Asset  Pattern           Confidence
PATH-E76DCCE5   AS-4   CAPEC-665         0.77
```

* An **attack path** = one asset + one pattern found for it.
* The program takes the **best 6**, spread across the assets so every asset is covered
  (`--max-paths` changes this number).
* **Confidence** here is the similarity score again (see Section 4).
* **Honest note:** the company describes *chains* (attack step 1, then 2, then 3). That is **not built
  yet**; today each path is a single pattern. The screen says so.

### Screen 6: Step 5/7, Generating threat scenarios

```
ok  6 scenarios generated (recorded model output)
```

* For every path the AI receives: the asset facts + the pattern text. It must write back **five
  things**: the attack, what is exposed, why it applies here, a citation, and a STRIDE type.
* Secrets are masked *before* this call.
* "recorded model output" means we are replaying a real earlier AI run so the demo works without
  internet. In live mode it says how many seconds the real call took.

### Screen 7: Step 6/7, Checking the output

```
#  Asset  Pattern  Citation  Schema  STRIDE fit  Evidence  Grounded  Result
1  AS-4   CAPEC-665    ok      ok        ok         ok        ok      passed
4  AS-2   ATT&CK-..    ok      ok       FAIL        ok        ok      flagged
```

Five automatic checks, all fixed rules:

| Check | Question it asks | Example of failing |
|---|---|---|
| **Citation** | Is there a real citation? | citation is "TBD" or empty |
| **Schema** | Are all required fields filled? | a field missing |
| **STRIDE fit** | Do the attack words match the threat type? | called "Spoofing" but describes a flood |
| **Evidence** | Is the reason specific to this asset? | "an attacker may attack the system" (too generic) |
| **Grounded** | Does it cite only a pattern that search really returned, a real asset, and an exposure that belongs to that asset? | cites CAPEC-999 that was never retrieved |

* `FAIL` in a column = that check failed. The row's **Result** is `flagged`.
* **What happens to a failing scenario:** the program regenerates *only that scenario* (up to 3 tries)
  and checks again. If it still fails, it is **flagged**: shown to the human with a yellow border.
* This is the answer to "can the AI hallucinate?": it can write imperfect text, but it **cannot sneak
  in a fake citation**, and anything doubtful is flagged.

### Screen 8: the results table

One row per scenario: asset, STRIDE letter, pattern, confidence, passed/flagged and the start of the
attack. It is the "table of contents" before the detailed review.

### Screen 9: Step 7/7, Your review (the human gate)

```
┌─ Scenario 2 of 6   THR-PATH-8FA7D95D-002 ─────────────────────────┐
│ Asset       AS-3                                                    │
│ STRIDE      Tampering    Confidence 0.75    Validation passed       │
│ Pattern     ATT&CK-T1542.002                                        │
│ Attack      Modifying the firmware image during a BLE OTA update... │
│ Exposure    BLE OTA interface allowing firmware updates without ... │
│ Why         The firmware image lacks signature verification ...     │
│ Citation    ATT&CK-T1542.002: Component Firmware                    │
│ Derived     AS-3 -> ATT&CK-T1542.002 (similarity 0.75)              │
│ Checks      Citation ok  Schema ok  STRIDE fit ok  Evidence ok ...  │
└─────────────────────────────────────────────────────────────────────┘
Approve this scenario? (y=yes, n=no, x=discard, a=all, q=quit; default y):
```

Read the card like a mini report:

* **THR-PATH-8FA7D95D-002**: the scenario's ID. It contains the path ID so we can always trace back.
* **Attack**: the story. **Exposure**: the weak spot on the asset. **Why**: why it applies.
* **Citation**: the library entry that backs the claim (the *proof*).
* **Derived**: the trail (asset -> pattern -> similarity). **Checks**: the same five checks, for this
  scenario. A yellow border and "flagged" means *look at this one carefully*.

Your answers:

| Key | Meaning | What happens |
|---|---|---|
| `y` / Enter | approve | kept for saving |
| `n` | reject | you type a reason; it is regenerated and shown again (max 3 times) |
| `x` | discard | removed from the run, with your reason, kept in history |
| `a` | approve the rest | quick finish |
| `q` | quit | unreviewed scenarios are not saved |

After the last scenario: **"Add a scenario of your own?"** lets the expert add a threat the AI missed.
It must use a real asset, a valid STRIDE type and a pattern ID that **really exists in the library**,
and it passes the same checks as AI output.

### Screen 10: the end (and what happens next time)

**The shared state is remembered between runs.** If you run the same project again, the first thing
you see is **"Already approved for this project (N), kept from earlier runs"** (including scenarios an
expert added). The agent skips patterns that are already approved, so you only review *new* proposals,
and at the end it shows **everything approved so far** (marked "earlier" or "new"). This is how an
expert can continue the work over several sessions. `--fresh` starts clean (the scripted `--auto`
rehearsal always starts clean).


```
Review finished: 5 approved, 1 discarded
ok  5 approved scenarios written to demo_output\SCRS_demo.json
    audit log: 5 write, 5 approve, 2 reject, 1 prune
ok  Report saved to demo_output\run_report.json
Run another project? (y/n):
```

* **SCRS** (shared state): the file all agents read. **Only approved scenarios go in.**
* **audit log**: a diary with time, action and reason for every write, approval, rejection, prune,
  add. (`prune` = discard.) Rejected and replaced scenarios are **not deleted**; they stay in the
  history marked as superseded. That is the company's "non-overwrite" rule.
* The demo writes to the `demo_output` folder so your real file is never touched.

## 4. How to read the numbers

| Number | What it really means | What it does NOT mean |
|---|---|---|
| **Similarity** (0-1) | How close the pattern's meaning is to the asset description | Not a probability the attack is real |
| **Confidence** (0-1) | The **average similarity** of the patterns used in the path | Not "the chance the AI is right". It says how well the *evidence matched the asset*. A value below **0.4** triggers a low-confidence warning |
| **passed** | All 5 automatic checks passed | Not "a human approved it" |
| **flagged** | Failed a check after the retries; needs extra attention | Not "wrong"; it is shown on purpose |

## 5. What happens inside when you press `n` (reject)

1. Your **reason** is saved in the audit log and the revision history (so it can never be lost).
2. The program takes **only that scenario's attack path**.
3. It gives the model the same asset facts and pattern **plus your reason** as extra instructions
   ("the reviewer said: too generic, name the interface").
4. The model writes a new version. The **five checks run again**.
5. The new version is shown as "Revised scenario". You answer again.
6. This can repeat **3 times**. After the third rejection the scenario is marked rejected and is not
   saved, so the loop cannot run forever.

## 6. Recorded mode vs live mode

| | Recorded (default for Smart Door Lock) | Live (`--mode live`) |
|---|---|---|
| AI text comes from | a saved real run | a real call to the model |
| Needs internet and a key | no | yes (funded key in `.env`) |
| Rejection reason | saved, but the screen shows the *next recorded alternative* | really used to rewrite the scenario |
| Speed | fast | about 7 seconds per scenario |
| Best for | safe demo | showing the true loop |

---

# PART B. PHASE 1 IN FULL

## 7. What the company asked for

The company document gives the whole TARA workflow (10 steps). **Phase 1 is Step 4, "Threat
identification"** (Section 3.2):

> *Retrieve relevant threat patterns; propose threat scenarios with rationale and KB references.*
> Input: assets + diagrams + knowledge base. Output: ranked threat list with citations.
> Human checkpoint: **expert prunes / adds**.

Plus the rules that apply to every AI part (Section 3.4). How we answered each:

| Company requirement | What we did |
|---|---|
| Retrieve relevant threat patterns | Semantic search over 2,300 patterns (CAPEC, ATT&CK, CWE, STRIDE) with pgvector |
| Propose scenarios with rationale | The AI writes attack, exposure, why-it-applies for each |
| **KB references / citations** on everything | Every scenario cites a pattern; code checks it was really retrieved |
| Ranked list | Every scenario carries a confidence score (average similarity) that can be used to rank; the demo spreads the first picks across assets |
| Expert prunes / adds | Discard (`x`) with reason; expert add, validated |
| Human-in-the-loop | Approve/reject loop; nothing saved without "yes" |
| Confidence and review flags | Confidence score; `flagged` status for doubtful ones |
| Non-overwrite | Old versions kept in the history as "superseded" |
| Auditability | Audit log: retrieved patterns per asset, model + prompt version, human decisions |
| Traceability | Each scenario carries use-case ID, asset ID/version, KB version, path ID |
| Determinism boundary | All decisions by fixed rules; AI only writes text |
| Privacy and secrets | Masking of PII and credentials before the AI call |
| Explainability | Rationale + evidence + "Derived" trail on every card |

## 8. How we built it, in the order we built it

Think of it as building a house: foundation first, then walls, then safety, then polish.

1. **Contracts first (the foundation).** We defined exactly what an *asset*, a *threat scenario*, an
   *evidence chain*, a *validation result* look like, using **Pydantic** models. Bad data is rejected
   at the door. (`agents/threat_agent/schemas.py`)
2. **A small knowledge base.** 24 hand-written patterns so we could develop and test quickly.
3. **Search.** Embedding model + PostgreSQL with the **pgvector** extension for "closest meaning"
   search. (`retrieval.py`)
4. **The AI writer.** A prompt that gives the model the asset facts and the pattern and demands a
   structured answer; secrets are masked first. (`generator.py`)
5. **The checker.** The **Protocol Invariant Validator**: 4 fixed checks, then we *measured* its
   mistakes honestly (wrongly accepts 15.38%, wrongly rejects 8.33% on 50 labelled scenarios).
6. **The orchestrator.** Ties it together, retries failed work (max 3), stamps each scenario
   `passed` or `escalated_after_retries`. (`orchestrator.py`)
7. **The web service.** FastAPI endpoints: start a run, approve, reject, prune, add. A **run
   registry** (in memory or PostgreSQL) remembers each run safely, even with several users at once.
8. **The human loop.** Reject -> reason -> regenerate -> re-check -> bounded retries, with history.
9. **The shared state (SCRS).** Approved scenarios saved with an audit log and non-overwrite history.
   We also found and fixed a gap: at first the API approval did *not* write to SCRS; now it does.
10. **The full knowledge base.** Downloaded all free catalogues and loaded 2,300 patterns plus 5,097
    standards pieces; marked each with topic tags.
11. **Search quality work.** We built a benchmark (dev / company / held-out questions) and tried many
    ideas; we kept the **topic-tag rerank** and rejected the rest (Section 12).
12. **Grounding rules.** Added checks so the AI cannot cite what was not retrieved; **retry only the
    failed scenarios** to save AI cost.
13. **Expert tools.** Prune and add with validation and a check that the pattern exists.
14. **Traceability, logging, secret masking, automatic retries for network and rate-limit errors.**
15. **Tests.** Over 300 automatic tests; every feature above has some.
16. **The CLI.** The friendly interface that shows all of it.

## 9. Every tool we used and why (simple explanations)

| Tool | What it is (simple) | What we use it for | Why we chose it |
|---|---|---|---|
| **Python 3.11+** | The programming language | Everything | Standard for AI/security tooling |
| **Pydantic** | A library that checks data has the right shape and types | Asset input, scenarios, validation results | Bad data is rejected immediately; self-documenting contracts |
| **FastAPI + Uvicorn** | A tool to build web services (APIs) and the server that runs them | The `/threat-agent/*` endpoints (start run, approve, reject, prune, add) | Fast, automatic input checking, other agents can call it |
| **PostgreSQL** | A reliable database | Knowledge base; run registry | Industry standard, supports concurrency and transactions |
| **pgvector** | An add-on that lets PostgreSQL store and search lists of numbers (vectors) | "Find the closest meaning" search | Keeps search and data in one database; no extra search server |
| **sentence-transformers `all-MiniLM-L6-v2`** | A small AI model that turns a sentence into 384 numbers | Converting patterns and asset text to vectors | Small, free, runs on a laptop, good quality for English text |
| **psycopg (v3)** | The Python-to-PostgreSQL connector, with a connection pool | All database access | Modern, supports pooling |
| **OpenAI Python library** | A client that talks to chat language models | Calling the writing model. It also works with **OpenRouter** and **Groq** by changing the web address | One code path for many providers; easy to swap models |
| **gpt-4o-mini** (via OpenRouter) | The language model | Writes the scenario text | Cheap and good enough; the model is a setting, not hard-wired |
| **Docker Compose** | Runs the database in a ready-made container | `docker compose up -d` starts PostgreSQL + pgvector | Same environment on every laptop |
| **rich** | A Python library for nice terminal output | The CLI tables and cards | Readable demo |
| **pytest** | A testing tool | 300+ automatic tests | Catches mistakes before the demo |
| **ruff** | A code-quality checker | Style, bugs, security hints on every commit | Keeps code clean |
| **Git/GitHub** | Version control | Branches, history, teamwork | Standard |
| **CAPEC / ATT&CK / CWE (MITRE)** | Free public catalogues of attacks and weaknesses | The knowledge base content | Free and recognised; named in the company document |
| **Common Criteria, CEM, JIL, EU CRA texts** | Standards documents | Stored as 5,097 searchable pieces | Free; needed later for Phase 2 mapping |

## 10. The important ideas, explained like a lesson

### 10.1 Semantic search (finding by meaning)

Normal search finds exact words. Ours finds *meaning*. A model turns each text into 384 numbers; texts
about similar things end up with similar numbers. To search, we convert the question the same way and
ask the database for the closest numbers. That is why "unauthenticated firmware update over Bluetooth"
finds "Component Firmware" even though the words differ.

### 10.2 Why we boost by topic tags

Meaning-search can be fooled by generic wording. Each pattern and each asset also gets **topic tags**
(cloud, firmware, crypto, hardware, wireless ...). Patterns whose tags match the asset get a small
bonus, and hardware-only patterns are slightly penalised for pure software assets. In our benchmark
this was the one change that reliably helped.

### 10.3 How we stop the AI from inventing things

Language models can "hallucinate": produce confident but false text. We cannot make that impossible,
so we use **layers**:

1. The AI is **only given retrieved patterns** and is told to cite one of them.
2. Fixed code checks: the cited pattern **must be one of the retrieved ones**, the asset must exist,
   the exposure must belong to the asset.
3. Failed scenarios are redone, then **flagged**.
4. A **human approves** every scenario.

So: *invented citations are impossible; imperfect wording is possible and is caught by the human.*

### 10.4 Determinism boundary

"Deterministic" means the same input always gives the same output. Searching, checking, saving and
the audit log are deterministic. Only the AI-written text can vary between runs, which is why we log
the run ID, model and prompt version.

### 10.5 Retry only what failed

If 2 of 12 scenarios fail, we regenerate **2**, not 12. That roughly halves the AI cost.

### 10.6 Human-in-the-loop with bounded retries

Reject -> reason -> regenerate -> re-check -> show again, **at most 3 times** per scenario, so the
loop always ends. Every step is saved in the history.

### 10.7 Why a shared state (SCRS)

Later agents (Risk, Requirements ...) must read the **approved** threats. SCRS is that shared record.
Only approved content enters it; nothing is overwritten.

## 11. What we achieved: the evidence and numbers

| Measurement | Result |
|---|---|
| Knowledge base | 2,300 patterns (CAPEC 556, ATT&CK 794, CWE 944, STRIDE 6) + 5,097 standards pieces |
| Automatic tests | over 300, all passing |
| Validator mistakes (50 labelled scenarios) | wrongly accepts 15.38% (4/26), wrongly rejects 8.33% (2/24), accuracy 88% |
| Company's six reference threats for the door lock (full knowledge base, gpt-4o-mini) | **1 of 6 matched** at similarity 0.75; near misses at 0.745 (T6) and 0.703 (T2) |
| Final run | 60 scenarios, 36 passed, 24 flagged, 6 template fallbacks, 405 seconds, about 222,000 input tokens |
| Earlier run on the small 24-pattern set | 2 of 6 (older version), 1 of 6 (newer version) |
| Retry-only-failed | roughly halves AI calls and tokens |

How to talk about the 1 of 6: *"The system produces grounded, cited scenarios for every asset. Against
your six reference threats it matches one at our similarity threshold and is close on two more. The
free catalogues are generic; your internal and hardware patterns are not in them. We need those, and an
expert's judgements of our search results, to improve this."*

## 12. Difficulties we faced and how we solved them

| Difficulty | What happened | What we did |
|---|---|---|
| **1. Search did not find the company's cited patterns** | With the big library, matching their six threats was weaker than with the small hand-written set (the small set was written around the demo systems) | Built a graded benchmark; tried query rewriting by AI, hybrid keyword search, a re-ranking model, other embedding models, STRIDE-balanced picking. Only the topic-tag rerank helped consistently; the rest were rejected on evidence. Still open: needs company patterns + expert judgements |
| **2. Hallucination** | Models can invent citations | Grounding rules in code, retry, flag, human approval |
| **3. The validator makes mistakes** | 15.38% wrong accepts | Measured and reported honestly; added the grounding layer on top; human gate |
| **4. Approval did not save to SCRS** | We found that the API approval did not write the shared state (only the CLI did) | Fixed: approval now writes all scenarios in one all-or-nothing save |
| **5. Two databases mixed up** | Loading the big library once overwrote the small one | Restored it; the build scripts now refuse to write to the wrong database; tests are pinned to the small set, the app defaults to the big one |
| **6. Cost and rate limits** | Free AI tiers allow about 8,000 tokens a minute; an account ran out of credit (HTTP 402); connections dropped | Retry-only-failed (cheaper), automatic waiting on rate limits, retries on dropped connections, recorded mode for demos |
| **7. Results varied between runs** | 1 of 6 vs 2 of 6 on different runs and setups | We never overwrite earlier results, label every run (model, knowledge base, pipeline version) and avoid over-claiming |
| **8. Multi-step chaining not built** | The chaining function is a placeholder | Honest: each path is a single pattern; listed as planned |
| **9. Team 1's asset table does not match our input** | Theirs lacks trust zone, interfaces, data flows, device config | Waiting on the four fields; adapter after that |
| **10. Paid standards** | ISO/SAE 21434 is paid; SESIP terms unclear | Loaded everything free; asked the company |
| **11. Loop bugs in the first CLI** | Pressing `n` did not repeat the review | Rewrote the loop with a bounded retry and history |
| **12. Keeping secrets safe** | API keys can leak when pasted in chats or committed | Keys live only in `.env` (ignored by Git); redaction before AI calls; keys that were exposed must be revoked |

## 13. What is not done

* **Multi-step attack chaining** (planned extension).
* **Team 1 adapter** (waiting for four fields).
* **Company internal patterns** and **expert judgements** of search results.
* **ISO/SAE 21434 and SESIP** catalogues (paid / unclear).
* **Data-residency rules** (needs company policy).
* **Full prompt text** in the audit log (we store prompt version and model).
* **Tamper-proof audit** (the SCRS is a JSON file, not signed or in an append-only store).
* **Diagram input** (the Modelling Agent belongs to another team).
* **Accuracy against the company's six threats** is 1 of 6, not yet where we want it.

## 14. Questions WE should ask the company

1. In the T6 row, is the pattern **CAPEC-189 or CAPEC-622**? (CAPEC-189 looks like a different
   attack in the public catalogue.)
2. Can you share your **internal / hardware threat patterns** (Section 3.4 mentions "internal pattern
   id")? Even 20-30 would help a lot.
3. Can one of your experts **judge about 190 search results** (relevant / not relevant)? We prepared a
   spreadsheet; it takes about an hour.
4. Do you have, or can you give us access to, **ISO/SAE 21434** text and the **SESIP** terms?
5. Are **cloud language models allowed** for your data, or must it run on-premise?
6. For Phase 2: your **attack-feasibility rating tables**, **impact level definitions** and **risk
   matrix**.
7. How do you want threats **ranked**: by similarity confidence, by STRIDE group, or by asset?
8. Do you have company rules on **how many retries** or what counts as "good enough" for a threat?
9. Is it enough that **only approved scenarios** enter the shared state, or do you also need drafts
   stored?
10. How should we handle the **Team 1 asset table**: can they add the four missing fields?
11. What **evidence format** would your auditors like for the audit log?
12. Which **other products** can we test on besides the lock and the pump?

## 15. Questions THEY may ask us, with answers

*(They know the project, so answers are direct and honest.)*

**Accuracy and quality**

**Q1. How accurate is it?**
On your door-lock example it produces cited scenarios for every asset and matches **1 of your 6**
reference threats at our similarity threshold (two more are close: 0.745 and 0.703). The checker
wrongly accepts 15.38% and wrongly rejects 8.33% in our 50-scenario test. The human gate catches the
rest. We think the main gap is missing company-specific knowledge, not the pipeline.

**Q2. Why did it only match 1 of 6?**
Our free library is general. Your six rows use hardware and internal knowledge (for example key
extraction by side-channel) that is not in the public catalogues in the same wording. Also one pattern
in your table (CAPEC-189) seems to differ from the public catalogue (CAPEC-622 looks closer). With your
patterns and an expert's judgements we can tune the search.

**Q3. Can the AI hallucinate?**
Its *wording* can be imperfect. Its *citations* cannot be invented: code checks that the cited pattern
was really retrieved, the asset exists and the exposure belongs to that asset. Failures are retried and
flagged, and a human approves everything. We do not claim zero errors.

**Q4. What does "confidence" mean?**
The average similarity between the asset and the patterns used. It tells how well the evidence matched
the asset, not the probability that the attack is real. Below 0.4 we show a low-confidence warning.

**Q5. Why would results differ between two runs?**
Search, checks and saving are deterministic. The AI-written text can vary. We log the run ID, model and
prompt version so a run can be explained.

**Q6. What is a "flagged" scenario?**
One that failed an automatic check after three tries. We show it with a warning rather than hiding it.

**Design and compliance**

**Q7. Does it follow ISO/SAE 21434?**
Phase 1 follows the TARA structure for the threat-identification step. We do not have the ISO text
(paid). Phase 2 (risk) follows the §15.5/15.6 structure from your document; we need your rating tables.

**Q8. Does it make us CRA-compliant?**
No tool does that by itself. It produces traceable, auditable evidence (citations, decisions, history)
that supports a CRA process. Accountability stays with your experts.

**Q9. How is the "determinism boundary" respected?**
Every accept/reject decision, the search ranking, the checks and the storage are fixed rules. The
language model only writes explanation text.

**Q10. Where is the audit trail and is it tamper-proof?**
In the shared-state JSON (every write, approval, rejection, prune, add with time and reason) and in
logs (retrieved patterns, model, prompt version). It is not cryptographically signed; moving it to a
database with append-only rules is a possible hardening.

**Q11. Do you log the prompts?**
We log the prompt *version*, the model, and the retrieved patterns for each run, not the full text of
every prompt. We can add full prompt logging if your audit needs it.

**Q12. How do you protect confidential data?**
Emails, phone numbers, IPs, passwords, API keys, tokens and private keys are masked before any AI
call. Only asset facts go to the model. We need your rule on cloud vs on-premise models; the model is a
setting, so an on-premise model can be used.

**Technology**

**Q13. Why PostgreSQL + pgvector and not a separate vector database?**
One database for patterns, runs and vectors keeps the system simpler and transactional. Our library
(2,300 patterns) is small, so no special vector server is needed.

**Q14. Why the MiniLM embedding model?**
It is small, free, runs on a laptop and works well on English technical text. We also tried other
embedding models and a re-ranking model; they did not give consistent gains, so we kept the simple one.

**Q15. Which language model and can we change it?**
`gpt-4o-mini` through OpenRouter in our tests. It is a setting; any OpenAI-compatible service works
(we also tried Groq). An on-premise model works the same way.

**Q16. What does a run cost?**
The final door-lock run used about 222,000 input and 18,000 output tokens, which is a few cents with
gpt-4o-mini. Retrying only failed scenarios roughly halves the cost.

**Q17. Will it work for any product?**
Yes, give it another asset JSON; we showed a lock and a medical pump. Quality depends on how detailed
the asset sheet is and how well the knowledge base covers that domain.

**Q18. What if the knowledge base changes?**
Scenarios store a knowledge-base version label. Right now it is a label, not a content hash; making it
a hash is a small improvement we can do.

**Q19. Can several people use it at once?**
The API's run store handles concurrent runs safely (atomic status changes in PostgreSQL). The SCRS file
is a single-process JSON file in Phase 1; Phase 2 should move it to the database.

**Q20. How do other agents use your output?**
Through the SCRS (approved scenarios) and the API. Phase 2 reads the approved scenarios from there.

**Process**

**Q21. What is still missing from Phase 1?**
Multi-step chaining, the Team 1 adapter, your internal patterns, ISO/SESIP catalogues, data-residency
rules and tamper-proof audit. All are listed with reasons.

**Q22. How did you test?**
Over 300 automatic tests, a labelled validator test (50 scenarios), a retrieval benchmark with
dev/company/held-out questions, and end-to-end runs on your six reference threats.

**Q23. What do you need from us?**
Internal patterns, an expert's judgements on about 190 results, the CAPEC-189/622 clarification, access
to ISO 21434 and SESIP terms, and the Phase 2 rating tables.

**Q24. Can the expert override the AI?**
Yes, at every step: approve, reject with reason, discard, or add an own scenario. Every override is
logged.

---

# PART C. SCRIPTS TO SPEAK

## 16. Script 1: the CLI demo (10-12 minutes)

### Before they arrive (checklist)

* [ ] `docker compose up -d`, wait 20 seconds.
* [ ] Wide terminal (120+ columns), large font.
* [ ] `python scripts/scrp_demo.py --auto` once as a rehearsal (loads the model).
* [ ] For live mode: `OPENAI_API_KEY` in `.env` is a funded key; test once with `--mode live`.
* [ ] Have ready: the rejection reason and the expert scenario from this document.

**Rejection reason to type:**
`Too generic. Name the specific interface, such as the BLE characteristic, and say how the attacker reaches it.`

**Expert scenario to type** (Spoofing example):
`AS-1` / `Spoofing` / `CWE-306` / `Impersonation of a legitimate caller to the Unlock Command through an unauthenticated management interface (identity spoofing)` / `Unlock Command interface accepts requests without caller authentication` / `The Unlock Command is reachable over its interface and no caller authentication is enforced before the critical function runs.` / `CWE-306: Missing Authentication for Critical Function` / `Known weakness class for this product family`

### Opening (30 seconds)

> "This is Phase 1, the Threat Agent: Step 4 of your TARA workflow. It reads an asset list and proposes
> threat scenarios, each backed by a public attack catalogue. The AI proposes; a human decides. I'll
> run it on a smart door lock."

### Part 1: choose a project (30 seconds)

*Run `python scripts/scrp_demo.py`, press Enter for project 1.*

> "This menu lists project files. Any product is just another JSON file. We also have a medical pump."

### Part 2: understanding and planning (1.5 minutes)

> "First the agent reads each asset: what it is and what must be protected, confidentiality,
> integrity, availability, authenticity. See the privacy line: credentials and personal data are masked
> before anything reaches the AI.
> Then it plans: from those security needs it decides which STRIDE threat types to look for."

### Part 3: knowledge base search (2 minutes)

> "Our library has 2,300 patterns from the free MITRE catalogues, CAPEC, ATT&CK and CWE, plus STRIDE,
> and about 5,000 pieces of Common Criteria and CRA text. The search is by meaning, not exact words.
> This table shows the best matches per asset. For the firmware image it found 'Component Firmware',
> which is exactly the right idea."

*Point at AS-3.*

### Part 4: paths, generation and checks (2.5 minutes)

> "Each match becomes an attack path. Multi-step chains are not built yet; I want to be upfront.
> The AI then writes a scenario for each path. And here is the key point: we do not trust it. Five
> fixed-rule checks look at every scenario. It can only cite a pattern that retrieval really returned,
> so it cannot invent a citation. If one fails, only that one is redone, up to three times; if it still
> fails it is flagged for the human. You can see one flagged row here."

*Point at the FAIL cell.*

### Part 5: human review (3 minutes)

> "Now the human gate. This card shows the attack, the exposure, the reason, the citation, where it
> came from and the check results."

*Scenario 1: press Enter.* "I approve this one."
*Scenario 2: type `n`, then the rejection reason above.*

> "I reject it and give a reason. It's saved in the audit trail. In live mode the reason goes to the
> model, only this scenario is rewritten and checked again, and I see the new version. Up to three
> times. In this recorded demo, the screen shows the next alternative and says so."

*Next scenario: type `x`, reason `Out of scope for this variant.`*

> "I can also discard one with a reason. Nothing is deleted from the history."

*Type `a` for the rest. Answer `y` to "Add a scenario of your own?" and type the expert scenario.*

> "The expert can add a threat the AI missed. It's checked like AI output, and the pattern ID has to
> exist in the library."

*(Optional: type the attack `Heavy rainfall damages the enclosure` to show it being refused.)*

### Part 6: saving and audit (1 minute)

> "Only approved scenarios are written to the shared state. The audit log shows writes, approvals,
> rejections with reasons, prunes and adds. Rejected and replaced content stays in the history. That's
> your traceability and non-overwrite rule."

### Part 7: honest close (1 minute)

> "Working: the full workflow from assets to approved, audited scenarios, with over 300 tests.
> Accuracy on your six reference threats is 1 of 6, with two more close. Not built: multi-step chains
> and the Team 1 adapter. What would help most: your internal patterns, an expert's judgement of about
> 190 search results, and the rating tables for Phase 2."

## 17. Script 2: the Phase 1 explanation talk (8-10 minutes, no screen needed)

**Slide/point 1: the goal (1 min)**
> "Your document describes an AI-assisted TARA process. Phase 1 is the Threat Agent, Step 4: given the
> assets, find the relevant threats, with rationale and citations, and let the expert prune or add."

**Point 2: how it works (2 min)**
> "Seven stages. One: read and validate the asset sheet, and mask secrets. Two: plan a search per asset
> using its security needs and STRIDE. Three: semantic search over a knowledge base of 2,300 patterns,
> turning text into vectors in PostgreSQL with pgvector. Four: form attack paths. Five: the language
> model writes the scenario from the asset facts and the retrieved pattern. Six: fixed-rule checks.
> Seven: the human approves or rejects, and approved scenarios go to the shared state with an audit
> log."

**Point 3: how we meet your Section 3.4 rules (2 min)**
> "Citations on every scenario, verified by code. Confidence and flags. Human approval. Non-overwrite
> history. Audit log of retrieved patterns, model, prompt version and decisions. Traceability fields on
> each scenario. Fixed rules for every decision; the AI only writes text. Masking of personal data and
> secrets. Evidence and rationale on every suggestion."

**Point 4: what we measured (1.5 min)**
> "The checker was measured on 50 labelled scenarios: 15% wrongly accepted, 8% wrongly rejected, and
> we report that openly. On your six door-lock threats, one is matched and two are close. Over 300
> automatic tests pass. A full run takes about 7 minutes and a few cents of AI cost."

**Point 5: the hard parts (1.5 min)**
> "Search quality was the hard part: a larger library is not automatically better. We tested six ideas
> with a benchmark and kept only the one that helped. We also dealt with hallucination, AI cost and
> rate limits, and a bug where approval did not reach the shared state, which is fixed."

**Point 6: what is open and what we need (1.5 min)**
> "Open: multi-step chaining, the Team 1 adapter, ISO 21434 and SESIP catalogues, data-residency rules.
> From you: internal or hardware patterns, an expert's judgement on a short list of results, the
> CAPEC-189 or 622 clarification, and the rating tables for Phase 2. Next phase: the Risk Agent."

---

# PART D. PHASE 2 (RISK AGENT) PLAN

## 18. The plan

### 18.1 What the company wants (Section 2.6, Step 5)

*Score impact (S/F/O/P) and attack feasibility. Input: threats + context. Output: risk score +
justification. The expert adjusts.* For every approved threat the Risk Agent must say:

1. **How bad?** Impact on four axes, **S**afety, **F**inancial, **O**perational, **P**rivacy, each
   Negligible to Severe. **Overall impact** = the worst axis.
2. **How easy for an attacker?** Five factors (ISO 21434 §15.5): elapsed time, expertise, knowledge of
   the item, window of opportunity, equipment -> a feasibility level (Low/Medium/High).
3. **How risky?** Combine impact and feasibility in a **risk matrix** -> Low/Medium/High.
4. **What do we do?** **Reduce / Share / Retain / Avoid**, with a reason.

Their six worked rows (these become our main test):

| Threat | Impact S/F/O/P | Overall impact | Feasibility | Risk |
|---|---|---|---|---|
| T1 | -/Mod/Sev/Mod | Severe | Medium | High |
| T2 | -/Sev/Sev/Sev | Severe | Medium | High |
| T3 | Mod/Sev/Sev/Sev | Severe | Medium | High |
| T4 | -/Neg/Mod/Sev | Moderate | Low | Medium |
| T5 | -/Mod/Sev/- | Moderate | High | Medium |
| T6 | -/Sev/Sev/Sev | Severe | Low | Medium |

What the rows teach us: overall impact is the **highest** axis; and the matrix is **not a simple
formula** (Moderate+High and Severe+Low both give Medium), so it must be a **configurable table**.

### 18.2 Design

* **Fixed rules in config tables:** impact levels, feasibility scoring, the risk matrix, treatment
  options. Easy to replace when the company gives its real tables.
* **AI for suggestions only:** propose axis ratings and the written justification from the scenario
  evidence, with the same masking and checks as Phase 1.
* **Human:** the expert adjusts and approves; every change is logged.

### 18.3 Inputs and outputs

* **Reads** approved scenarios from the SCRS and asset damage information.
* **Writes** a risk record per threat: impact per axis, overall impact, feasibility factors and level,
  risk value, treatment decision, justification, history of changes, links back to the threat ID.

### 18.4 Steps and timing (a plan, not a promise)

| Week | Work | Result |
|---|---|---|
| 1 | Data model, rule-table format (impact, feasibility, risk matrix, treatment) | Schema + empty tables |
| 2 | Deterministic engine: overall impact, feasibility rating, matrix lookup | Pure functions with unit tests |
| 3 | **Reproduce the company's six rows (T1-T6)** as a test | Test passes = tables right |
| 4 | AI suggestion step with masking and checks | Draft ratings with reasons |
| 5 | Human gate + audit (CLI and API like Phase 1) | Reviewable risk workflow |
| 6 | Integration with SCRS, door-lock demo, documentation | Phase 2 demo |

### 18.5 Needs and risks

| Need | From | If missing |
|---|---|---|
| Feasibility scoring tables | Company / ISO 21434 | We use a clearly labelled placeholder |
| Risk matrix | Company | Same; the six rows fix part of it |
| Impact level definitions | Company | Same |
| Approved threats | Phase 1 | Done |
| Asset damage scenarios | Team 1 | Impact suggestions are weaker |

After Phase 2 the document's next step maps risk to required attack resistance (JIL / SESIP / EAL) with
a rule base, which fits the same "rules in tables" design.

---

# PART E. SMALL DICTIONARY

## 19. Words used in this guide

| Word | Simple meaning |
|---|---|
| **Asset** | A thing worth protecting (key, firmware, log, personal data) |
| **Threat / scenario** | A way an attacker could harm an asset, written as a short story |
| **TARA / threat modelling** | Systematically finding and rating ways a product can be attacked |
| **STRIDE** | A six-point checklist of attack types |
| **CAPEC** | Public catalogue of attack patterns |
| **ATT&CK** | Public catalogue of real attacker techniques |
| **CWE** | Public catalogue of software / hardware weaknesses |
| **Knowledge base (KB)** | Our searchable library of those catalogues |
| **Embedding / vector** | The 384 numbers that stand for the meaning of a text |
| **Cosine similarity** | A 0-to-1 score of how close two meanings are |
| **pgvector** | PostgreSQL add-on for storing and searching vectors |
| **LLM** | The language model that writes the scenario text |
| **Hallucination** | An AI inventing facts; we block invented citations with fixed checks |
| **Prompt** | The instructions and facts we give the language model |
| **Validator** | Our fixed-rule checker for the AI's output |
| **Grounding** | Making sure the output rests only on retrieved evidence |
| **FAR / FRR** | How often the checker wrongly accepts / wrongly rejects |
| **Human in the loop (HITL)** | A person approves or rejects before anything is final |
| **SCRS** | The shared state file where approved results are stored for all agents |
| **Audit log** | The diary of every action and decision |
| **Redaction / masking** | Hiding personal data and secrets before sending text to the AI |
| **Flagged / escalated** | Failed a check after the retries; needs extra human attention |
| **Determinism boundary** | Fixed rules decide; the AI only writes text |
| **API** | A way for programs (other agents) to call our service |
| **Impact / feasibility / risk** | How bad / how easy for an attacker / the combined rating (Phase 2) |
| **JIL, SESIP, EAL** | Standards describing how strong the protection must be (later step) |
| **CRA** | The EU Cyber Resilience Act, the law behind the project |
