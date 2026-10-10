# Phase 1 Explained in Simple Words, Demo Script and Phase 2 Plan

*For Group TY-A9. Read this before the company meeting. Everything here is written the way you
would explain it to a classmate: simple words, one idea at a time.*

**Contents**

1. The project in one minute
2. What the company asked for (and what Phase 1 is)
3. What we built, mapped to the company document
4. The demo on the command line, explained screen by screen
5. The demo script to speak in the meeting
6. Honest status: what is done, what is not, and our numbers
7. Questions for the company
8. Phase 2 (Risk Agent): the plan
9. Small dictionary

---

## 1. The project in one minute

When a company builds a smart product (a door lock, a medical pump, a car part), the law (the EU
**Cyber Resilience Act**, CRA) says they must find out **how hackers could attack it** and **write down
what they did about it**. That job is called **threat modelling** (the standard way to do it is
**ISO/SAE 21434 TARA**).

Today, experts do this by hand. It is slow, different every time, and hard to prove to an auditor.

Our project, **SCRP**, builds an **AI assistant that does the first draft of this work**, while
**humans stay in charge**. The AI proposes. The expert checks, accepts or rejects. Every decision is
saved so that an auditor can follow it later.

The company document splits the work into steps. Different agents (small programs) do different steps:

| Step | What happens | Who builds it |
|---|---|---|
| 1-2 | Capture the use case, draw diagrams | other teams |
| 3 | List the assets (things worth protecting) | Team 1 |
| **4** | **Find the threats (attacks) for each asset** | **us: the Threat Agent = Phase 1** |
| 5 | Score the risk (how bad, how easy) | **us: Phase 2, the Risk Agent** |
| 6 | Decide how strong the protection must be | later |
| 7-10 | Write requirements, reports, checks | later |

**Phase 1 = Step 4: the Threat Agent.** You give it a list of assets. It gives back a list of
possible attacks, each one backed by evidence from a known attack catalogue.

---

## 2. What the company asked for (and what Phase 1 is)

The company document (Section 3.2, row 4) says, in plain words:

> **Threat identification.** *Retrieve relevant threat patterns; propose threat scenarios with
> rationale and knowledge-base references.*
> Input: assets + diagrams + knowledge base. Output: a ranked threat list with citations.
> Human checkpoint: **the expert prunes or adds.**

So the Threat Agent must:

1. **Look into a knowledge base** of known attacks (STRIDE, CAPEC, ATT&CK, CWE ...).
2. **Pick the attacks that fit each asset.**
3. **Write a threat scenario** for each: what the attack is, why it applies, and **which catalogue
   entry proves it**.
4. **Let a human prune (remove) or add** scenarios.

The document also has a list of rules for *every* AI part (Section 3.4). We followed all of them
that apply to Phase 1. See the table in the next section.

---

## 3. What we built, mapped to the company document

### 3.1 The pipeline (the path the data takes)

```
Assets (JSON)  ->  Understand  ->  Plan search  ->  Search knowledge base  ->  Attack paths
   ->  AI writes scenarios  ->  Automatic checks  ->  HUMAN approves / rejects  ->  Saved (SCRS)
```

Plain meaning of each part:

* **Understand.** Read each asset: its name, type, interfaces (BLE, HTTPS ...), and what must be
  protected (secret? unchanged? always available? genuine?).
* **Plan search.** Turn each asset into a search sentence and work out which kinds of threats apply.
* **Search the knowledge base.** Find the most similar attack patterns (explained in 4.3).
* **Attack paths.** Pair each found pattern with its asset.
* **AI writes scenarios.** A language model writes the attack story, but **only using the pattern it
  was given**.
* **Automatic checks.** Programs (not AI) check the AI's work. Bad work is redone.
* **Human gate.** A person says yes or no. Only "yes" is saved.
* **Saved.** Approved scenarios go to the shared state file (**SCRS**) with a full history.

### 3.2 The company's rules (Section 3.4) and how we did them

| Company rule | What it means | What we did |
|---|---|---|
| **Citations** | Every suggestion must point to a knowledge-base item | Every scenario has a `kb_reference` (like `CAPEC-665`) and a citation text. The program **checks** that the AI only cites a pattern that search really returned. Invented citations are impossible. |
| **Confidence and review flags** | Mark AI output with confidence; "needs review" until a human approves | Each scenario has a confidence score. If it fails a check after retries it is marked **flagged**. Nothing is final until a human approves. |
| **Human in the loop** | AI proposes, humans decide | The approve / reject / discard step. Nothing reaches the saved state without a "yes". |
| **Non-overwrite** | AI never silently replaces approved content | When a scenario is replaced, the old one is kept in the history marked "superseded". Rejected and pruned content is never deleted. |
| **Auditability** | Log what was retrieved, which model, human decisions | We log: the patterns retrieved for every asset, the model and prompt version, every rejection with the reason, every prune and add. |
| **Traceability** | Link each output to its inputs | Each scenario carries the use-case id, the asset id and version, and the knowledge-base version. |
| **Determinism boundary** | Use fixed rules where possible; AI only for language | All checking is done by fixed rules in code. The AI only writes the explanation text. |
| **Privacy and secrets** | Remove personal data and credentials before sending to the AI | A masking step replaces emails, phone numbers, IP addresses, passwords, API keys, tokens and private keys with `[REDACTED...]` before anything is sent. |
| **Explainability** | Each suggestion shows its reason and evidence | Every scenario has: what is exposed, why it applies, which pattern matched, and the citation. |
| **Expert prunes or adds (Step 4)** | The human can remove or add threats | `x` = discard with a reason. "Add a scenario of your own" = expert add, which is also checked. |

**Not done / partly done:** data-residency (where data may be processed) is not handled; we store the
*prompt version*, not the full prompt text. Both are listed in Section 6.

### 3.3 The knowledge base (the "library of known attacks")

The company document lists **STRIDE, CAPEC, ATT&CK, ISO catalogues**. We loaded everything that is
**free**:

| Source | What it is | Entries |
|---|---|---|
| **CAPEC** | Catalogue of attack patterns (how attackers act) | 556 |
| **ATT&CK** | Real-world attacker techniques (enterprise + industrial) | 794 |
| **CWE** | Catalogue of software and hardware weaknesses | 944 |
| **STRIDE** | The six basic threat types | 6 |
| **Total patterns** | | **2,300** |
| Standards text | Common Criteria / CEM / JIL / EU CRA documents, cut into pieces | 5,097 pieces |

**Not loaded:** ISO/SAE 21434 itself (it is paid) and the company's own internal patterns (we do not
have them). We also have a small 24-entry set that the automatic tests use. The real program uses the
big one by default.

### 3.4 The safety net: why the AI cannot just make things up

Two layers, both fixed rules (no AI):

**Layer 1 - four validator checks** (measured: wrongly accepts 15.38%, wrongly rejects 8.33% on our
test set):
1. **Citation present** - there is a real citation, not "TBD".
2. **Schema complete** - all required fields are filled.
3. **STRIDE fit** - the attack words match the threat type (a "replay" attack is Spoofing, not DoS).
4. **Evidence specific** - the reason is about this asset, not generic words.

**Layer 2 - grounding rules:**
5. **Grounded** - the scenario cites only a pattern that search really returned, points to a real
   asset, and the exposure it names is a real property of that asset.

If a scenario fails, **only that scenario** is redone (up to 3 tries). That saves AI cost. If it
still fails, it is **flagged** and shown to the human.

> **Be honest in the meeting:** these checks make *invented citations* impossible. They do **not**
> prove the story is technically perfect. That is exactly why a human approves.

### 3.5 Other things we built

* A **web API** (FastAPI) with the same workflow: start a run, approve, reject, prune, add.
* A **database** that remembers runs.
* **Over 300 automatic tests** that all pass.

---

## 4. The demo on the command line, explained screen by screen

You start it with:

```
python scripts/scrp_demo.py
```

### 4.1 The project menu

```
Available projects:
  #   Project           Assets   File
  1   Smart Door Lock        6   ...fixtures\smart_door_lock\input.json
  2   Infusion Pump          2   ...fixtures\infusion_pump\input.json
Select a project (1-2, default 1):
```

**What it is:** a list of "project files" (JSON). Each file describes one product and its assets.
**Why it matters:** the same program works for *any* product: just give it another JSON. We show a
door lock and a medical pump to prove it is not built for one product only.

### 4.2 Step 1: Understanding the system

The agent prints each asset and what it **must protect**:

* **Confidentiality** - secret, nobody else may read it (like a password).
* **Integrity** - must not be changed (like firmware).
* **Availability** - must always work (like the unlock command).
* **Authenticity** - must be genuine, from the right person.

It also prints **"Privacy: N items masked"**: before any text goes to the AI, secrets and personal data
are hidden.

**Say it simply:** "First the agent reads the asset sheet like a student reads a question paper."

### 4.3 Step 2: Planning the search

For each asset the agent writes a **search sentence** and works out which **STRIDE** types apply.
STRIDE is a checklist of six ways to attack:

| Letter | Meaning | Easy example |
|---|---|---|
| **S** | Spoofing | pretending to be someone else (replaying an unlock) |
| **T** | Tampering | changing data (modified firmware) |
| **R** | Repudiation | denying you did it (deleting the log) |
| **I** | Information disclosure | secrets leak (listening to traffic) |
| **D** | Denial of service | making it stop working |
| **E** | Elevation of privilege | getting more power than allowed |

The rule: *integrity needs -> Tampering; authenticity -> Spoofing; confidentiality -> Information
disclosure; availability -> Denial of service.* The "topic tags" (cloud, firmware, crypto ...) help
the search choose the right area.

### 4.4 Step 3: Searching the knowledge base

This is the "smart search". Simple version:

1. Every attack pattern in the library was turned into a **list of 384 numbers** that captures its
   meaning (a "vector"). Similar meanings give similar numbers.
2. Our search sentence is turned into numbers the same way.
3. We find the patterns whose numbers are **closest** (cosine similarity, a score from 0 to 1).
4. Patterns whose topic tags match the asset get a **small bonus**.

The screen shows the **best matches per asset** with their **similarity** (for example 0.77). Higher
= more similar. This is also the line `60 patterns retrieved (ATT&CK 26, CAPEC 18, ...)`.

**Say it simply:** "It is like searching a library by meaning, not by exact words."

### 4.5 Step 4: Building attack paths

An **attack path** here = one asset + one pattern found for it. The agent takes the best 6, spread
across the assets so every asset gets attention.

> **Honest note (say it before they ask):** the company also describes *chains* of several patterns
> (step 1 then step 2 then step 3 of an attack). **That multi-step chaining is not built yet.** Today
> each path is one pattern. It is listed as a planned extension.

### 4.6 Step 5: Generating scenarios

For every path, the AI model gets: the asset facts + the pattern text. It must write: **the attack,
what is exposed, why it applies, and a citation.** In recorded mode this line says
"(recorded model output)": we replay a real earlier model run so the demo works without internet.
With `--mode live` the model is really called.

### 4.7 Step 6: Checking the output (the table)

```
#  Asset  Pattern  Citation  Schema  STRIDE fit  Evidence  Grounded  Result
1  AS-4   CAPEC-665   ok       ok       ok         ok        ok      passed
4  AS-2   ATT&CK..    ok       ok      FAIL        ok        ok      flagged
```

Each column is one automatic check from Section 3.4. `FAIL` means that check did not pass; the
result is `flagged`, meaning "human, look at this one carefully".

### 4.8 The results table

One row per scenario: asset, STRIDE letter, pattern, confidence, passed or flagged, and the start of
the attack text. A quick overview before the detailed review.

### 4.9 Step 7: Your review (the human gate)

Each scenario is shown as a card:

```
Asset       AS-3
STRIDE      Tampering   Confidence 0.75   Validation passed
Pattern     ATT&CK-T1542.002
Attack      Modifying the firmware image during a BLE OTA update ...
Exposure    BLE OTA interface allowing firmware updates without signature verification
Why         The firmware image lacks signature verification ...
Citation    ATT&CK-T1542.002: Component Firmware
Derived     AS-3 -> ATT&CK-T1542.002 (similarity 0.75)
Checks      Citation ok  Schema ok  STRIDE fit ok  Evidence ok  Grounded ok
```

* **Attack** - the story. **Exposure** - the weak spot on the asset. **Why** - the reason it applies.
* **Citation** - the catalogue entry that backs it up.
* **Derived** - the trail: this asset matched this pattern with this similarity.
* **Checks** - the five automatic checks for *this* scenario.

You then answer:

| Answer | Meaning | What happens inside |
|---|---|---|
| `y` or Enter | yes | scenario is kept for saving |
| `n` | no | you type a **reason**; the reason is saved; the scenario is **regenerated** and shown again; checks run again; allowed **3 times** |
| `x` | discard | removed, with your reason, kept in history |
| `a` | approve all remaining | quick finish |
| `q` | quit review | unreviewed ones are not saved |

**What the "regenerate" really does (live mode):** your reason is added to the AI's instructions
("the reviewer said: ..."), only that one scenario is written again, and it goes through all checks
again. **In recorded mode** the reason is saved but the screen shows the next recorded alternative
(it says so on screen).

### 4.10 Adding your own scenario

After the last scenario, "Add a scenario of your own?" lets the expert type one in. It must name an
asset that exists, a valid STRIDE type, a pattern id that **really exists in the knowledge base**, and
must pass the same checks as AI output. Example you can type:

| Prompt | Type |
|---|---|
| Asset | `AS-1` |
| STRIDE category | `Spoofing` |
| Pattern id | `CWE-306` |
| Attack description | `Impersonation of a legitimate caller to the Unlock Command through an unauthenticated management interface (identity spoofing)` |
| What is exposed | `Unlock Command interface accepts requests without caller authentication` |
| Why it applies | `The Unlock Command is reachable over its interface and no caller authentication is enforced before the critical function runs.` |
| Citation text | `CWE-306: Missing Authentication for Critical Function` |
| Why are you adding it | `Known weakness class for this product family` |

To show the safety net, type the attack `Heavy rainfall damages the enclosure` instead: the checker
refuses it because it does not match "Spoofing".

### 4.11 The last lines: saving

```
Review finished: 5 approved, 1 discarded
ok  5 approved scenarios written to demo_output\SCRS_demo.json
    audit log: 5 write, 5 approve, 2 reject, 1 prune
```

* **SCRS** = the shared state file that all agents will read (Phase 2 will read from it).
* **audit log** = a diary: every write, approval, rejection, prune and add, with time and reason.
* For the demo this goes to the folder `demo_output`, so your real file is never touched.

---

## 5. The demo script to speak in the meeting

*Target time: 10-12 minutes. Open the terminal in the `trc-engine` folder beforehand. Run the
command once before the meeting so the model is loaded and the database is up (`docker compose up -d`).*

### Before they arrive (checklist)

* [ ] `docker compose up -d` and wait 20 seconds.
* [ ] Terminal wide (at least 120 columns), dark background, large font.
* [ ] `.env` has a working key if you want live mode. If not, use the default recorded mode.
* [ ] Run `python scripts/scrp_demo.py --auto` once as a rehearsal.
* [ ] Have the two files open: this document and `docs/research/final_fullkb_addendum.md`.

### Opening (1 minute)

> "Good morning. Our project is SCRP. Phase 1 is the **Threat Agent**: Step 4 of your TARA workflow.
> It takes the asset list and proposes threat scenarios, each backed by an entry from a public attack
> catalogue. **The AI only proposes. A human decides.** I will show it working on a smart door lock,
> then on a medical pump to show it is not tied to one product."

### Part 1: Pick the project (30 seconds)

*Run:* `python scripts/scrp_demo.py` *and press Enter for project 1.*

> "This menu lists project files. Each is a JSON with the assets of one product. Any new product is
> just a new JSON file."

### Part 2: Steps 1-2, understanding and planning (1.5 minutes)

> "First the agent reads each asset: what it is and what must be protected. Confidentiality,
> integrity, availability, authenticity. Notice the privacy line: before anything goes to the AI,
> credentials and personal data are masked.
> Next it plans the search. From the security needs it works out the STRIDE threat types to look for.
> Integrity maps to Tampering, authenticity to Spoofing, and so on."

### Part 3: Step 3, knowledge base search (2 minutes)

> "Now the search. Our library has **2,300 attack patterns** from the free MITRE catalogues, CAPEC,
> ATT&CK and CWE, plus STRIDE, and over 5,000 text pieces from Common Criteria and the CRA.
> The search works by **meaning**, not exact words: each pattern and each asset description becomes a
> list of numbers, and we take the closest ones. This table shows the best matches for every asset
> with the similarity score."

*Point at one row, e.g. AS-3 Firmware Image matched to ATT&CK Component Firmware (0.75).*

> "For the firmware image it found 'Component Firmware', which is the right idea."

### Part 4: Steps 4-6, paths, generation and checks (2.5 minutes)

> "Each match becomes an attack path. We have not built **multi-step chains** yet; today each path is
> a single pattern. I want to be upfront about that.
> Then the AI writes a scenario for each path. It must give the attack, what is exposed, why it
> applies, and a citation.
> And here is our main safeguard: the AI is not trusted. Five **fixed-rule checks**, no AI involved,
> examine every scenario. A scenario can only cite a pattern that was really retrieved, so it cannot
> invent a citation. If a scenario fails, only that one is redone, up to three times. If it still
> fails, it is flagged for the human. You can see one flagged row here."

*Point at the FAIL cell.*

### Part 5: Human review, the important part (3 minutes)

> "Now the human gate. Each scenario is a card with the attack, the exposure, the reason and the
> citation. At the bottom: where it came from, and the result of the five checks."

*Press Enter on scenario 1 (y).*

> "I approve this one."

*On scenario 2 type `n`, then the reason:*

`Too generic. Name the specific interface, such as the BLE characteristic, and say how the attacker reaches it.`

> "I reject it and say why. The reason is saved in the audit trail. In live mode the agent gives the
> reason to the model, rewrites only this scenario, checks it again and shows it to me again. I can
> reject up to three times. In this recorded demo, the screen shows the next alternative and says so."

*Approve the next one. On a later one type `x` and the reason `Out of scope for this variant.`*

> "I can also discard a scenario with a reason. It is not deleted from history."

*Type `a` to approve the rest. Then answer `y` to "Add a scenario of your own?" and type the
example from Section 4.10.*

> "The expert can add a threat the AI missed. It is checked like the AI output. The pattern id must
> exist in the library; try a wrong one and it is refused."

### Part 6: Saving and the audit trail (1 minute)

> "Only approved scenarios are written to the shared state, the SCRS. Here is the audit log: writes,
> approvals, rejections with reasons, prunes and adds. Nothing is deleted: rejected and replaced
> content stays in the history. This is the traceability your document asks for."

### Part 7: Honest status and close (1.5 minutes)

> "To be transparent:
> * **Working:** the whole pipeline from assets to approved, audited scenarios, with 300+ tests.
> * **Accuracy:** on your six reference threats for the door lock, we match **1 of 6** at our
>   similarity threshold; two more are close. The reason is that the free library is general, and your
>   own patterns and ISO 21434 text are not in it yet.
> * **Not built:** multi-step chains; the adapter for the Team 1 asset table (we need four extra fields
>   from them).
> * **Next:** Phase 2, the Risk Agent, which scores impact and feasibility as in Section 2.6.
>
> What would help us most: your internal threat patterns, an expert to judge about 190 search results,
> and your risk rating tables for Phase 2."

### If they ask... (prepared answers)

| Question | Honest answer |
|---|---|
| **Can the AI hallucinate?** | The *story text* can be imperfect, so a human approves everything. But *citations* cannot be invented: code checks that the cited pattern was really retrieved. |
| **Why only 1 of 6?** | The free catalogues are generic; your six reference rows use hardware/internal knowledge that is not in them. Their table also seems to label one pattern (CAPEC-189) that probably should be CAPEC-622. Please confirm. |
| **Does it work for any product?** | Yes, give it another asset JSON. We showed a door lock and a pump. It works best when the asset sheet is detailed. |
| **Does our data go to the cloud?** | Only redacted text goes to the language model, and only the asset facts. We would like your decision on cloud use or an on-premise model. |
| **Which standards are covered?** | CAPEC, ATT&CK, CWE, STRIDE and text from Common Criteria, CEM, JIL, EU CRA. ISO/SAE 21434 is paid; we need access or a licence. |
| **Why are some scenarios flagged?** | They failed an automatic check after three retries. We show them on purpose instead of hiding them. |
| **Is it deterministic?** | Retrieval, checks and saving are deterministic. The AI text varies between runs, which is why we store the run id, model and prompt version. |
| **How much does a run cost?** | The door-lock run used about 220,000 input tokens (a few cents with gpt-4o-mini). Retrying only failed scenarios cut that roughly in half. |

---

## 6. Honest status: what is done, what is not, and our numbers

### Done (and tested)

* The whole Step 4 workflow with the human gate (approve, reject-and-regenerate, discard, expert add).
* The full free knowledge base (2,300 patterns, 5,097 standards chunks).
* Automatic checks (4 validator checks + grounding), retry-only-what-failed.
* Masking of personal data and secrets.
* Traceability fields, audit log, non-overwrite history.
* A web API with the same workflow, a run database, and 300+ passing tests.
* A command-line demo for any project JSON.

### Not done

| Item | Why |
|---|---|
| **Multi-step attack chaining** | The chaining function is a placeholder. Each path is one pattern. |
| **Team 1 adapter** | Team 1's table lacks trust zone, interfaces, data flows and device config. |
| **ISO/SAE 21434, SESIP** catalogues | Paid or unclear licence. |
| **Company internal patterns** | We do not have them. |
| **Data-residency rules** | Needs the company's policy. |
| **Full prompt text in the audit log** | We store prompt version and model, not the whole text. |

### Our numbers (use them exactly)

| Measurement | Result |
|---|---|
| Patterns in the knowledge base | 2,300 (+ 5,097 standards pieces) |
| Validator error rates | wrongly accepts 15.38%, wrongly rejects 8.33% |
| Company's six reference threats (door lock, full knowledge base, gpt-4o-mini) | **1 of 6 matched** at similarity 0.75; near misses at 0.745 and 0.703 |
| Scenarios generated in the final run | 60 (36 passed, 24 flagged for review) |
| Earlier run on the small 24-entry set | 2 of 6 (older version) and 1 of 6 (newer) |
| Automatic tests | over 300, all passing |

**Do not say:** "it reproduces the company's threat table" or "Run 8 used the whole dataset". The
accurate sentence: *"On your door-lock example it produces grounded scenarios for every asset and
matches 1 of your 6 reference threats; we need your internal patterns and an expert's judgements to
improve this."*

---

## 7. Questions for the company

1. Please confirm **CAPEC-189 vs CAPEC-622** in the T6 row of your table.
2. Can you share **internal or hardware threat patterns** ("internal pattern id" in Section 3.4)?
3. Can an expert **judge about 190 search results** (we prepared a sheet) so we can tune the search?
4. Access to **ISO/SAE 21434** text and the **SESIP** terms? (for Phase 2 and the mapping step)
5. Are **cloud language models** allowed for your data, or must it run on-premise?
6. For Phase 2: your **attack-feasibility rating tables** and **risk matrix** (see Section 8).
7. Is a **ranked list** enough, or do you want threats grouped per STRIDE category?
8. Should the **5 automatic checks** and the 3-retry limit match any company policy?

---

## 8. Phase 2 (Risk Agent): the plan

### 8.1 What the company wants (Section 2.6 and Step 5)

Step 5 of the document: *score impact (S/F/O/P) and attack feasibility (time, expertise, knowledge,
window, equipment). Input: threats + context. Output: risk score + justification. Human checkpoint:
the expert adjusts.*

In simple words, for **every approved threat** the Risk Agent must say:

1. **How bad is it?** (Impact) on four axes: **S**afety, **F**inancial, **O**perational, **P**rivacy,
   each from *Negligible* to *Severe*. The **overall impact** is the worst of the four.
2. **How easy is it for the attacker?** (Attack feasibility) using five factors from ISO 21434
   section 15.5: **elapsed time, expertise, knowledge of the item, window of opportunity,
   equipment**. The result is a level, e.g. Low / Medium / High.
3. **How risky is it?** Combine impact and feasibility using a **risk matrix** -> Low / Medium / High.
4. **What to do about it?** The **risk treatment decision**: **Reduce / Share / Retain / Avoid**, with
   the reason.

The company's own worked example gives six rows to test against:

| Threat | Impact S/F/O/P | Overall impact | Feasibility | Risk |
|---|---|---|---|---|
| T1 | -/Mod/Sev/Mod | Severe | Medium | High |
| T2 | -/Sev/Sev/Sev | Severe | Medium | High |
| T3 | Mod/Sev/Sev/Sev | Severe | Medium | High |
| T4 | -/Neg/Mod/Sev | Moderate | Low | Medium |
| T5 | -/Mod/Sev/- | Moderate | High | Medium |
| T6 | -/Sev/Sev/Sev | Severe | Low | Medium |

Two things we can already see: overall impact = the **highest** axis; and the matrix is not a simple
formula (Moderate+High and Severe+Low both give Medium), so the matrix must be a **table we can
configure**, not hard-coded logic.

### 8.2 Design: rules in tables, AI only for suggestions

The company's "determinism boundary" says: fixed rules for decisions, AI only for language. So:

* **Fixed rules (tables in a config file):** impact levels, feasibility scoring, the risk matrix, the
  treatment options. Easy to change when the company gives us their real tables.
* **AI (suggestion only):** propose the ratings per axis and the written justification for each
  threat ("why Severe for Operational?"), using the scenario's evidence.
* **Human:** the expert sees each rating, can change it, and approves. Changes are logged like in
  Phase 1.

### 8.3 What it reads and writes

* **Reads:** the approved threat scenarios from the SCRS (written by Phase 1) plus asset damage
  information.
* **Writes:** a `RiskAssessment` per threat to the SCRS: impact per axis, overall impact, feasibility
  factors, feasibility level, risk value, treatment decision, justification, who changed what.
* Same rules as Phase 1: citations to the rules used, non-overwrite, audit log, traceability
  (threat id -> risk id).

### 8.4 Steps and rough timing

| Week | Work | Result |
|---|---|---|
| 1 | Define the data model, rule tables and config format (impact levels, feasibility, risk matrix, treatment) | Schema + empty tables |
| 2 | Build the deterministic engine: overall impact = max of axes, feasibility rating, risk matrix lookup | Pure functions with unit tests |
| 3 | **Reproduce the company's six rows** exactly as a test (T1-T6) | Test passes = tables are right |
| 4 | AI suggestion step: propose axis ratings and justification from the scenario (with redaction and checks) | Draft ratings with reasons |
| 5 | Human gate: expert adjusts ratings, approves, treatment decision, audit log | CLI + API like Phase 1 |
| 6 | Integrate with SCRS; demo on the door lock; documentation; write-up | Phase 2 demo |

Timing is a plan, not a promise: it depends on getting the company's rating tables early.

### 8.5 How we will test it

* **The six company rows (T1-T6)** are the main test: given their inputs, our rule engine must output
  their overall impact and risk.
* Unit tests for each table lookup, edge cases (a "-" axis means no impact on that axis).
* The same safeguards as Phase 1: checks on AI suggestions, human approval, audit trail.

### 8.6 What we need and the risks

| Need | From | Risk if missing |
|---|---|---|
| Feasibility scoring tables (how factor values map to Low/Medium/High) | Company / ISO 21434 | We use a clearly-labelled placeholder table |
| The risk matrix | Company | Same; our 6-row test fixes part of it |
| Impact level definitions per axis | Company | Same |
| Approved threats from Phase 1 | us | Done |
| Team 1 data (asset damage scenarios) | Team 1 | Impact suggestions will be weaker |

After Phase 2, the next step in the document is mapping risk to required attack resistance (JIL /
SESIP / EAL) with a rule base, which fits the same "tables in config" design.

---

## 9. Small dictionary

| Word | Simple meaning |
|---|---|
| **Asset** | Something worth protecting (a key, firmware, a log, personal data) |
| **Threat / scenario** | A way an attacker could harm an asset, written as a short story |
| **Threat modelling / TARA** | Systematically finding and rating the ways a product can be attacked |
| **STRIDE** | A 6-point checklist of attack types |
| **CAPEC** | Public catalogue of attack patterns |
| **ATT&CK** | Public catalogue of real attacker techniques |
| **CWE** | Public catalogue of software / hardware weaknesses |
| **Knowledge base (KB)** | Our library of those catalogues, searchable by meaning |
| **Embedding / vector** | The list of 384 numbers that stands for the meaning of a text |
| **Cosine similarity** | A score (0 to 1) of how close two meanings are |
| **LLM** | The language model (AI) that writes the scenario text |
| **Hallucination** | When an AI invents facts; we block invented citations with fixed checks |
| **Validator** | Our fixed-rule checker for the AI's output |
| **Grounding** | Making sure the output rests only on retrieved evidence |
| **Human in the loop (HITL)** | A person approves or rejects before anything is final |
| **SCRS** | The shared state file where approved results are stored for all agents |
| **Audit log** | The diary of every action and decision |
| **Redaction** | Hiding personal data and secrets before sending text to the AI |
| **Flagged** | Failed an automatic check after retries; needs extra human attention |
| **Impact / feasibility / risk** | How bad it would be / how easy for an attacker / the combined rating (Phase 2) |
| **JIL, SESIP, EAL** | Standards that describe how strong protection must be (later step) |
| **CRA** | The EU Cyber Resilience Act (the law behind the project) |
