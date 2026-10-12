# The CLI demo: explained simply, and the two-person script

**Presenters:** Shriraj = Steps 1–3 · Aryan = Steps 4–7 and the close.
**Run it with:** `python scripts/scrp_demo.py` (press Enter to choose project 1, Smart Door Lock).

---

# PART 1. What the screen shows (explained like a teacher)

## The idea in one story

> A company is building a **smart door lock**. The law says they must find out **how a hacker could attack it**.
> Normally a senior security expert does this by hand, which takes days.
> Our program is a **fast junior assistant**: it reads the product description, looks in a big **library of known
> attacks**, writes a short report for each possible attack, and a **checker** makes sure the assistant did not
> make anything up. Then the **senior expert (the human) says yes or no** to every report.
> Only the "yes" reports are saved, with a diary of every decision.

Remember one sentence: **the AI proposes, the human decides.**

## What appears on the screen, in order

| Order | What you see | One-line meaning |
|---|---|---|
| 0 | A menu of projects | "Which product do you want to analyse?" |
| 1 | **Step 1/7 Understanding the system** | The program reads the product's parts |
| 2 | **Step 2/7 Planning the search** | It decides what kind of attacks to look for |
| 3 | **Step 3/7 Searching the knowledge base** | It searches the library of known attacks |
| 4 | **Step 4/7 Building attack paths** | It pairs each attack idea with the part it threatens |
| 5 | **Step 5/7 Generating threat scenarios** | The AI writes a short report for each |
| 6 | **Step 6/7 Checking the output** | Fixed rules check the AI's work |
| 7 | **Step 7/7 Your review** | The human approves or rejects each report |
| 8 | Final lines | Approved reports are saved with an audit log |

---

## Step 0: The project menu

```
Available projects:
  1   Smart Door Lock     6 assets
  2   Infusion Pump       2 assets
Select a project (1-2, default 1):
```

**Teacher explanation:** Each project is a small file describing one product. Our program is not built for only
one product: give it another file and it works. We show a door lock and a medical pump.
**An "asset"** is a thing worth protecting, like a secret key or the unlock command.

## Step 1: Understanding the system

```
Asset  Name              Must protect                              Interfaces
AS-1   Unlock Command    Integrity, Availability, Authenticity     BLE 5.0, GATT, Cloud API
```

**Teacher explanation:** Like reading a question paper before answering. For each asset the program notes what
it is, which "doors" an attacker could knock on (**interfaces**: Bluetooth, internet), and **what must be
protected**. There are four goals:

| Goal | Simple meaning | Example |
|---|---|---|
| **Confidentiality** | Kept secret | a password |
| **Integrity** | Not changed by attackers | firmware |
| **Availability** | Always works | the unlock function |
| **Authenticity** | Really from the right person or device | the unlock command |

**The privacy line:** "0 credential / personal items masked." Before anything goes to the AI, the program hides
passwords, keys, emails and phone numbers. If the product description contained `password: abc123`, the AI
would see `[REDACTED]` instead.

## Step 2: Planning the search

```
Asset  Search text               Topic tags            STRIDE to look for
AS-3   Firmware Image embedded…  crypto, firmware      Spoofing, Tampering, DenialOfService
```

**Teacher explanation:** Now the program plans what to look for. It writes a **search sentence** for each asset
and works out which of the six **STRIDE** attack types matter, using the protection goals from Step 1.

| Letter | Attack type | Everyday example |
|---|---|---|
| S | Spoofing | pretending to be the owner (replaying an unlock signal) |
| T | Tampering | changing something (a fake firmware update) |
| R | Repudiation | denying you did it (deleting the log) |
| I | Information disclosure | a secret leaks (listening to traffic) |
| D | Denial of service | making it stop working |
| E | Elevation of privilege | getting more power than allowed |

The rule: integrity → Tampering, authenticity → Spoofing, confidentiality → Information disclosure,
availability → Denial of service. **Topic tags** (cloud, firmware, crypto…) help the search choose the right area.

## Step 3: Searching the knowledge base

```
60 patterns retrieved in 24s (ATT&CK 26, CAPEC 18, STRIDE 11, CWE 5)
Asset  Pattern           Source   Similarity  Title
AS-3   ATT&CK-T1542.002  ATT&CK   0.75        Component Firmware
```

**Teacher explanation:** The **knowledge base** is our library: **2,300 known attack patterns** from free public
catalogues:

* **CAPEC**: typical attack methods ("how attackers usually do X").
* **ATT&CK**: techniques used in real attacks.
* **CWE**: common weaknesses (mistakes that attacks use).
* **STRIDE**: our six basic types.

How the search works: every pattern in the library was converted into **384 numbers that capture its meaning**.
The asset description is converted the same way. Things with similar meaning get similar numbers, so the
computer can find the closest ones. That means it can search **by meaning, not by exact words**. This is why
"firmware update over Bluetooth without a signature check" finds "Component Firmware".

**Similarity (0 to 1):** how close the meaning is. 0.75 = quite close. It is **not** the probability that the
attack is real. The first search takes ~20–50 seconds because the model loads into memory.

## Step 4: Building attack paths

```
Path           Asset  Pattern           Confidence
PATH-96F49E61  AS-4   CAPEC-665         0.77
```

**Teacher explanation:** An **attack path** here is simply *one asset + one attack pattern found for it*. The
program takes the best 6 and spreads them across the assets so every asset is covered. **Confidence** is the
similarity score again.

**Honest note:** the company also describes *chains* (step 1, then 2, then 3 of an attack). **Chaining is not built
yet**; each path is a single pattern. The screen says so, and we say so.

## Step 5: Generating threat scenarios

```
6 scenarios generated (recorded model output)
```

**Teacher explanation:** For every path, the **AI language model** gets the asset facts and the pattern text, and
must write a short report with: **the attack**, **what is exposed**, **why it applies here**, and **a citation**
(which library entry it is based on). This is the **only** creative step, and the only place AI is used.
"Recorded model output" means we replay a real earlier AI run so the demo works without internet; in live mode
the program calls the AI right now.

## Step 6: Checking the output

```
#  Asset  Pattern   Citation  Schema  STRIDE fit  Evidence  Grounded  Result
1  AS-4   CAPEC-665    ok       ok       ok         ok        ok      passed
4  AS-2   ATT&CK..     ok       ok      FAIL        ok        ok      flagged
```

**Teacher explanation:** We do **not** trust the AI. Five **fixed rules** (no AI) check every report:

| Check | Question |
|---|---|
| **Citation** | Is there a real citation? |
| **Schema** | Are all required fields filled? |
| **STRIDE fit** | Do the attack words match the attack type? |
| **Evidence** | Is the reason specific to this asset, not generic? |
| **Grounded** | Does it only cite a pattern that was really found in Step 3, for a real asset? |

If a report fails, only **that one** is redone, up to 3 times. If it still fails it is **flagged** and shown
to the human with a yellow border. **Key point: the AI cannot sneak in a made-up citation.** It can still write
imperfect wording, which is why a human approves everything.

After this you see a **results table**: one row per report (asset, attack type, pattern, confidence, passed or
flagged). It is the table of contents before the review.

## Step 7: Your review (the human gate)

```
╭─ Scenario 2 of 6 ─────────────────────────────────────────╮
│ Asset     AS-3                                             │
│ STRIDE    Tampering    Confidence 0.75   Validation passed │
│ Pattern   ATT&CK-T1542.002                                 │
│ Attack    Modifying the firmware image during a BLE OTA…   │
│ Exposure  BLE OTA interface allowing updates without sig…  │
│ Why       The firmware image lacks signature verification… │
│ Citation  ATT&CK-T1542.002: Component Firmware             │
│ Derived   AS-3 -> ATT&CK-T1542.002 (similarity 0.75)       │
│ Checks    Citation ok  Schema ok  STRIDE fit ok  ...       │
╰────────────────────────────────────────────────────────────╯
Approve this scenario? (y=yes, n=no, x=discard, a=all, q=quit; default y):
```

**Teacher explanation:** Each report is a small card.

* **Attack** = the story. **Exposure** = the weak spot. **Why** = why it applies. **Citation** = the proof.
* **Derived** = the trail: which asset matched which pattern. **Checks** = the five rules for this report.

The human types:

| Key | Meaning | What happens |
|---|---|---|
| `y` (or Enter) | yes | kept for saving |
| `n` | no | you type a **reason**; the report is regenerated and shown again (max 3 times) |
| `x` | discard | removed, with a reason, kept in history |
| `a` | approve all remaining | quick finish |
| `q` | quit | unreviewed reports are not saved |

After the last report: **"Add a scenario of your own?"** lets the expert add a threat the AI missed. It must
use a real asset, a valid attack type, and a pattern ID that really exists in the library, and it passes the
same checks.

## The ending

```
Review finished: 5 approved, 1 discarded
5 approved scenarios written to demo_output\SCRS_demo.json
audit log: 5 write, 5 approve, 2 reject, 1 prune
```

Only approved reports are saved, in the **shared state (SCRS)**, which later agents read. The **audit log** is a
diary of every approval, rejection, discard and addition with time and reason. Nothing is deleted: rejected and
discarded reports stay in the history. If you run the project again, the program shows what you approved earlier
and only proposes **new** reports.

---

# PART 2. The two-person script

**Total time ~10 minutes.** `[brackets]` = actions. Speak slowly; point at the screen while talking.

## Before the demo (checklist)

* [ ] `docker compose up -d` (wait 20 seconds).
* [ ] Wide terminal (120+ columns), big font, dark background.
* [ ] Run `python scripts/scrp_demo.py --auto` once to warm up, then clear the screen.
* [ ] Start fresh: `python scripts/scrp_demo.py --fresh`.
* [ ] Decide who types: **Aryan holds the keyboard from Step 4**. Shriraj holds it for the project menu and Steps 1–3
      (just pressing Enter).

---

## OPENING: Shriraj (about 45 seconds)

> "Good morning. We are Team TY-A9. This is **Phase 1 of our project: the Threat Agent**. It does Step 4 of your
> TARA workflow: given a list of assets, it finds possible attacks, explains them, and backs each one with a
> public attack catalogue.
> Two things to remember: **first, the AI only proposes; a human always decides**. **Second, every suggestion
> shows its evidence.**
> I will show the first three steps: how the program understands the product and searches. My teammate Aryan
> will show how the reports are written, checked and approved."

`[Run: python scripts/scrp_demo.py]`

## MENU: Shriraj (about 20 seconds)

> "First, we choose the project. Each one is a small file describing a product. Our program works for any
> product: here is a door lock and a medical pump. We choose the door lock."

`[Press Enter]`

## STEP 1: Shriraj (about 60 seconds)

> "**Step 1: understanding the system.** The program reads each part of the product, called an asset: the unlock
> command, the keys, the firmware, the audit log, and so on.
> For each asset, it records the interfaces, meaning the ways it can be reached, like Bluetooth or the cloud,
> and what must be protected. There are four goals: keep it secret, keep it unchanged, keep it working, and keep
> it genuine.
> Look at this line: **privacy**. Before anything is sent to the AI, passwords, keys and personal data are hidden.
> Here it says zero because our description has none, but if it did they would be masked."

`[Point at the asset table, then the privacy line]`

## STEP 2: Shriraj (about 60 seconds)

> "**Step 2: planning the search.** Now the program decides what to look for. It writes a search sentence for
> each asset and works out which kinds of attack matter.
> We use the **STRIDE** checklist: six attack types, such as pretending to be someone, changing something, or
> making it stop working.
> The rule is simple: if integrity must be protected, look for tampering; if it must be genuine, look for
> spoofing; and so on. See this column: for the firmware image it will look for spoofing, tampering and denial of
> service."

`[Point at the "STRIDE to look for" column on the AS-3 row]`

## STEP 3: Shriraj (about 90 seconds)

> "**Step 3: searching our knowledge base.** This is our library of known attacks: **2,300 patterns** from free
> public catalogues: CAPEC for attack methods, ATT&CK for real attacker techniques, and CWE for common
> weaknesses.
> The search works by **meaning, not by exact words**. Each pattern and each asset description is turned into a
> list of numbers that stands for its meaning, and the computer finds the closest ones.
> Here it found 60 patterns. Look at the firmware image: it matched **'Component Firmware'**, with a similarity of
> 0.75. That is exactly the right idea. The similarity score only says how close the meaning is. It does not say
> that the attack is certain.
> That is the end of my part. Aryan will now show what we do with these patterns."

`[Point at the retrieved-count line, then the AS-3 row. Hand over the keyboard to Aryan]`

---

## STEP 4: Aryan (about 45 seconds)

> "Thank you, Shriraj. **Step 4: attack paths.** A path is simply one asset together with one attack pattern found
> for it. The program takes the best six, spread across the assets so every asset is covered.
> We want to be honest about one limit: your document also describes **chains**, several attack steps one after
> another. That part is **not built yet**. Today each path is a single pattern, and the screen says so."

`[Point at the path table and the warning line]`

## STEP 5: Aryan (about 45 seconds)

> "**Step 5: writing the reports.** For each path, the AI receives the asset facts and the pattern text. It must
> write the attack, what is exposed, why it applies here, and a **citation** of the pattern.
> This is the **only step where the AI is used**. In this demo we replay a real earlier AI run so it works
> without internet, but we can run it live as well. Everything before and after this step is fixed rules."

`[Point at "6 scenarios generated"]`

## STEP 6: Aryan (about 75 seconds)

> "**Step 6: checking.** We do not simply trust the AI. Five **fixed rules**, with no AI, check every report:
> is there a citation, are all fields filled, does the attack match its type, is the reason specific to this
> asset, and does it only cite a pattern that was really found.
> That last rule is important: **the AI cannot invent a citation**.
> See this row: the STRIDE check failed, so this report is **flagged**. Normally only the failed report is redone,
> up to three times; if it still fails, we show it to the human with a warning rather than hiding it.
> Here is the results table: five passed and one flagged."

`[Point at the FAIL cell, then at the results table]`

## STEP 7: Aryan (about 3 minutes)

> "**Step 7: the human review.** This is the most important part. Each report is a card with the attack, the
> weak spot, the reason, the proof, where it came from, and the result of the five checks. Nothing is saved until
> a human says yes."

`[Scenario 1: press Enter]` > "I approve this one."

`[Scenario 2: type n, Enter, then type the reason]`
**Reason to type:** `Too generic. Name the specific interface, such as the BLE characteristic, and say how the attacker reaches it.`

> "I reject it and give a reason. The reason is saved. In live mode the AI rewrites only this report using my
> comment, and it is checked again. I can do this up to three times. In this recorded demo the screen shows the
> next alternative and says so."

`[Next scenario: type x, Enter, reason: Out of scope for this variant.]`

> "I can also **discard** a report. It is removed from the result but kept in the history with my reason."

`[Type a to approve the rest]`

> "Now the expert can **add a threat the AI missed**."

`[Type y at "Add a scenario of your own?" and enter these answers in order:]`

| Prompt | Type |
|---|---|
| Asset | `AS-1` |
| STRIDE | `Spoofing` |
| Pattern id | `CWE-306` |
| Attack description | `Impersonation of a legitimate caller to the Unlock Command through an unauthenticated management interface (identity spoofing)` |
| What is exposed | `Unlock Command interface accepts requests without caller authentication` |
| Why it applies | `The Unlock Command is reachable over its interface and no caller authentication is enforced before the critical function runs.` |
| Citation | `CWE-306: Missing Authentication for Critical Function` |
| Why adding | `Known weakness class for this product family` |

> "It is checked like the AI's work, and the pattern ID must really exist in the library."

`[Wait for the final lines]`

> "Only approved reports are saved, in the shared state that other agents read, together with an **audit log**:
> every approval, rejection, discard and addition, with time and reason. Nothing is deleted. If we run the project
> again, it shows what we approved earlier and only proposes new reports."

## CLOSE: Aryan (about 60 seconds)

> "To summarise: **the AI proposes, fixed rules check, and a human decides.** Every report carries its evidence
> and its trail.
> What works today: the full flow from assets to approved, logged reports, with over 300 automatic tests.
> What we are honest about: on your six reference threats we match one of six, because the free catalogues do not
> contain your internal patterns; and attack chaining is not built yet.
> What would help us most: your internal threat patterns, an expert to judge about 190 search results, and your
> risk-rating tables for Phase 2. Thank you. We are happy to take questions."

---

# PART 3. Likely questions, and who answers

| Question | Who | Short answer |
|---|---|---|
| What exactly is the knowledge base? | Shriraj | 2,300 attack patterns from free MITRE catalogues (CAPEC, ATT&CK, CWE) plus our STRIDE rules, and 5,000+ standards text pieces. ISO 21434 is paid and not loaded |
| Is the search keyword-based? | Shriraj | No, it is by meaning (384-number vectors, closest match) |
| What does the similarity score mean? | Shriraj | How close the meaning is, not the probability of the attack |
| What if the product description has secrets? | Shriraj | Passwords, keys, emails, phones, IPs and tokens are masked before the AI sees them |
| Can the AI hallucinate? | Aryan | Its wording can be imperfect, so a human approves each one; but it cannot invent a citation because code checks that the cited pattern was really found |
| What happens to a flagged report? | Aryan | It is retried up to 3 times; if it still fails it is shown to the human with a warning |
| Is this accurate? | Aryan | We match 1 of your 6 reference threats; the checker wrongly accepts 15% and wrongly rejects 8% on our test; the human gate is the quality control |
| Where is the data saved? | Aryan | Approved reports and the audit log in the shared-state file; in the API version, runs are also stored in PostgreSQL |
| Does it work for any product? | Shriraj | Yes, give it another asset file; we show a lock and a pump |
| What about chains of attacks? | Aryan | Not built yet; planned extension |
| What do you need from us? | Aryan | Internal patterns, an expert's judgement of search results, risk tables for Phase 2, and the CAPEC-189 vs CAPEC-622 clarification |

## If something goes wrong

* **Database not running** → `docker compose up -d`, wait 20 seconds, run again.
* **Screen too narrow** (tables cut off) → make the window wider or reduce the font.
* **Live mode fails** (no internet or no AI credit) → use the default recorded mode.
* **You typed a wrong answer** → press `q`, then start again with `python scripts/scrp_demo.py --fresh`.
