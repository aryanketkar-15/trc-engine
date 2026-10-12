# Questions to ask the company (simple version)

Tip: ask the **Must ask** questions first. Write down the answers in the right-hand column during the meeting.

## A. Must ask (these block our progress)

| # | Question | Why we ask (one line) |
|---|---|---|
| 1 | In your sample table, the key-extraction threat (T6) is listed as **CAPEC-189**. In the public catalogue, CAPEC-189 is a different attack, and **CAPEC-622** (electromagnetic side-channel) looks closer. Which one do you mean? | So we match your expected answer and not a typing mistake |
| 2 | Do you have **your own attack patterns**, especially for **hardware / embedded devices** (your document mentions an "internal pattern id")? Can you share even 20–30 of them? | The free public catalogues are general; your examples need your own knowledge. This is our biggest gap |
| 3 | Can one of your security experts spend about an hour to mark about **190 search results** as "relevant" or "not relevant"? We prepared a sheet. | So we can measure and improve our search properly, not guess |
| 4 | For the next phase (Risk), can you share your **impact levels**, your **attack-feasibility rating table** and your **risk matrix** (how impact and feasibility give Low / Medium / High)? | We build the rules from your tables; without them we use placeholders |
| 5 | Are we allowed to send your product data to a **cloud AI service**, or must everything run **on your own machines**? | Decides which AI model we can use |

## B. Quality: what do you expect from the output?

| # | Question | Why we ask |
|---|---|---|
| 6 | For the door-lock example, your table lists six threats. Do you expect our program to **find those same six**, or is it fine if it finds **different but reasonable** threats that an expert approves? | Today we match 1 of 6 exactly; we need to know the real target |
| 7 | What would you call a **good result** for this prototype (for example: "at least 4 of 6", or "experts approve most suggestions")? | So we know when we have succeeded |
| 8 | How should threats be **ranked**: by how well they match, by attack type, or by asset? | Decides how we sort and show them |
| 9 | Do you want **multi-step attack chains** (attacker does step 1, then 2, then 3), or are single threats per asset enough for now? | Chaining is not built yet; it costs time |
| 10 | If the AI is not sure, do you prefer **more suggestions to review** or **fewer, safer suggestions**? | Sets how strict our checks should be |

## C. Standards and knowledge

| # | Question | Why we ask |
|---|---|---|
| 11 | Can you give us access to the **ISO/SAE 21434** text and the **SESIP / Common Criteria** details you use? (They are paid or unclear for us.) | Needed for citations and for Phase 2 and the mapping step |
| 12 | Besides CAPEC, ATT&CK and CWE, are there other catalogues or internal checklists your experts really use? | We loaded all free ones; we do not want to miss yours |
| 13 | Should the knowledge base be **fixed (frozen) per project version**, or updated whenever the public catalogues change? | Affects repeatability of results |

## D. Audit and approvals (CRA evidence)

| # | Question | Why we ask |
|---|---|---|
| 14 | Do your auditors need to know **who** approved each threat, and does that need a login with roles? | Our log records what and when, but not yet who |
| 15 | Must the audit log be **tamper-proof** (write-once storage, signed entries), or is a protected log enough for now? | Our log is a plain file today |
| 16 | How long must audit records be **kept**? | Affects storage design |
| 17 | What does an auditor want to see for each threat: only the final text, or also the **rejected versions and reasons**? | We keep all history; we want to show the right view |

## E. Working with the other teams

| # | Question | Why we ask |
|---|---|---|
| 18 | Which team gives us the **asset table**, and when can we get a **real example** (not made up) for the door lock? | We built our input to match; we need a real file to test |
| 19 | Are the extra details (trust zones, interfaces, data flows) going to be provided for each asset? | They make our threats more specific |
| 20 | Who decides the **IDs** (use case, asset, threat, requirement) so all teams link the same way? | Team 3 needs clean links |
| 21 | Do you want one **combined demo** at the end with all agents, and on which date should the interfaces be frozen? | Helps us plan |

## F. Practical

| # | Question | Why we ask |
|---|---|---|
| 22 | Can we use other **example products** (not only the lock and the pump) for testing? | Shows our program works for any product |
| 23 | Who is our contact person for quick questions, and how do we reach them? | Saves waiting time |
| 24 | Do you have a **template for the final TARA report** so we can write our text in the style you can quote? | Our evidence text can be shaped to fit |

## After the meeting
For each answer: write the decision, the person who said it, and the date. Then update the project journal.
