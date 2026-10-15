# Infineon review meeting, 12 Oct 2026: what the company said and what it means for us

*Source: the auto-generated transcript (names and some words are garbled, for example "Lama 3", "Infinion", "recruitment"
for "requirement"). Company speaker: **Munjuluri Bala Nagendra Raja** (Infineon, ES SYS SAR); a second Infineon colleague
(Shubham) agreed but was not on a microphone. This file records what was said, not our interpretation, unless marked
**Meaning for us**.*

## 1. Overall verdict

* Team 2 (us): good; the databases we picked are "the same data the company would have suggested".
* Team 3: "you are on the right path"; human editing at every stage is "very much appreciated".
* All three: "great approach in how you divided the problem… the students are on the right track. Please continue."
* A follow-up call is possible: "write to us, and if required we can have one more call".

## 2. What the company told Team 1 (it affects our input)

| Said | Meaning for us |
|---|---|
| **Security properties should be yes/no, not High/Medium/Low.** For each asset: is confidentiality required? integrity? availability? (a distance reading needs integrity, a key needs confidentiality). He "cannot directly correlate High to an asset" | Our input already uses booleans (`confidentiality`, `integrity`, `availability`, `authenticity`). Good fit. Team 1 will change their ratings to yes/no |
| **An application has many use cases** (smart lock: issue credential, access the lock, delete a lost credential…). Show a **list of use cases**, then **one table per use case**. Do not put everything into one use case | Our runs are keyed by `use_case_id`. We must handle **several use cases per product**, one threat run per use case, and keep results separate |
| **Each use case gets its own data-flow diagram** (unless two are very close and are combined) | Our `system_model` input is per use case |
| **Use a standard LLM; Infineon will not provide an in-house one.** Their internal LLMs are only reachable inside Infineon's network. They are also using standard LLMs, no fine-tuning yet | Settles our question on cloud AI: **standard cloud LLMs are acceptable** |
| **Keep the LLM swappable** through one setting or gateway so models can be compared | We already switch by `OPENAI_BASE_URL`/`OPENAI_MODEL` |
| Using a **cloud-hosted LLM** is faster and fine "if you have such a chance on campus"; do not restrict to a small local model | Supports using OpenRouter/Groq-type access |
| **ISO/SAE 21434 is for road vehicles; the SRS only gave examples.** Other public threat databases are fine; use what fits the use case | The ISO text is **not required**; our free catalogues are acceptable |
| For the **smart door lock they will send the threat sources they use (the open-source ones)** | **Action:** receive and compare with our knowledge base |
| **Free choice of example**, but their support is limited for unfamiliar ones; consumer electronics and automotive they can help with | |
| Team 1 should **take the databases from Team 2** | Our knowledge-base zip is exactly this |

## 3. What the company told Team 2 (us)

| Said | Meaning for us |
|---|---|
| Treats security properties as yes/no: noticed some assets have the property and some do not | Confirms the design |
| **"You also use the CWE database. The previous team can use that too."** | Confirms sharing the KB with Team 1 |
| **Harmonise the example across all teams**: "whichever example you use I'm fine, but keep the same example across all the teams." | **Action:** Team 1, 2 and 3 all use the **smart door lock** (Team 1 demoed a drone, so they must switch) |
| **Plan for going back one step iteratively.** We should be able to look at the previous step's result (for example the DFD), edit it, and re-run downstream. Infineon's own prototype does this. "Please plan how you do that when integrating Team 1 and Team 2." | **Action:** support re-running threats when assets or the DFD change; our `asset_version` and `use_case_id` fields help detect stale threats; design the "go back and restart" path |
| **Ranking:** "I don't see that as conflicting." Take each asset and rank the threats **per asset**. Then decide which threats to mitigate (severe ones); those drive the **security requirements**. Threats we decide **not** to mitigate are captured as **residual risk** | **Action:** threats are grouped per asset; Phase 2 must record the **treatment decision** (mitigate / accept) and **residual risk**, which Team 3 consumes |
| **Flow as he sees it:** Team 1 output → our threat agent → the next agent derives security requirements from our output | Confirms the hand-off chain |
| **The threat-modelling technique is a configurable parameter in Infineon's tool.** For this project **STRIDE only is fine**, delivered end to end. "Plan it like this, good enough for this version." | **Decision:** STRIDE only. Keep the technique modular, do not build others |
| **Redaction** before sending data to a model was mentioned approvingly | Our masking step stays |

## 4. What the company told Team 3 (it affects the shared design)

* Their requirements step links requirements to **test cases**: "very good".
* Human editing of every generated field: appreciated; "extend it to the first two teams".
* **Open question from the company:** where do **security objectives** come from? The chain should be
  *use case → assets → threats → security objectives → security requirements*. Team 3 said they derive objectives with Gemini from threat, asset and KB context; the company wants this flow made clear.
* **Two diagrams for the next meeting:** (1) an **AI/agent architecture**: orchestrator, each agent, its purpose, its output and how it feeds the next; (2) a **security flow** diagram (use case → asset → threat → objective → requirement).
* "Next time start with an architecture diagram showing all agents."

## 5. Our own statements we should correct or avoid

* In the demo it was said that when a reviewer rejects a scenario, the reason is stored "so that for the further project or any other project, if it gets the same issue it would be solved directly by the LLM". **That is not implemented.** Today rejection reasons are stored in the audit log and used to regenerate that scenario in the same run. They are not learned across projects. Do not repeat this claim.
* "Postgres with pgvector" and "sentence transformers" statements were accurate.
* The company answered our open question on ranking: per asset (see section 3).

## 6. Action list for Team 2

| # | Action | Who | Priority |
|---|---|---|---|
| 1 | Agree with Team 1 and Team 3: **smart door lock** is the single shared example | Shriraj (said he would coordinate) | High |
| 2 | Share the **knowledge-base package** with Team 1 | us | High (done: `docs/TRC_KB_Package.zip`) |
| 3 | Receive Infineon's list of **open-source threat sources for the smart door lock** and compare with our library | us | High |
| 4 | Support **multiple use cases** per product (one threat run per use case, results kept separate) | us | High |
| 5 | Design the **"go back one step and re-run"** flow with Team 1 (stale-threat detection by `asset_version`) | us + Team 1 | High |
| 6 | Add **treatment decision and residual risk** to the Risk Agent design (mitigate → requirement; accept → residual risk) | us (Phase 2) | High |
| 7 | Keep **STRIDE only**, modular, finish end to end | us | Decided |
| 8 | Prepare the two diagrams (agent architecture; security flow including security objectives) together with Team 3 | all teams | Next meeting |
| 9 | Clarify with the company: who derives **security objectives** and from what | Team 3 / us | Open |
| 10 | Send a short email of thanks and our questions; offer a follow-up call | Dr. Gaikwad / us | Soon |

## 7. Our earlier questions: now answered or still open

| Our question | Status |
|---|---|
| Cloud AI allowed? | **Answered:** standard LLMs are fine for this non-sensitive project data |
| How to rank threats? | **Answered:** per asset; severity decides mitigation; accepted ones are residual risk |
| Is ISO 21434 needed? | **Answered in practice:** it is for road vehicles; other public databases are acceptable |
| Other catalogues to use? | **Partly answered:** they will send the smart-door-lock sources |
| Which technique? | **Answered:** STRIDE only |
| Multi-step attack chains? | **Not discussed** |
| CAPEC-189 vs CAPEC-622, internal patterns, expert judgements, risk tables | **Still open**; ask by email |
| Who approved (audit identity), tamper-proof audit | **Not discussed** |
