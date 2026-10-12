# API + Database demo: simple explanation script for industry people

**Goal of this demo (one sentence):** show that other agents and programs can use our Threat Agent through a
normal web API, and that every run and every decision is **stored and traceable**.

**Time:** about 7 minutes. **Who speaks:** one person (or split: *Part A* by the first presenter, *Part B* by the second).

---

## 1. The idea first (say this in 30 seconds)

> "In the command-line demo we showed how the Threat Agent works for a person. But in your final system, other
> agents, like the Risk Agent or the Requirements Agent, will not type in a terminal. They will **call our agent
> like a web service**. This page is that service.
> The idea is the same: **the AI proposes, a human decides**. The difference is that now every step is a
> **web call**, and every result is **saved in a database**, so nothing is lost and everything can be traced."

---

## 2. Explain the page in plain words

Use this **picture** while speaking (draw it on a whiteboard or slide):

```
 Other agent / UI                     Our service                          Storage
 ────────────────    1 analyze  ──►   find threats with AI   ──►   PostgreSQL: the RUN (draft, waiting for human)
                     2 look     ──►   show the scenarios
 Human expert        3 reject / prune / add  ──►  fix them       ──►   PostgreSQL: the history of changes
                     4 approve  ──►   final                      ──►   Shared-state file: ONLY approved results + audit log
```

Say it like this:

> "Think of it as **a form with seven buttons**.
> 1. **Analyze**: 'here is my system and its assets, find the threats.'
> 2. **Look**: 'show me what you found.'
> 3. **Reject, remove, add**: the human corrects the draft.
> 4. **Approve**: 'this is final.'
> Only the last button makes the result official."

---

## 3. The live demo, step by step

> **Prepare before the meeting:** Docker running, server started (`python -m uvicorn main:app --port 8000`),
> browser open at `http://localhost:8000/docs`, a database window open
> (`docker exec -it trc-postgres psql -U trc_user -d trc_engine_fullkb`), and the infusion pump input file ready
> to paste (`docs/handoff_team3/samples/input_infusion_pump.json`) with a **new run_id** (e.g. `RUN-DEMO-01`).
> Delete test rows first: `DELETE FROM threat_agent_runs;`

### Step 1: The API key (20 seconds)

`[Point at the X-API-Key box]`

> "Changing anything needs a **secret key**. Without it the service answers 'unauthorized'. This protects the
> approval buttons, because approving is a security decision."

### Step 2: Send the system (about 1–2 minutes of waiting, so talk while it runs)

`[Paste the input into POST /analyze → Execute]`

> "I am sending a **medical infusion pump** with two assets: the dosage-control firmware, and the patient data
> interface. For each asset I describe what must be protected and how it connects to the outside.
> While it runs, here is what happens inside: the service searches our library of 2,300 known attacks, the AI
> writes a short report for each, and five fixed rules check the AI's work. **A wrong input would be refused
> straight away**, and I can show that later."

`[When the response appears]`

> "We got **code 202, accepted**, and the run ID. The page wording says 'poll for progress', but by now the work
> is already done."

### Step 3: Show that it was saved in the database (1 minute)

`[Switch to the database window and run:]`

```sql
SELECT run_id, status, validation_status, jsonb_array_length(scenarios) AS scenarios
FROM threat_agent_runs ORDER BY created_at DESC;
```

> "This is our database, PostgreSQL. A row was created for this run.
> **'Pending human'** means the AI has finished, and the run is **waiting for a person**. We have 20 draft
> scenarios. Nothing is official yet."

### Step 4: Look at the scenarios (1 minute)

`[On the page: GET /{run_id}/scenarios → Execute, or run the table query below]`

```sql
SELECT s->>'tid' AS id, s->>'asset_id' AS asset, s->>'stride_category' AS type, s->>'kb_reference' AS based_on
FROM threat_agent_runs r, jsonb_array_elements(r.scenarios) s WHERE r.run_id = 'RUN-DEMO-01' LIMIT 8;
```

> "Each scenario says: **which asset**, **what type of attack**, and **which entry of the public catalogue it is
> based on**. Every one carries its evidence, so the reviewer can judge it."

### Step 5: The human corrects the draft (2 minutes)

`[POST /{run_id}/scenarios/{tid}/prune: choose one id, give a reason, Execute]`

> "The expert removes one scenario and **must give a reason**."

`[POST /{run_id}/reject: reason "Too generic"]`

> "Or the expert rejects with feedback. The system regenerates using that feedback."

`[Back in the database window: rerun the first query, then:]`

```sql
SELECT jsonb_pretty(rejection_history), jsonb_pretty(edit_history) FROM threat_agent_runs WHERE run_id = 'RUN-DEMO-01';
```

> "Look: the reason, the time, and the removed scenario are **kept**. We never delete history."

### Step 6: Approve (1 minute)

`[POST /{run_id}/approve → Execute, then show the file: SCRS_state.json]`

> "Now the expert approves. Only now do the results go into the **shared state**, a separate file that the next
> agents read. It contains **only approved threats**, plus an **audit log**: who or what was written, when, and
> for which run."

`[In the database: status is now 'approved'.]`

---

## 4. Closing (30 seconds)

> "So: **seven calls, one database, one shared state.** Any agent can call us, a human always has the last word,
> every decision is stored with its reason, and approved results are separated from drafts.
> What is next: connect this to Team 1's asset tables and their database, so the whole chain from use case to
> threats runs in one system."

---

## 5. Honest limits (say them before they ask)

| Limit | What to say |
|---|---|
| The shared state is a plain file | "It records every action, but it is not tamper-proof yet. After integration it will go into the shared database with a hash-chained log." |
| No approver name recorded yet | "The log shows what was approved and when; recording **who** approved comes with the login system." |
| Waiting time | "The analysis takes one to a few minutes live because the AI writes each report." |
| Not yet linked to Team 1 | "Today we send the asset file ourselves; the link to their approved asset table is the next integration step." |

---

## 6. Likely questions and short answers

| Question | Answer |
|---|---|
| Why a database **and** a file? | The database holds the working run, including drafts and every correction. The file holds only the approved result for the other agents. |
| Can someone approve without permission? | The approval call needs the secret key now. Real user login and roles come with Team 1's system. |
| What if the AI service is down? | The analysis cannot run, but the stored runs, history and approved results stay readable. |
| Can the AI approve its own work? | No. The approval is a separate call that only a human or an authorised program makes; the AI has no way to call it. |
| What if the same system is sent twice? | Each run needs its own ID; the second run is a separate row. |
| What does 'pending human' mean? | The AI finished; the draft is waiting for review. |
| Can we see what was rejected later? | Yes, the history keeps the rejected content, the reason and the time. |

## 7. If something goes wrong

* **401 Unauthorized** → wrong key; use the `THREAT_AGENT_API_KEY` value from `.env`.
* **Page seems stuck** → the analysis is running; wait up to 3 minutes and do not click Execute again.
* **No row in the database** → you are in the wrong database; connect to `trc_engine_fullkb`.
* **422 error** → the pasted input is damaged; copy the sample file again.
* **Nothing in `SCRS_state.json` yet** → correct before approval; it fills only after `approve`.
