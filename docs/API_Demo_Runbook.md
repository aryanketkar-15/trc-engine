# API demo: complete execution runbook (step by step)

Do this **once as a rehearsal** (section 5 shows how to reset), then again for the real demo.
Total time: about 15 minutes for the rehearsal, about 8 for the demo (the AI parts take 1–3 minutes each).

All commands are for **Windows PowerShell** in the project folder `C:\Users\Chetan\trc-engine`.

## 0. What you need open (three windows)

| Window | Used for |
|---|---|
| **A: Server terminal** | runs the API |
| **B: Database terminal** | shows the stored data |
| **C: Browser** | the interactive docs page |

## 1. Preparation (before the meeting)

### 1.1 Start the database
```powershell
docker compose up -d
```
Wait 20 seconds. Check: `docker ps` shows `trc-postgres` as running.

### 1.2 Keep the real shared-state file safe
Approving writes to a file. For rehearsals use a **separate file**, so your real `SCRS_state.json` stays untouched (the folder is created automatically).

### 1.3 Start the server (Window A)
```powershell
$env:SCRS_STATE_PATH = "demo_output/SCRS_api_demo.json"
python -m uvicorn main:app --port 8000
```
Wait for: `Application startup complete.` Leave this window open and visible; errors appear here.

### 1.4 Open the database (Window B)
```powershell
docker exec -it trc-postgres psql -U trc_user -d trc_engine_fullkb
```
Clean old test rows:
```sql
DELETE FROM threat_agent_runs;
```
(You should see `DELETE n`. If it says the table does not exist, start the server first and make one call.)

### 1.5 Open the docs page (Window C)
Go to **http://localhost:8000/docs**.
Click **Authorize** (green button, top right). In the box, paste the value of `THREAT_AGENT_API_KEY` from `.env`
(for the default setup it is `trc-dev-secret-key`). Click **Authorize**, then **Close**.

### 1.6 Files you will paste from (all in `docs/api_demo/`)
| File | Used in |
|---|---|
| `analyze_infusion_pump.json` | Step 2 (run id is `RUN-DEMO-01`; change the number for each new run) |
| `reject.json` | Step 4 |
| `prune.json` | Step 5 |
| `add_scenario.json` | Step 6 |

---

## 2. Step 2: Send the system for analysis (`POST /analyze`)

1. On the page click **POST /api/v1/threat-agent/analyze** → **Try it out**.
2. Click inside **Request body**, press `Ctrl+A`, then paste the whole content of `analyze_infusion_pump.json`.
3. Click **Execute**.
4. **Wait 1–3 minutes.** Do not click again. Watch Window A: you will see log lines scrolling.
5. Expected: **Code 202**, body with `"run_id": "RUN-DEMO-01"`.

**Check in Window B:**
```sql
SELECT run_id, status, validation_status, jsonb_array_length(scenarios) AS scenarios
FROM threat_agent_runs ORDER BY created_at DESC;
```
Expected: one row, `RUN-DEMO-01 | pending_human | passed | 20` (the exact number may differ slightly).

**What to say:** "The AI finished. The draft is saved and is waiting for a human."

## 3. Step 3: Look at the scenarios (`GET /scenarios`)

1. Click **GET /api/v1/threat-agent/{run_id}/scenarios** → **Try it out**.
2. In `run_id` type `RUN-DEMO-01` → **Execute**.
3. In the response, find one scenario and note its `tid` (for example `THR-PATH-1A2B3C4D-007`).
   Each scenario shows asset, STRIDE type, `kb_reference` and the evidence.

Optional readable table in Window B:
```sql
SELECT s->>'tid' AS tid, s->>'asset_id' AS asset, s->>'stride_category' AS type, s->>'kb_reference' AS based_on
FROM threat_agent_runs r, jsonb_array_elements(r.scenarios) s WHERE r.run_id = 'RUN-DEMO-01' ORDER BY asset LIMIT 10;
```

## 4. Step 4: The human rejects (`POST /reject`) ⚠ do this ONCE and do it FIRST

> **Important:** a rejection **regenerates the whole list** (about 1–3 minutes) and **replaces** the scenarios,
> including their ids. So reject **before** you prune or add, otherwise those edits are lost. A **third**
> rejection ends the run as `rejected`, so reject only once in the demo.

1. Click **POST /api/v1/threat-agent/{run_id}/reject** → **Try it out**.
2. `run_id` = `RUN-DEMO-01`. Request body: paste `reject.json`:
   ```json
   {"reason": "Too generic. Name the specific interface and explain why the existing controls do not stop the attack."}
   ```
3. **Execute**, wait 1–3 minutes.
4. Expected: **Code 200**, `status: pending_human`, `human_rejection_count: 1`, and a **new list** of scenarios.

**Check in Window B:**
```sql
SELECT run_id, status, human_rejection_count FROM threat_agent_runs;
SELECT jsonb_pretty(rejection_history) FROM threat_agent_runs WHERE run_id = 'RUN-DEMO-01';
```
**What to say:** "The reason, the time and the rejected scenarios are kept. We never delete history."

Because the ids changed, repeat **Step 3** to get a fresh `tid`.

## 5. Step 5: The human removes one scenario (`POST /prune`)

1. Click **POST …/{run_id}/scenarios/{tid}/prune** → **Try it out**.
2. `run_id` = `RUN-DEMO-01`, `tid` = a `tid` from the **new** list. Body: paste `prune.json`.
3. **Execute**. Expected: **Code 200**, `remaining_scenarios` one less than before.

**Check:** `SELECT jsonb_array_length(scenarios), jsonb_pretty(edit_history) FROM threat_agent_runs WHERE run_id='RUN-DEMO-01';`

## 6. Step 6: The expert adds a scenario (`POST /scenarios`)

1. Click **POST …/{run_id}/scenarios** → **Try it out**.
2. `run_id` = `RUN-DEMO-01`. Body: paste `add_scenario.json` (a tampering threat on the dosage firmware,
   based on CAPEC-186 "Malicious Software Update").
3. **Execute**. Expected: **Code 201**, a new `tid` starting with `THR-EXP-`, `status: pending_human`.

**Show the safety net (optional, 30 seconds):** change `"kb_reference"` to `CAPEC-999999` and Execute.
Expected: **Code 422**, "does not exist in the knowledge base". Change it back afterwards.

## 7. Step 7: Approve (`POST /approve`)

1. Click **POST …/{run_id}/approve** → **Try it out** → `run_id` = `RUN-DEMO-01` → **Execute**.
2. Expected: **Code 200**, `status: approved`, and the number of scenarios written.

**Check in Window B:**
```sql
SELECT run_id, status, jsonb_array_length(scenarios) FROM threat_agent_runs;
```
**Check the shared-state file** (a third PowerShell window):
```powershell
python -m json.tool demo_output\SCRS_api_demo.json | more
```
You will see `threat_scenarios` (approved only), `audit_log` (`write`, `approve`, `reject`, `prune`, `add`) and `revision_history`.

**What to say:** "Only now are the results official. Drafts stay in the database; the final result and the
audit log are in the shared state."

## 8. Quick one-minute extras (if there is time)

* `GET …/{run_id}/status` → shows the current state and counters.
* Try approving again → **409**: "already approved". This shows the state rules.
* Send the same `run_id` again to `/analyze` → refused or duplicated; use a new id each time.

---

## 9. Reset between rehearsal and the real demo

```sql
DELETE FROM threat_agent_runs;
```
```powershell
Remove-Item demo_output\SCRS_api_demo.json -ErrorAction SilentlyContinue
```
Then stop the server (`Ctrl+C` in Window A) and start it again (step 1.3). Use `RUN-DEMO-02` etc. if you keep old rows.

## 10. Timing plan for the real demo (about 8 minutes)

| Time | What | Notes |
|---|---|---|
| 0:00 | Explain the idea and the picture | no typing |
| 0:45 | Step 2: Execute analyze | **start it, then talk about what happens inside while it runs (1–3 min)** |
| 3:30 | Step 3: database row + scenarios | |
| 4:30 | Step 4: reject | to save time you can pre-run the reject before the audience arrives, or skip it and show the `rejection_history` of a rehearsal run |
| 5:30 | Step 5 and 6: prune and add | fast |
| 6:30 | Step 7: approve, then show the file | |
| 7:30 | Close and questions | |

**Safe trick:** do Steps 2 and 4 before the meeting on a run named `RUN-DEMO-READY`, and in the meeting show Steps
3, 5, 6, 7 on it plus one live `analyze` of a *second* run while you explain.

## 11. If something goes wrong

| What you see | Meaning | Fix |
|---|---|---|
| 401 Unauthorized | Wrong or missing API key | Use `THREAT_AGENT_API_KEY` from `.env` (not the OpenRouter key) |
| 422 on analyze | Pasted JSON damaged, or `use_case` shorter than 10 characters | Paste the file again |
| 409 on reject/prune/add/approve | Run not in `pending_human` (already approved or rejected) | Use a new run |
| 500 on analyze | Look at Window A for the error | Often the AI key has no credit or the database is down |
| Page stays loading > 5 min | The AI call is slow or stuck | Wait; if it fails the error appears in Window A. Use a one-asset input |
| Empty table in the database | Wrong database | Connect to `trc_engine_fullkb` |
| `threat_agent_runs` does not exist | Server has not made a call yet | Start the server and send any request |
| Nothing in the SCRS file | You have not approved yet, or you are reading the wrong file | Approve first; the file is the one set in `SCRS_STATE_PATH` |
