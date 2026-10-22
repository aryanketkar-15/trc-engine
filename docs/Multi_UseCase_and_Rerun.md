# Several use cases per product, and "go back one step and re-run"

Both came out of the Infineon review on 12 Oct 2026. They are implemented and tested (350 automatic tests pass).

## 1. Several use cases per product

**The company's words:** an application has many use cases (smart lock: issue a credential, access the lock, delete a
lost credential). Show a list of use cases; each use case gets its own table and its own data-flow diagram.

### How we handle it
* **Product file format** (`projects/smart_door_lock_multi_use_case.json`, copy in `docs/shared_example/`):

  ```jsonc
  { "project_id": "CSDL-100", "product_name": "...",
    "assets": [ ...the assets, listed once... ],
    "use_cases": [
      { "use_case_id": "UC-01", "title": "...", "description": "...",
        "system_model": "<this use case's data-flow description>",
        "asset_ids": ["AS-1", "AS-2", "AS-4", "AS-6"] } ] }
  ```
* **One run per use case.** `expand_project()` turns the file into one normal `ThreatAgentInput` per use case (its own
  `use_case_id`, its own system model, only its assets). Nothing else in the pipeline had to change.
* **Separate results.** Every scenario now carries `project_id` and `use_case_id`. Approved results, the review history and the
  "already approved" list are kept **per `project_id` + `use_case_id`**, so UC-01 and UC-02 never mix.
* **Single-use-case files still work** exactly as before.

### Using it
| Where | How |
|---|---|
| CLI | `python scripts/scrp_demo.py`, choose "Smart Door Lock Multi Use Case"; a table lists the use cases with how many scenarios are already approved; pick a number, an id (`UC-02`) or `all`. Or `--project 3 --use-case UC-02` |
| API | `POST /api/v1/threat-agent/expand-project` (body: the product file) returns one input per use case; send each to `POST /analyze` separately |
| Files | A report per use case: `demo_output/run_report_UC-02.json` |

## 2. Going back one step and re-running

**The company's words:** be able to look at the previous step's result (for example the DFD), edit it, and restart so
the downstream steps run again.

### What "out of date" means
Every scenario is stamped when it is produced with two short hashes:

| Stamp | Hash of | Changes when… |
|---|---|---|
| `asset_fingerprint` | the asset facts (name, type, location, the four yes/no properties, damage scenario, interfaces, trust zone, data flows, device settings, version) | someone edits the asset |
| `context_fingerprint` | the use-case text and the system model | someone edits the use case or the DFD |

Comparing the stamps with the **current** input is deterministic (no AI):

| Finding | Reason shown |
|---|---|
| asset no longer in the input | asset removed from the input |
| asset fingerprint differs | asset facts changed |
| context fingerprint differs | use case or system model changed (every threat of the use case) |
| old scenario without stamps, asset version differs | asset version changed |

Assets that have **no approved threat** at all are listed as *uncovered* (for example a new asset).

### The re-run flow
1. You (or Team 1) change the upstream data: edit the asset or the system model.
2. Run the CLI again for that use case. It shows **"Upstream data changed since you approved"** with each affected scenario and the reason.
3. Answer **y**: the out-of-date scenarios are **retired**, not deleted: they move to the revision history (action `stale`) with the reason, and
   an audit entry `stale` is written.
4. The agent **re-runs only the affected assets** (changed + uncovered) and shows new proposals; everything still valid stays approved.
5. You review and approve the new scenarios; the shared state ends up with the unchanged old ones plus the new ones.

If you answer **n**, nothing is touched.

### API
| Endpoint | Does |
|---|---|
| `POST /api/v1/threat-agent/staleness` | read-only: body = the CURRENT input; returns `stale`, `fresh`, `changed_assets`, `removed_assets`, `uncovered_assets`, `affected_assets` |
| `POST /api/v1/threat-agent/retire-stale` | retires the stale scenarios; then call `POST /analyze` with only the `affected_assets` |

(Both need the `X-API-Key` header.)

### What we tested
Rehearsal on the door lock use case UC-02: approved 4 scenarios, edited asset AS-4 in the input file, re-ran. The tool listed 1 out-of-date
scenario on AS-4, retired it, re-ran only AS-4, and the shared state ended with 3 unchanged + 4 new approved scenarios (7).
Automatic tests cover fingerprints, every staleness rule, retirement, and the three endpoints.

## 3. Limits (honest)
* Staleness is detected from the **input you give us**. We do not watch Team 1's database yet; after integration the same comparison can run
  against their latest approved asset table.
* A changed system model marks **every** threat of that use case out of date (we cannot tell which parts of the text matter).
* "Going back" is at the level of our own step (threats). Re-running Team 1's earlier steps is Team 1's flow.
* Retired scenarios are kept in the history but are not automatically re-proposed unchanged; the agent proposes fresh scenarios for the affected assets.
* Scenarios approved before this change have no stamps and are compared by asset version only.
* In recorded mode (no internet) the re-run replays earlier model output; with the live model the new proposals reflect the edited asset.
