# 03 · Traceability, audit trail and rules for reading our data

## 1. Keys you can link on

```
UC-n  ──►  AS-n (+ asset_version)  ──►  THR-…  ──►  (RISK-… planned)  ──►  SR-n (yours)
use case     asset (Team 1)            threat (us)     risk (us, later)       requirement
```

| Key | Where it lives | Use it to |
|---|---|---|
| `use_case_id` | on every threat | link the threat to Team 1's use case |
| `asset_id` + `asset_version` | on every threat | link to the exact asset row; if the asset's version later increases, the threat may be stale |
| `tid` | on every threat; unique | the key your requirements should point to |
| `kb_reference` | on every threat | link to the attack catalogue entry (CAPEC / ATT&CK / CWE / STRIDE rule) |
| `run_id` | on every threat and audit entry | group everything produced by one run |
| `kb_snapshot_version` | on every threat | know which knowledge base was used |

A requirement can cover several threats and a threat can lead to several requirements: use a link table
`(requirement_id, tid)`, not a single column.

## 2. The shared state (SCRS) file

`samples/output_scrs_state_sample.json` is a real file written by our code. It has three parts:

```jsonc
{
  "threat_scenarios": {            // APPROVED scenarios only, keyed by tid
     "THR-PATH-FF8876D6-001": { ...ThreatScenario... }
  },
  "audit_log": [                   // one entry per action, oldest first
     { "run_id": "...", "tid": "...", "timestamp": "...Z", "action": "write",
       "reason": null, "previous_tid": null }
  ],
  "revision_history": {            // everything that was NOT kept as is, by run_id
     "RUN-...": [ { "timestamp": "...", "action": "prune", "reason": "...", "scenarios": [ {...} ] } ]
  }
}
```

### Audit log actions

| `action` | Meaning | `reason` |
|---|---|---|
| `write` | An approved scenario was stored | – |
| `approve` | A human approved the scenario (written together with `write`) | – |
| `reject` | A human rejected scenario(s) of a run | the reviewer's reason (required) |
| `revise` | A scenario replaced an earlier one; `previous_tid` points to the old one | – |
| `prune` | A human discarded a scenario | the reason (required) |
| `add` | A human expert added their own scenario | why it was added |

### `revision_history`

Nothing is deleted. Rejected, pruned, added and replaced scenarios are kept in full with the reason and time.
Entries **without** an `action` field are human rejections (their `reason` is the reviewer's feedback).

## 3. Rules you must follow when reading our data

1. **Use only `status == "approved"`.** The `threat_scenarios` part of the SCRS contains only approved ones,
   but other sources (API before approval, files) may contain drafts.
2. **Never treat missing as zero.** If a risk, requirement or asset fact is missing, record "unknown".
3. **Carry the quality flag.** If `validation_status` is `escalated_after_retries`, show "approved with
   automatic-check warning" in your reports; if `expert_added`, show "expert-authored".
4. **Do not overwrite our records.** Reference them by `tid`. If you need a change, ask for a reject / revise on
   our side so the history stays intact.
5. **Re-check on version change.** A new `asset_version` or `kb_snapshot_version` means earlier threats may
   need review.
6. **Do not interpret `confidence_score` as likelihood.** It is evidence-match strength.

## 4. Audit integrity: what we do and do not claim

| Property | Status |
|---|---|
| Every write, approval, rejection, prune and add is logged with time, run and reason | yes |
| Rejected / pruned / replaced content is never deleted | yes |
| The log is tamper-evident (hash chain) | **no** (plain JSON file). Team 1's audit log is hash-chained with a database trigger; after integration our events should be written there |
| The log records **who** approved | **not yet** (no actor field). To be fixed during integration with Team 1's authenticated users |

If you build the Trace/Audit report from our data, please mention these two limits.

## 5. A worked trace row (from the samples)

| Use case | Asset | Asset version | Threat | STRIDE | KB reference | Status | Check result |
|---|---|---|---|---|---|---|---|
| UC-6E516A54 | AS-4 | 1.0 | THR-PATH-FF8876D6-001 | Tampering | CAPEC-665 | approved | passed |

`python tools/check_handoff.py` prints this matrix for the whole sample.

## 6. Suggested uses by agent (for discussion)

| Your agent | Likely use of our output |
|---|---|
| **Requirements** | one or more security requirements per approved threat; quote `attack_vector` and `evidence_chain`; link `tid` → `SR-n` |
| **Trace/Audit** | the matrix above; counts of approved / flagged / expert-added threats; the audit log as decision evidence |
| **Consistency** | assets with no approved threat (gap or justified), threats whose asset changed version (stale), approved threats with no requirement (untreated), scenarios flagged `escalated_after_retries` |
