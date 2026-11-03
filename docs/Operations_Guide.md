# Operations guide

## Run with Docker

Create `.env` from `.env.example`, then:

```bash
docker compose --profile app up --build -d
```

Checks: `GET /health` (process is up) and `GET /ready` (database, knowledge base, tables, rule base, audit chain). The knowledge
base is restored separately; see `docs/Move_Laptop_and_Ollama.md`, step 4.

## Production settings

The API refuses to start with `ENVIRONMENT=production` unless all of these hold, and it lists whatever is wrong:

| Setting | Why |
|---|---|
| `TRC_USERS_FILE` | Decisions carry a verified person instead of a typed name |
| `THREAT_AGENT_API_KEY` not the default | The development key is public in this repository |
| `AUDIT_HMAC_KEY` | Someone who can edit the file cannot recompute the audit chain |
| `REQUIRE_AUTH_FOR_READS=true` | Threat data is sensitive |
| `DATABASE_URL` not using the development password | |

Keep the API behind HTTPS (a reverse proxy). It does not terminate TLS itself. Interactive API docs are off in production.

## Users and roles

```bash
python scripts/manage_users.py add "Dr. Vidya Gaikwad" approver --file secrets/users.json
```

| Role | May |
|---|---|
| viewer | Read |
| analyst | Also run the agents |
| approver | Also approve, reject, prune, add, retire, confirm |

The key is shown once and only its hash is stored. To replace a key, remove the user and add them again. With named users, a
decision always records the logged-in name, whatever the request body says.

## Audit

```bash
python scripts/verify_audit.py --scrs SCRS_state.json
```

Exit code 0 means intact. It checks the hash chain and that approved records still match what was approved. The same check is at
`GET /api/v1/scrs/audit/verify`; the decision log is at `GET /api/v1/scrs/audit/log`.

If you set `AUDIT_HMAC_KEY` on a state file that already has entries, those entries stop verifying. Set the key before first use.

## Backup and recovery

Back up the state file, `logs/llm_audit.jsonl`, `secrets/users.json` and the database. Each save also keeps the previous state as
`SCRS_state.json.bak`.

If the state file is damaged, the API answers 503 and changes nothing. To recover: stop the API, copy the file aside, restore the
backup, then run the audit check. A lock file (`.json.lock`) older than 60 seconds is cleared automatically.

## Changing tables and rules

Edit `agents/risk_agent/ratings.json` or `agents/compliance_agent/rules.json`, and raise the version inside the file. Records keep
the version they were made with. Existing approved records do not change by themselves; change them through the API with a
`supersede_reason`, which keeps the old version in the history.

## API errors

| Code | Meaning |
|---|---|
| 401 / 403 | Missing or wrong key / role not allowed |
| 409 | Would change approved content (the response has the diff), or someone else saved first: reload and repeat |
| 413 | Request larger than `MAX_REQUEST_BYTES` |
| 503 | Shared state cannot be read, or `/ready` found a failed check |

Every response carries an `X-Request-ID`; send your own to follow a request through logs.
