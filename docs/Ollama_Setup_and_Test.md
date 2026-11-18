# Connecting Ollama and testing all three agents

For the person doing the Ollama step (RTX 4060 laptop) and for their Claude. It is complete on its own. For the machine move itself (copying files, Docker) it builds on `docs/Move_Laptop_and_Ollama.md`.

## 1. What this project is, in five lines

- TRC engine = Team 2's three agents for TARA: **Threat Agent**, **Risk Agent**, **Compliance Agent**. Repo `aryanketkar-15/trc-engine`, branch `develop`.
- Every agent works without a language model. The model only drafts text or suggests values. **Humans approve everything.**
- Models are reached through one OpenAI-compatible client, `common/llm_client.py`. Ollama speaks that protocol, so no code change is needed to switch.
- A weak or unreachable model must never crash an agent. Each one falls back to its rule-based result and says so.
- Your job: make a local model work in all three agents and measure how well.

## 2. What each agent asks the model

| Agent | What the model does | If the model fails or answers badly |
|---|---|---|
| Threat (`agents/threat_agent/generator.py`) | Writes the attack scenario for each attack path found in the knowledge base. | That path falls back to a deterministic scenario; the log says `llm_fallback_engaged`. |
| Risk (`agents/risk_agent/suggester.py`) | Suggests impact and feasibility ratings for one threat. The risk number is computed by rules, never by the model. | The suggestion says `rule-based default`. |
| Compliance (`agents/compliance_agent/explainer.py`) | Writes a 2-3 sentence rationale citing standards excerpts. It cannot change any level. | No AI rationale is attached; the record keeps its rule-based text. |

All three read the answer through `common/llm_json.py`, which strips a Markdown fence, a `<think>` block and surrounding prose. Local models do all of these.

## 3. Settings (`.env`)

```
USE_LIVE_LLM=true
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_API_KEY=ollama
OPENAI_MODEL=llama3.1:8b
LLM_TIMEOUT_SECONDS=180
```

- `OPENAI_API_KEY` must be present. Any dummy value works for Ollama; the word `ollama` is fine. Do not put a real key here.
- The base URL must end in `/v1`.
- Set the Windows environment variable `OLLAMA_CONTEXT_LENGTH=8192` and restart Ollama. Without it, Ollama silently cuts long prompts and the Threat Agent answers get worse.
- Model choice for 8 GB VRAM: start with `llama3.1:8b`. Team 1 uses `qwen3.5:9b` with thinking off; try it second. A model that spills out of VRAM is very slow. Change only `OPENAI_MODEL` to switch; never edit code for this.
- Never commit `.env`. Never paste API keys into chat, code, docs or commit messages.

## 4. Step by step

1. Get the code and the knowledge base: sections 1-4 of `docs/Move_Laptop_and_Ollama.md` (clone, `pip install -e .`, `docker compose up -d`, restore `TRC_KB_Package.zip` into database `trc_engine_fullkb`). The knowledge base zip is not in Git; ask Chetan for it.
2. Install Ollama, run `ollama pull llama3.1:8b`, set `OLLAMA_CONTEXT_LENGTH`, restart Ollama.
3. Edit `.env` as in section 3.
4. Check the connection:

```bash
python scripts/check_llm.py
```

   Expect clean JSON and a time. If this fails, fix it before going on (section 6).

5. Check all three agents with the model, in one go (about 2 assets, a few minutes):

```bash
python scripts/live_agents_check.py
```

   It prints, per agent, how many model calls were made and how many answers were **used**, plus the latency, and writes `demo_output/live_check/report.json`.
   - Exit code 0 = all three agents used the model. 1 = at least one agent only fell back (the model is reachable but its answers are not usable). 2 = the setup is wrong (it prints why).
   - Bigger run: `python scripts/live_agents_check.py --assets 4 --paths 8`.

6. Run the full chain with the real model:

```bash
python scripts/scrp_demo.py --auto --quiet --project 3 --use-case UC-01 --mode live
```

   `--mode live` is required. Without it the demo may replay recorded output for some projects and never call the model.

```bash
python scripts/risk_demo.py --auto --approver "Your name" --use-case UC-01 --input projects/smart_door_lock_multi_use_case.json
```

```bash
python scripts/compliance_demo.py --auto --approver "Your name" --input projects/smart_door_lock_multi_use_case.json
```

```bash
python scripts/tara_report.py --use-case UC-01
```

7. Run the tests (Docker must be up):

```bash
python -m pytest tests -q -p no:cacheprovider
```

   `tests/risk_agent/unit/test_local_model_answers.py` uses a fake Ollama and needs no GPU. One database test, `test_build_index_is_idempotent`, is occasionally flaky and passes when run alone.

## 5. What good looks like

- `live_agents_check.py`: exit 0; Risk lines say `LLM suggestion`; Compliance shows an AI rationale; Threat has fewer "fell back" paths than paths. A few fallbacks with a small model are normal, all of them is not.
- Whole chain: the Threat Agent run is the slow part (roughly one model call per attack path). Expect minutes, not seconds.
- `scripts/verify_audit.py` reports the audit trail intact after the chain.
- Record: model name, seconds per call (from `report.json`), paths used vs fell back, and whether the scenarios read sensibly. Compare with the hosted-model results in `docs/research/`.

## 6. Troubleshooting

| What you see | Cause | Fix |
|---|---|---|
| `PROBLEM: USE_LIVE_LLM is off` | `.env` has false, or an environment variable overrides it | Set `USE_LIVE_LLM=true`; check `$env:USE_LIVE_LLM` in PowerShell |
| `Connection error` / refused | Ollama is not running, or the URL is wrong | Start Ollama; open `http://localhost:11434` (it says "Ollama is running"); URL must be `http://localhost:11434/v1` |
| HTTP 404 model not found | `OPENAI_MODEL` is not pulled | `ollama list`, then `ollama pull <name>` and match the name exactly |
| Validation error for `OPENAI_API_KEY` | The variable is missing or empty | Set it to any text, e.g. `ollama` |
| Timeout | First call loads the model into memory; model too big for 8 GB | Raise `LLM_TIMEOUT_SECONDS` to 300; use a smaller model; close other GPU programs |
| HTTP 402 / credit errors | `.env` still points at OpenRouter or OpenAI | Check `OPENAI_BASE_URL`; the check script prints the endpoint it is using |
| Everything "fell back", answers not JSON | Model too small or ignores instructions; thinking model | Try `qwen3.5:9b` or another instruction model; `report.json` shows the start of an unusable answer |
| Truncated JSON | Answer cut by `max_tokens` | Not a settings problem; report it, do not raise limits blindly |
| Threat Agent returns only 1-2 scenarios | Project has few assets, or the project id is the recorded demo one | Use `--mode live` and `projects/smart_door_lock_multi_use_case.json` |
| Compliance "NOT TESTED" | Knowledge base missing in the database | Restore `trc_engine_fullkb` (section 4 of the move guide) |
| Very slow | Model running on CPU | `ollama ps` should say 100% GPU; update the NVIDIA driver |

## 7. Rules for changing things

Do not change these, they exist on purpose:

- The model never sets a risk level, resistance level or approval. Do not let it.
- Do not weaken the checks that drop answers (cited excerpt must exist, levels must match, PII redaction, schema validation).
- Do not add retries or longer prompts to hide a weak model; report the model as weak instead.
- Do not write secrets anywhere or commit `.env`, logs, `demo_output/` or `SCRS_state.json`.

If a real parsing problem turns up, fix it in `common/llm_json.py` and add a test case in `tests/risk_agent/unit/test_local_model_answers.py`.

## 8. Git rules

- Work on `develop` (or a branch off it). Normal pushes only; never force push.
- Commits are authored by the four team members only. Do not add `Co-Authored-By` or "Generated with" lines; the team lead says who owns which commit.
- Run `ruff check .` and the tests before pushing.

## 9. Paste this to your Claude

```
You are helping me connect a local Ollama model to the TRC engine (repo aryanketkar-15/trc-engine, branch develop, folder trc-engine) and test its three agents: Threat, Risk and Compliance. Read docs/Ollama_Setup_and_Test.md fully first; it is the complete guide, and docs/Move_Laptop_and_Ollama.md covers the machine setup. This laptop has an RTX 4060 (8 GB VRAM) and Windows.

Do, in order, and stop to tell me if a step fails:
1. Confirm Python 3.11+, Docker, and that the knowledge base database trc_engine_fullkb is restored (ask me for TRC_KB_Package.zip if it is not).
2. Install Ollama, pull llama3.1:8b, set OLLAMA_CONTEXT_LENGTH=8192, restart Ollama.
3. Set .env exactly as in section 3 of the guide (OPENAI_API_KEY=ollama; never write a real key; never commit .env).
4. Run python scripts/check_llm.py, then python scripts/live_agents_check.py. Read the output and demo_output/live_check/report.json.
5. If an agent only fell back, diagnose with the troubleshooting table before changing anything. Try qwen3.5:9b by changing only OPENAI_MODEL.
6. Run the full chain from section 4 step 6 (use --mode live) and the test suite.
7. Report: model, seconds per call, per agent how often the model's answer was used vs fell back, any unusable answer samples, and test results.

Rules: do not let the model decide risk levels, resistance levels or approvals; do not weaken validation or redaction; do not paste secrets anywhere; no force push; commits only under the team members' names with no Claude or Co-Authored-By lines; ask me before committing.
```
