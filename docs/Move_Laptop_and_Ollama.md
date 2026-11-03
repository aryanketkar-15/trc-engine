# Moving to the RTX 4060 laptop and switching to Ollama

Everything except the model runs without changes. Only steps 5 and 6 are LLM work.

## 1. Copy what Git does not carry

Take these from the current laptop on a USB drive or similar. None of them are in the repository:

| Item | Why |
|---|---|
| `docs/TRC_KB_Package.zip` | The full knowledge base (2,300 patterns, 5,097 standards pieces) |
| `.env` | Settings. It holds API keys, so do not put it in chat or commit it |
| `company_document.pdf` | The company specification |

## 2. Get the code

```bash
git clone https://github.com/aryanketkar-15/trc-engine.git
```

```bash
git -C trc-engine checkout develop
```

Install Python 3.11 or newer and Docker Desktop. Then install the project from inside the `trc-engine` folder.

```bash
pip install -e .
```

## 3. Start the database

```bash
docker compose up -d
```

## 4. Load the knowledge base

Unzip `TRC_KB_Package.zip`, open Git Bash in the unzipped folder, and load the dump into a database named `trc_engine_fullkb`:

```bash
docker exec trc-postgres psql -U trc_user -d postgres -c "CREATE DATABASE trc_engine_fullkb"
```

```bash
docker exec trc-postgres psql -U trc_user -d trc_engine_fullkb -c "CREATE EXTENSION IF NOT EXISTS vector"
```

```bash
gunzip -c db/trc_kb_tables.sql.gz | docker exec -i trc-postgres psql -U trc_user -d trc_engine_fullkb -q
```

Copy `.env` into the project folder. Check the result:

```bash
python scripts/scrp_demo.py --auto --quiet --project 3 --use-case UC-01
```

With the current `.env` this may use the hosted model; `USE_LIVE_LLM=false` runs it with no model at all.

## 5. Install Ollama and a model

Install Ollama from https://ollama.com (an up-to-date NVIDIA driver is the only GPU requirement), then:

```bash
ollama pull llama3.1:8b
```

Ollama reads a limited amount of each prompt by default and silently drops the rest, and Threat Agent prompts are long. Set
this Windows environment variable and restart Ollama:

```
OLLAMA_CONTEXT_LENGTH=8192
```

## 6. Point the project at it

Change these lines in `.env`:

```
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_API_KEY=ollama
OPENAI_MODEL=llama3.1:8b
LLM_TIMEOUT_SECONDS=180
USE_LIVE_LLM=true
```

Then check it:

```bash
python scripts/check_llm.py
```

## 7. Run the whole chain and time it

```bash
python scripts/scrp_demo.py --auto --quiet --project 3 --use-case UC-01 --mode live
```

```bash
python scripts/risk_demo.py --auto --approver "Your name" --use-case UC-01 --input projects/smart_door_lock_multi_use_case.json
```

```bash
python scripts/compliance_demo.py --auto --approver "Your name" --input projects/smart_door_lock_multi_use_case.json
```

```bash
python scripts/tara_report.py --use-case UC-01
```

Things to check, because the local model has not been tried yet:

1. `check_llm.py` reports clean JSON.
2. In the Threat Agent run, how many scenarios came from the model and how many fell back.
3. In `risk_demo.py`, each line says `LLM suggestion` and not `rule-based default`.
4. In `compliance_demo.py`, an `AI rationale` appears. If none appears, the model's answer failed the checks and the record
   keeps its rule-based justification, which is safe.
5. Compare the threats with the earlier hosted-model results in `docs/research/`.

If a model is slow or weak, change only `OPENAI_MODEL` (and pull it). No code changes are needed.
