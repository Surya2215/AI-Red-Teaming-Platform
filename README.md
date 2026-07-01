# AI Red Teaming and LLM Security Assessment Platform

Enterprise-grade LLM vulnerability assessment platform focused on the OWASP LLM Top 10. The implementation ships with OWASP LLM01 prompt-injection checks, single-turn attacks, multi-turn Crescendo attack orchestration, multi-provider LLM judge/detector support, React frontend, FastAPI API, PostgreSQL-backed SQLAlchemy persistence, and JSON target templates.

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn core.api:app --reload
```

Set PostgreSQL in `.env` when running locally outside Docker:

```env
DATABASE_URL=postgresql+asyncpg://redteam:redteam@localhost:5432/redteam
```

Run the React frontend:

```bash
cd frontend
npm install
npm run dev
```

Run tests:

```bash
pytest
```

Run the mock-chatbot regression suite after feature changes:

```bash
python run_regression_tests.py
```

The runner discovers every scenario plugin, executes it against `mock://` targets,
runs matching detectors, and writes `reports/regression/regression-summary.json`.

Run external tool scans through workers:

```bash
docker compose up --build
```

The compose stack includes RabbitMQ, Valkey, the API, frontend, and a Celery
tool worker. See `docs/tool-worker-deployment.md` for EC2 deployment guidance.
For step-by-step EC2 commands and queue smoke tests, see
`docs/ec2-tool-worker-runbook.md`.

## LLM Providers

Select the model provider from the Configurations page, or set it in `.env`:

```env
LLM_PROVIDER=azure_openai
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_DEPLOYMENT=
AZURE_OPENAI_API_VERSION=2024-12-01-preview
```

Supported providers are Azure OpenAI, OpenAI, AWS Bedrock, Ollama localhost, Hugging Face, and Anthropic. If the configured provider is not ready, the platform uses a deterministic local fallback so the demo, tests, and mock target remain runnable.

## Repository Layout

```text
checks/       Dynamic detector plugins
scenarios/    Dynamic attack scenario plugins
targets/      JSON target templates
engine/       Orchestration, loaders, judge, target execution
frontend/     React frontend
ui/           Legacy Streamlit frontend
core/         Settings, schemas, API, LLM client, logging
database/     SQLAlchemy models and repository
reports/      Generated JSON/PDF reports
logs/         Structured JSON logs
configs/      Scan defaults
tests/        Unit tests
docs/         Architecture, mockups, examples
```

## Architecture

```mermaid
flowchart LR
    UI["React UI"] --> API["FastAPI API"]
    UI --> ORCH["Scan Orchestrator"]
    API --> ORCH
    ORCH --> AE["Attack Engine"]
    ORCH --> DE["Detector Engine"]
    AE --> SL["Scenario Loader"]
    DE --> DL["Detector Loader"]
    AE --> TE["Target Executor"]
    AE --> JA["Judge Agent"]
    JA --> LLM["Configured LLM Provider"]
    DE --> LLM
    TE --> TARGET["Target App"]
    ORCH --> DB["PostgreSQL / asyncpg SQLAlchemy"]
    ORCH --> REPORTS["Reports"]
    ORCH --> LOGS["JSON Logs"]
```

## Target Streaming And Non-Streaming Configuration

The target workflow supports both regular HTTP responses and Server-Sent Events (SSE) streaming.

- Non-streaming: omit `streaming` (or set `streaming.enabled` to `false`).
- Streaming: set `streaming.enabled` to `true` in a workflow step (commonly `next_turn`).

### Non-streaming example

```json
{
    "type": "none",
    "workflow": {
        "next_turn": {
            "enabled": true,
            "method": "POST",
            "url": "https://example.app/chat",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "message": "{{prompt}}",
                "session_id": "{{session_id}}"
            },
            "response_message_path": "response.text"
        }
    }
}
```

### Streaming example (SSE)

```json
{
    "type": "none",
    "workflow": {
        "next_turn": {
            "enabled": true,
            "method": "POST",
            "url": "https://example.app/chat/stream",
            "headers": {"Accept": "text/event-stream"},
            "body": {
                "message": "{{prompt}}",
                "session_id": "{{session_id}}"
            },
            "streaming": {
                "enabled": true,
                "response_message_path": "delta.content",
                "response_session_id_path": "meta.task_id",
                "stop_conditions": [
                    {"value": "[DONE]"},
                    {"path": "result.final", "value": "true"}
                ],
                "select_conditions": [
                    {"path": "delta.role", "value": "agent"}
                ]
            }
        }
    }
}
```

### Condition matching rules

- `value: "true"` or `"false"`: strict boolean match.
- `value: "*"`: field presence (`not None`).
- Any other value: exact string match (`str(value) == signal`).

For stop conditions:

- If `path` is omitted, matching is done on raw SSE `data:` content before JSON parsing (for example `[DONE]`).
- If `path` is provided, matching is done on the parsed JSON chunk.

For select conditions:

- All select conditions must match before chunk content is appended.
- Session ID extraction via `response_session_id_path` runs on every parsed chunk before select filtering.

## Extending

Add a scenario file under `scenarios/<OWASP category>/` with `get_scenario()` returning an object that exposes `metadata` and async `run(...)`.

Add a detector file under `checks/<OWASP category>/` with `get_detector()` returning an object that exposes `metadata` and async `evaluate(scenario_result)`.

The loader supports filenames with spaces and hyphens, so plugin directories can match OWASP category names exactly.

## Security Notes

Secrets are loaded from `.env` and redacted from logs. Target authentication can reference environment variables. Prompt logging is intentionally report-oriented and should be reviewed before running against sensitive production targets.

## Docker

```bash
docker compose up --build
```

API: `http://localhost:8000`  
Frontend: `http://localhost:5173`

