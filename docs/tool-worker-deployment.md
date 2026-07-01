# Tool Worker Deployment

This platform now supports two execution modes for external tools:

- Local blocking execution: `POST /tool-scans/run`
- Queue-backed worker execution: `POST /tool-scans/submit` and `GET /tool-scans/jobs/{job_id}`

Use the queue-backed path for Garak, PyRIT, DeepTeam, or other heavyweight scanners.

## Recommended AWS Layout

```mermaid
flowchart LR
    UI["React UI"] --> API["FastAPI API"]
    API --> MQ["RabbitMQ"]
    API --> VALKEY["Valkey Result Backend"]
    MQ --> WORKER1["EC2 Tool Worker: Garak"]
    MQ --> WORKER2["EC2 Tool Worker: PyRIT / DeepTeam"]
    WORKER1 --> TARGET["Target LLM App/API"]
    WORKER2 --> TARGET
    WORKER1 --> REPORTS["Shared Reports Volume or S3 Sync"]
    WORKER2 --> REPORTS
    API --> VALKEY
```

## Environment

Set these variables in the API and every tool worker:

```env
CELERY_BROKER_URL=amqp://redteam:redteam@rabbitmq:5672//
CELERY_RESULT_BACKEND=redis://valkey:6379/0
CELERY_TASK_DEFAULT_QUEUE=tool-scans
TOOL_WORKER_ENABLED=true
```

For EC2, use private security groups:

- API can reach RabbitMQ `5672`.
- API can reach Valkey `6379`.
- Workers can reach RabbitMQ `5672`.
- Workers can reach Valkey `6379`.
- Workers can reach the target applications being tested.
- End users should only reach the platform UI/API, not the tool workers.

## Worker Command

```bash
celery -A engine.tool_tasks.celery_app worker --loglevel=INFO --queues=tool-scans --concurrency=1
```

Install scanner CLIs on the worker instance or bake them into the worker image:

```bash
pip install -r requirements.txt
pip install garak
```

PyRIT and DeepTeam command support is scaffolded through the same worker path. Install their CLIs in the worker image when you enable those tools.

## Local Docker Compose

`docker-compose.yml` includes:

- `rabbitmq`
- `valkey`
- `api`
- `tool-worker`

Start everything locally:

```bash
docker compose up --build
```
