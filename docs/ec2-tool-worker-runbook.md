# EC2 Tool Invocation Runbook

Use this to deploy external tool invocation with Celery, RabbitMQ, and Valkey.

## Option A: MVP All-In-One EC2

Use one EC2 instance for:

- FastAPI API
- React frontend
- PostgreSQL
- RabbitMQ
- Valkey
- Celery tool worker

Recommended EC2 size for MVP: `t3.large` or bigger. Use Ubuntu or Amazon Linux 2023 with at least 30 GB disk.

### 1. Security Group

Open only what you need:

- `22` SSH from your IP only
- `8000` API from your IP or load balancer
- `5173` frontend from your IP or load balancer
- `15672` RabbitMQ management from your IP only, optional

Do not expose:

- `5672` RabbitMQ publicly
- `6379` Valkey publicly
- `5432` PostgreSQL publicly

### 2. Bootstrap Amazon Linux 2023

```bash
sudo dnf update -y
sudo dnf install -y git
git clone <YOUR_REPO_URL> AI-Red-Teaming-Platform
cd AI-Red-Teaming-Platform
bash deploy/ec2/bootstrap-amazon-linux-2023.sh
```

Edit `.env`:

```bash
nano .env
```

Start:

```bash
docker compose up -d --build
docker compose ps
```

Watch logs:

```bash
docker compose logs -f api tool-worker rabbitmq valkey
```

### 3. Test Queue Invocation

Install Python if needed, then run:

```bash
python3 scripts/smoke_tool_queue.py --api http://localhost:8000
```

Expected:

```text
PASS: queued dry-run completed through worker
```

This proves:

```text
API -> RabbitMQ -> Celery worker -> Valkey -> API polling
```

### 4. Test From Your Laptop

Replace `EC2_PUBLIC_IP`:

```bash
curl http://EC2_PUBLIC_IP:8000/health
python scripts/smoke_tool_queue.py --api http://EC2_PUBLIC_IP:8000
```

## Option B: Separate Worker EC2

Use this when RabbitMQ and Valkey run on another private EC2/ECS service.

On worker EC2:

```bash
git clone <YOUR_REPO_URL> AI-Red-Teaming-Platform
cd AI-Red-Teaming-Platform
cp deploy/ec2/.env.ec2.example .env
nano .env
```

Set:

```env
CELERY_BROKER_URL=amqp://redteam:<password>@<RABBITMQ_PRIVATE_IP>:5672//
CELERY_RESULT_BACKEND=redis://<VALKEY_PRIVATE_IP>:6379/0
CELERY_TASK_DEFAULT_QUEUE=tool-scans
```

Start only the worker:

```bash
docker compose -f deploy/ec2/docker-compose.worker.yml up -d --build
docker compose -f deploy/ec2/docker-compose.worker.yml logs -f tool-worker
```

## Running A Real Garak Job

First prove queue dry-run works. Then submit a real job:

```bash
curl -X POST http://localhost:8000/tool-scans/submit \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "garak",
    "profile": "quick",
    "timeout_seconds": 300,
    "dry_run": false,
    "garak_target_type": "ollama",
    "garak_target_name": "llama3.2",
    "garak_probe_mode": "owasp"
  }'
```

Poll the returned `job_id`:

```bash
curl http://localhost:8000/tool-scans/jobs/<JOB_ID>
```

For a real Garak scan, the worker must be able to reach the configured model target.

## Troubleshooting

Check service state:

```bash
docker compose ps
```

Check API:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/tool-scans/tools
```

Check worker logs:

```bash
docker compose logs -f tool-worker
```

Check RabbitMQ UI:

```text
http://EC2_PUBLIC_IP:15672
user: redteam
password: redteam
```

For production, change default passwords and restrict RabbitMQ management to your IP or private network.
