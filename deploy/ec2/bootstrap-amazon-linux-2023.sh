#!/usr/bin/env bash
set -euo pipefail

# Bootstrap an Amazon Linux 2023 EC2 instance for the red-team platform.
# Usage:
#   REPO_URL=https://github.com/<org>/<repo>.git bash deploy/ec2/bootstrap-amazon-linux-2023.sh

APP_DIR="${APP_DIR:-/opt/ai-red-teaming-platform}"
REPO_URL="${REPO_URL:-}"

sudo dnf update -y
sudo dnf install -y git docker
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user || true

sudo mkdir -p "$APP_DIR"
sudo chown -R "$USER:$USER" "$APP_DIR"

if [ -n "$REPO_URL" ] && [ ! -d "$APP_DIR/.git" ]; then
  git clone "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"

if [ ! -f .env ]; then
  cp deploy/ec2/.env.ec2.example .env
  echo "Created $APP_DIR/.env. Edit it with real secrets before starting the stack."
fi

mkdir -p logs reports targets

docker compose version

cat <<'NEXT_STEPS'

Bootstrap complete.

Next:
  1. Edit .env with real provider secrets:
       nano .env

  2. Start the all-in-one stack:
       docker compose up -d --build

  3. Watch services:
       docker compose ps
       docker compose logs -f api tool-worker rabbitmq valkey

  4. Test queued tool invocation:
       python3 scripts/smoke_tool_queue.py --api http://localhost:8000

If this is a worker-only EC2 instance, use:
       docker compose -f deploy/ec2/docker-compose.worker.yml up -d --build

NEXT_STEPS
