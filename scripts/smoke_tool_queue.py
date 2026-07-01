"""Smoke test for queued external tool invocation.

This verifies:
API -> RabbitMQ -> Celery tool worker -> Valkey result backend -> API polling.

It uses dry_run=True, so Garak/PyRIT/DeepTeam do not need to execute for this
test to pass. It proves queue connectivity first.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def api_json(base_url: str, path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{base_url.rstrip('/')}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{exc.code} {exc.reason}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Could not reach API: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test Celery/RabbitMQ/Valkey tool queue.")
    parser.add_argument("--api", default="http://localhost:8000", help="Base URL for the FastAPI service.")
    parser.add_argument("--timeout", type=int, default=120, help="Seconds to wait for the worker result.")
    args = parser.parse_args()

    health = api_json(args.api, "/health")
    print(f"health: {health}")

    tools = api_json(args.api, "/tool-scans/tools")
    print(f"queue: {tools.get('queue')}")

    queued = api_json(
        args.api,
        "/tool-scans/submit",
        {
            "tool_id": "garak",
            "profile": "quick",
            "timeout_seconds": 30,
            "dry_run": True,
            "garak_target_type": "ollama",
            "garak_target_name": "llama3.2",
            "garak_probe_mode": "owasp",
        },
    )
    job_id = queued["job_id"]
    print(f"queued job: {job_id}")

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        status = api_json(args.api, f"/tool-scans/jobs/{job_id}")
        print(f"status: {status['status']}")
        if status.get("ready") or status.get("result"):
            result = status.get("result") or {}
            if result.get("status") == "VALIDATED":
                print("PASS: queued dry-run completed through worker")
                print("command:", " ".join(result.get("command", [])))
                return 0
            print(json.dumps(status, indent=2))
            print("FAIL: worker returned a non-validated result")
            return 1
        time.sleep(2)

    print(f"FAIL: job {job_id} did not complete within {args.timeout}s")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
