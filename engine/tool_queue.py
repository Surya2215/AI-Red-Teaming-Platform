"""Celery-backed tool scan queue integration.

RabbitMQ is used as the broker and Valkey is used as the Redis-compatible
result backend. The module is intentionally optional so local development and
tests can still use the blocking ``run_tool_scan`` path without Celery running.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from core.config import get_settings
from engine.tool_scan import TOOL_DEFINITIONS, ToolScanRequest, ToolScanResult


class ToolScanQueuedResult(BaseModel):
    job_id: str
    celery_task_id: str
    tool_id: str
    tool_name: str
    status: str = "QUEUED"
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolScanJobStatus(BaseModel):
    job_id: str
    status: str
    ready: bool
    successful: bool = False
    submitted_at: datetime | None = None
    completed_at: datetime | None = None
    result: ToolScanResult | None = None
    error: str | None = None


def get_celery_app():
    """Create the Celery app lazily so importing the API does not require Celery."""

    try:
        from celery import Celery
    except ImportError as exc:
        raise RuntimeError("Celery is not installed. Install requirements.txt in the API and worker environments.") from exc

    settings = get_settings()
    app = Celery(
        "ai_red_team_tool_scans",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=["engine.tool_tasks"],
    )
    app.conf.update(
        task_default_queue=settings.celery_task_default_queue,
        task_track_started=True,
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        worker_prefetch_multiplier=1,
        task_acks_late=True,
    )
    return app


def submit_tool_scan(request: ToolScanRequest) -> ToolScanQueuedResult:
    """Submit a scan to RabbitMQ for execution by an EC2/ECS tool worker."""

    tool = TOOL_DEFINITIONS[request.tool_id]
    app = get_celery_app()
    task = app.send_task(
        "redteam.tool_scan.run",
        args=[request.model_dump(mode="json")],
        queue=get_settings().celery_task_default_queue,
    )
    return ToolScanQueuedResult(
        job_id=task.id,
        celery_task_id=task.id,
        tool_id=tool.id,
        tool_name=tool.name,
    )


def get_tool_scan_job(job_id: str) -> ToolScanJobStatus:
    """Read current job state from Valkey/Celery result backend."""

    app = get_celery_app()
    async_result = app.AsyncResult(job_id)
    state = str(async_result.state or "PENDING")

    if state == "SUCCESS":
        payload = async_result.result
        if isinstance(payload, dict):
            result = ToolScanResult.model_validate(payload)
            return ToolScanJobStatus(
                job_id=job_id,
                status=result.status,
                ready=True,
                successful=result.status in {"COMPLETED", "VALIDATED"},
                completed_at=result.completed_at,
                result=result,
            )
        return ToolScanJobStatus(job_id=job_id, status="FAILED", ready=True, error="Worker returned a non-JSON result.")

    if state == "FAILURE":
        return ToolScanJobStatus(job_id=job_id, status="FAILED", ready=True, error=str(async_result.result))

    status_map: dict[str, str] = {
        "PENDING": "QUEUED",
        "RECEIVED": "QUEUED",
        "STARTED": "RUNNING",
        "RETRY": "RETRYING",
        "REVOKED": "CANCELLED",
    }
    return ToolScanJobStatus(
        job_id=job_id,
        status=status_map.get(state, state),
        ready=async_result.ready(),
    )


def queue_health() -> dict[str, Any]:
    """Return queue configuration without exposing credentials."""

    settings = get_settings()
    return {
        "worker_enabled": settings.tool_worker_enabled,
        "broker": _redact_url(settings.celery_broker_url),
        "result_backend": _redact_url(settings.celery_result_backend),
        "queue": settings.celery_task_default_queue,
    }


def _redact_url(value: str) -> str:
    if "@" not in value or "://" not in value:
        return value
    scheme, rest = value.split("://", 1)
    return f"{scheme}://***@{rest.split('@', 1)[1]}"
