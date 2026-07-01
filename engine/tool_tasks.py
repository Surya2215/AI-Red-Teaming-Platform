"""Celery task entrypoints for external red-team tool execution."""

from __future__ import annotations

from engine.tool_queue import get_celery_app
from engine.tool_scan import ToolScanRequest, run_tool_scan


celery_app = get_celery_app()


@celery_app.task(name="redteam.tool_scan.run", bind=True)
def run_tool_scan_task(self, request_payload: dict) -> dict:
    request = ToolScanRequest.model_validate(request_payload)
    result = run_tool_scan(request)
    return result.model_dump(mode="json")
