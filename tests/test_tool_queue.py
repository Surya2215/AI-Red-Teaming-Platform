from datetime import UTC, datetime

from engine.tool_queue import get_tool_scan_job, queue_health, submit_tool_scan
from engine.tool_scan import ToolScanRequest, list_tool_connectors


class FakeTask:
    id = "task-123"


class FakeAsyncResult:
    state = "SUCCESS"
    result = {
        "scan_id": "scan-123",
        "tool_id": "garak",
        "tool_name": "Garak",
        "status": "VALIDATED",
        "started_at": datetime.now(UTC).isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "command": ["garak", "--help"],
        "dry_run": True,
        "report_paths": [],
    }

    def ready(self):
        return True


class FakeCeleryApp:
    def send_task(self, name, args, queue):
        self.name = name
        self.args = args
        self.queue = queue
        return FakeTask()

    def AsyncResult(self, job_id):
        self.job_id = job_id
        return FakeAsyncResult()


def test_submit_tool_scan_queues_request(monkeypatch):
    fake_app = FakeCeleryApp()
    monkeypatch.setattr("engine.tool_queue.get_celery_app", lambda: fake_app)

    request = ToolScanRequest(
        tool_id="garak",
        dry_run=True,
        garak_target_name="llama3.2",
    )

    queued = submit_tool_scan(request)

    assert queued.job_id == "task-123"
    assert queued.status == "QUEUED"
    assert fake_app.name == "redteam.tool_scan.run"
    assert fake_app.args[0]["tool_id"] == "garak"


def test_get_tool_scan_job_returns_completed_result(monkeypatch):
    fake_app = FakeCeleryApp()
    monkeypatch.setattr("engine.tool_queue.get_celery_app", lambda: fake_app)

    status = get_tool_scan_job("task-123")

    assert status.ready is True
    assert status.successful is True
    assert status.result is not None
    assert status.result.status == "VALIDATED"


def test_queue_health_redacts_credentials(monkeypatch):
    class Settings:
        tool_worker_enabled = True
        celery_broker_url = "amqp://redteam:secret@rabbitmq:5672//"
        celery_result_backend = "redis://:secret@valkey:6379/0"
        celery_task_default_queue = "tool-scans"

    monkeypatch.setattr("engine.tool_queue.get_settings", lambda: Settings())

    health = queue_health()

    assert health["queue"] == "tool-scans"
    assert "secret" not in health["broker"]
    assert "secret" not in health["result_backend"]


def test_worker_mode_connectors_do_not_require_local_tool_binaries():
    connectors = list_tool_connectors(worker_mode=True)

    assert connectors
    assert all(item["available"] for item in connectors)
    assert all(item["execution_mode"] == "worker_queue" for item in connectors)
