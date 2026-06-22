import httpx
import pytest

from core.schemas import ScanSettings, TargetConfig
from engine.target_executor import TargetExecutor


@pytest.mark.asyncio
async def test_streaming_select_stop_and_session_extraction() -> None:
    sse = "\n".join(
        [
            'data: {"meta":{"task_id":"task-123"},"delta":{"role":"system","content":"meta"}}',
            'data: {"delta":{"role":"user","content":"ignored"}}',
            'data: {"delta":{"role":"agent","content":"Hel"}}',
            'data: {"delta":{"role":"agent","content":"lo"}}',
            'data: {"result":{"final":true}}',
            "",
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/chat"
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/event-stream"},
            content=sse,
        )

    executor = TargetExecutor(settings=ScanSettings(retry_count=0))
    target = TargetConfig(
        name="Stream Target",
        url="https://example.com/chat",
        method="POST",
        request_template={"message": "{{prompt}}"},
    )

    step = {
        "method": "POST",
        "url": "https://example.com/chat",
        "body": {"message": "{{prompt}}"},
        "streaming": {
            "enabled": True,
            "response_message_path": "delta.content",
            "response_session_id_path": "meta.task_id",
            "stop_conditions": [{"path": "result.final", "value": "true"}],
            "select_conditions": [{"path": "delta.role", "value": "agent"}],
        },
    }

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await executor._request_with_retry(
            client=client,
            target=target,
            step=step,
            context={"conversation_id": "conv-1", "prompt": "hi"},
        )

    assert result["status_code"] == 200
    assert result["text"] == "Hello"
    assert result.get("response_session_id") == "task-123"


@pytest.mark.asyncio
async def test_streaming_raw_done_sentinel_stops_before_parse() -> None:
    sse = "\n".join(
        [
            'data: {"delta":{"content":"A"}}',
            "data: [DONE]",
            'data: {"delta":{"content":"B"}}',
            "",
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/event-stream"},
            content=sse,
        )

    executor = TargetExecutor(settings=ScanSettings(retry_count=0))
    target = TargetConfig(name="Stream Target", url="https://example.com/chat", method="POST", request_template={})
    step = {
        "method": "POST",
        "url": "https://example.com/chat",
        "streaming": {
            "enabled": True,
            "response_message_path": "delta.content",
            "stop_conditions": [{"value": "[DONE]"}],
        },
    }

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await executor._request_with_retry(
            client=client,
            target=target,
            step=step,
            context={"conversation_id": "conv-2", "prompt": "hi"},
        )

    assert result["text"] == "A"


@pytest.mark.asyncio
async def test_non_streaming_behavior_remains_supported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, json={"answer": "ok"})

    executor = TargetExecutor(settings=ScanSettings(retry_count=0))
    target = TargetConfig(name="Plain Target", url="https://example.com/chat", method="POST", request_template={"q": "{{prompt}}"})
    step = {
        "method": "POST",
        "url": "https://example.com/chat",
        "body": {"q": "{{prompt}}"},
    }

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await executor._request_with_retry(
            client=client,
            target=target,
            step=step,
            context={"conversation_id": "conv-3", "prompt": "hi"},
        )

    assert result["status_code"] == 200
    assert result["json_body"] == {"answer": "ok"}
