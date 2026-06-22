import httpx
import pytest

from core.schemas import AttackPrompt, ScanSettings, TargetConfig
from engine.target_executor import TargetExecutor


@pytest.mark.asyncio
async def test_workflow_login_uses_form_encoding_and_cookie_session() -> None:
    seen_requests: list[tuple[str, str | None, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body_text = request.content.decode("utf-8")
        seen_requests.append((request.url.path, request.headers.get("content-type"), body_text))

        if request.url.path == "/login":
            assert request.headers.get("content-type") == "application/x-www-form-urlencoded"
            assert body_text == "username=admin&password=Password%40123"
            return httpx.Response(
                status_code=302,
                headers={
                    "location": "/",
                    "set-cookie": "session=test-session-cookie; Path=/; HttpOnly; SameSite=Lax",
                },
            )

        if request.url.path == "/chat":
            assert request.headers.get("content-type") == "application/json"
            assert request.headers.get("cookie", "").startswith("session=test-session-cookie")
            return httpx.Response(status_code=200, json={"response": "Hello! How can I assist you today?"})

        raise AssertionError(f"Unexpected path: {request.url.path}")

    executor = TargetExecutor(settings=ScanSettings(retry_count=0))
    target = TargetConfig(
        name="Vulnerable Chatbot (Session Auth)",
        url="http://example.com/chat",
        method="POST",
        headers={"Content-Type": "application/json"},
        request_template={"message": "{{prompt}}"},
        auth={
            "type": "session",
            "workflow": {
                "credential_authentication": {
                    "enabled": True,
                    "method": "POST",
                    "url": "http://example.com/login",
                    "body_encoding": "form",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": {"username": "admin", "password": "Password@123"},
                },
                "next_turn": {
                    "enabled": True,
                    "method": "POST",
                    "url": "http://example.com/chat",
                    "headers": {"Content-Type": "application/json"},
                    "body": {"message": "{{prompt}}"},
                    "response_message_path": "response",
                },
            },
        },
        timeout_seconds=30,
    )

    prompt = AttackPrompt(prompt="Hello", category="test", stage="test")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        login_result = await executor._request_with_retry(
            client=client,
            target=target,
            step=target.auth["workflow"]["credential_authentication"],
            context={
                "conversation_id": "conv-1",
                "session_id": "conv-1",
                "access_token": "",
                "prompt": prompt.prompt,
            },
        )
        assert login_result["status_code"] == 302

        chat_response = await client.request(
            method="POST",
            url="http://example.com/chat",
            headers={"Content-Type": "application/json"},
            json={"message": "Hello"},
        )

    assert chat_response.status_code == 200
    assert chat_response.json() == {"response": "Hello! How can I assist you today?"}
    assert [item[0] for item in seen_requests] == ["/login", "/chat"]