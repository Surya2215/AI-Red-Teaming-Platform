import pytest
import json
from pathlib import Path

from core.schemas import ScanRequest, ScanSettings, TargetConfig
from engine.scan_orchestrator import ScanOrchestrator


@pytest.mark.asyncio
async def test_mock_target_scan_completes_and_detects_vulnerability():
    request = ScanRequest(
        scan_name="pytest mock scan",
        target=TargetConfig(
            name="Mock HR Bot",
            url="mock://internal-hr-chatbot",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(max_turns=3, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    assert result.scenario_results[0].detector_results
    assert any(item.vulnerable for item in result.scenario_results[0].detector_results)

    report_path = Path("reports") / f"{result.scan_id}.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert "enterprise_report" in payload
    assert "enterprise_report_markdown" in payload
    assert "executive_summary" in payload["enterprise_report"]

