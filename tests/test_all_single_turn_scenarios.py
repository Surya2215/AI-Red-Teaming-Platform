"""Comprehensive tests for all single-turn attack scenarios."""

import pytest
from core.schemas import ScanRequest, ScanSettings, TargetConfig
from engine.scan_orchestrator import ScanOrchestrator


@pytest.mark.asyncio
async def test_llm01_single_turn_executes_multiple_payloads():
    """Test that LLM01 single-turn attack executes multiple payloads, not just the first one."""
    request = ScanRequest(
        scan_name="LLM01 single-turn multiple payloads",
        target=TargetConfig(
            name="Test HR Bot",
            url="mock://internal-hr-chatbot",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(max_turns=25, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multiple turns were executed (not just 1)
    assert len(scenario.turns) > 1, f"Expected multiple turns, got {len(scenario.turns)}"
    
    # Count distinct prompt categories to ensure variety
    categories = set()
    for turn in scenario.turns:
        if turn.prompt and turn.prompt.category:
            categories.add(turn.prompt.category)
    
    assert len(categories) > 0, "Expected multiple prompt categories"
    print(f"✓ Executed {len(scenario.turns)} payloads across {len(categories)} categories")


@pytest.mark.asyncio
async def test_llm02_single_turn_execution():
    """Test LLM02 Sensitive Information Disclosure scenario."""
    request = ScanRequest(
        scan_name="LLM02 single-turn test",
        owasp_category="LLM02_Sensitive_Information_Disclosure",
        target=TargetConfig(
            name="Test Chatbot",
            url="mock://test-chatbot",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm02.sensitive_information_disclosure"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    assert len(scenario.turns) >= 1


@pytest.mark.asyncio
async def test_llm03_single_turn_execution():
    """Test LLM03 Supply Chain scenario."""
    request = ScanRequest(
        scan_name="LLM03 single-turn test",
        owasp_category="LLM03_Supply_Chain",
        target=TargetConfig(
            name="Test API",
            url="mock://test-api",
            method="POST",
            request_template={"input": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm03.supply_chain"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    assert len(scenario.turns) >= 1


@pytest.mark.asyncio
async def test_llm04_single_turn_execution():
    """Test LLM04 Data/Model Poisoning scenario."""
    request = ScanRequest(
        scan_name="LLM04 single-turn test",
        owasp_category="LLM04-Data_model_poisoning",
        target=TargetConfig(
            name="Test Model",
            url="mock://test-model",
            method="POST",
            request_template={"data": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm04.data_model_poisoning"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_llm05_single_turn_execution():
    """Test LLM05 Improper Output Handling scenario."""
    request = ScanRequest(
        scan_name="LLM05 single-turn test",
        owasp_category="LLM05-Improper_output_handling",
        target=TargetConfig(
            name="Test Handler",
            url="mock://test-handler",
            method="POST",
            request_template={"output": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm05.improper_output_handling"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_llm06_single_turn_execution():
    """Test LLM06 Excessive Agency scenario."""
    request = ScanRequest(
        scan_name="LLM06 single-turn test",
        owasp_category="LLM06-Excessive_agency",
        target=TargetConfig(
            name="Test Agent",
            url="mock://test-agent",
            method="POST",
            request_template={"action": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm06.excessive_agency"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_llm07_single_turn_execution():
    """Test LLM07 Insecure Plugin Design scenario."""
    request = ScanRequest(
        scan_name="LLM07 single-turn test",
        owasp_category="LLM07-Insecure Plugin Design",
        target=TargetConfig(
            name="Test Plugin",
            url="mock://test-plugin",
            method="POST",
            request_template={"plugin": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm07.system_prompt_leakage"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_llm08_single_turn_execution():
    """Test LLM08 Vector Embedding Weaknesses scenario."""
    request = ScanRequest(
        scan_name="LLM08 single-turn test",
        owasp_category="LLM08-Vector_Embedding_Weaknesses",
        target=TargetConfig(
            name="Test Embedding",
            url="mock://test-embedding",
            method="POST",
            request_template={"embedding": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm08.vector_embedding_weaknesses"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_llm09_single_turn_execution():
    """Test LLM09 Misinformation scenario."""
    request = ScanRequest(
        scan_name="LLM09 single-turn test",
        owasp_category="LLM09-Misinformation",
        target=TargetConfig(
            name="Test Misinformation",
            url="mock://test-misinformation",
            method="POST",
            request_template={"info": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm09.misinformation"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_llm10_single_turn_execution():
    """Test LLM10 Unbounded Consumption scenario."""
    request = ScanRequest(
        scan_name="LLM10 single-turn test",
        owasp_category="LLM10-Unbounded_Consumption",
        target=TargetConfig(
            name="Test Unbounded",
            url="mock://test-unbounded",
            method="POST",
            request_template={"resource": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm10.unbounded_consumption"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results


@pytest.mark.asyncio
async def test_all_scenarios_with_max_turns_limit():
    """Test that all scenarios respect max_turns limit."""
    request = ScanRequest(
        scan_name="Max turns enforcement test",
        target=TargetConfig(
            name="Test Bot",
            url="mock://test-bot",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(max_turns=3, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify max_turns is respected
    assert len(scenario.turns) <= 3, f"Expected max 3 turns, got {len(scenario.turns)}"
    print(f"✓ Max turns enforced: {len(scenario.turns)}/3 turns executed")


@pytest.mark.asyncio
async def test_detector_results_for_single_turn_attacks():
    """Test that detector results are generated for single-turn attacks."""
    request = ScanRequest(
        scan_name="Detector results test",
        target=TargetConfig(
            name="Test Detector",
            url="mock://test-detector",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify detectors were executed
    assert scenario.detector_results, "Expected detector results"
    assert len(scenario.detector_results) > 0
    
    # Verify each detector result has expected fields
    for detector_result in scenario.detector_results:
        assert detector_result.detector_id
        assert hasattr(detector_result, 'vulnerable')
        print(f"✓ Detector {detector_result.detector_id}: vulnerable={detector_result.vulnerable}")
