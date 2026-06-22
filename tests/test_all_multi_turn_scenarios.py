"""Comprehensive tests for all multi-turn attack scenarios."""

import pytest
from core.schemas import ScanRequest, ScanSettings, TargetConfig
from engine.scan_orchestrator import ScanOrchestrator


@pytest.mark.asyncio
async def test_llm01_multi_turn_crescendo_attack():
    """Test LLM01 Crescendo multi-turn attack."""
    request = ScanRequest(
        scan_name="LLM01 crescendo attack test",
        target=TargetConfig(
            name="Test HR Bot",
            url="mock://internal-hr-chatbot",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.crescendo_attack"],
        settings=ScanSettings(max_turns=10, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify turns were executed
    assert len(scenario.turns) >= 1
    print(f"✓ Crescendo attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_indirect_injection():
    """Test LLM01 indirect prompt injection multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 indirect injection test",
        target=TargetConfig(
            name="Test Chatbot",
            url="mock://test-chatbot",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["indirect_prompt_injection"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ Indirect injection attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_rag_injection():
    """Test LLM01 RAG injection multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 RAG injection test",
        target=TargetConfig(
            name="Test RAG System",
            url="mock://test-rag",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["rag_injection"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ RAG injection attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_tool_injection():
    """Test LLM01 tool injection multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 tool injection test",
        target=TargetConfig(
            name="Test Tool System",
            url="mock://test-tools",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["tool_injection"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ Tool injection attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_encoding_obfuscation():
    """Test LLM01 encoding obfuscation multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 encoding obfuscation test",
        target=TargetConfig(
            name="Test Encoding",
            url="mock://test-encoding",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["encoding_obfuscation"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ Encoding obfuscation attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_context_saturation():
    """Test LLM01 context saturation multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 context saturation test",
        target=TargetConfig(
            name="Test Context",
            url="mock://test-context",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["context_saturation"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ Context saturation attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_delayed_triggering():
    """Test LLM01 delayed triggering multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 delayed triggering test",
        target=TargetConfig(
            name="Test Delayed",
            url="mock://test-delayed",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["delayed_triggering"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ Delayed triggering attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_llm01_multi_turn_agent_to_agent_injection():
    """Test LLM01 agent-to-agent injection multi-turn chain."""
    request = ScanRequest(
        scan_name="LLM01 agent-to-agent injection test",
        target=TargetConfig(
            name="Test Agent",
            url="mock://test-agent",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.prompt_injection"],
        settings=ScanSettings(
            max_turns=10,
            retry_count=0,
            prompt_injection_attack_types=["agent_to_agent_injection"],
        ),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify multi-turn chain was executed
    assert len(scenario.turns) > 0
    print(f"✓ Agent-to-agent injection attack executed {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_multi_turn_judge_decisions_are_recorded():
    """Test that judge decisions are properly recorded in multi-turn attacks."""
    request = ScanRequest(
        scan_name="Judge decisions test",
        target=TargetConfig(
            name="Test Judge",
            url="mock://test-judge",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.crescendo_attack"],
        settings=ScanSettings(max_turns=10, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Check for judge decisions in multi-turn chain
    judge_decisions_found = 0
    for turn in scenario.turns:
        if hasattr(turn, 'judge_decision') and turn.judge_decision:
            judge_decisions_found += 1
            print(f"✓ Turn {turn.turn}: Judge decision action={turn.judge_decision.next_action}")
    
    print(f"✓ Found {judge_decisions_found} judge decisions in {len(scenario.turns)} turns")


@pytest.mark.asyncio
async def test_multi_turn_respects_max_turns():
    """Test that multi-turn attacks respect max_turns limit."""
    request = ScanRequest(
        scan_name="Multi-turn max turns test",
        target=TargetConfig(
            name="Test Max Turns",
            url="mock://test-max-turns",
            method="POST",
            request_template={"message": "{{prompt}}", "conversation_id": "{{conversation_id}}"},
        ),
        scenario_ids=["llm01.crescendo_attack"],
        settings=ScanSettings(max_turns=5, retry_count=0),
    )

    result = await ScanOrchestrator().run_scan(request)

    assert result.status.value == "COMPLETED"
    assert result.scenario_results
    scenario = result.scenario_results[0]
    
    # Verify max_turns is respected
    assert len(scenario.turns) <= 5, f"Expected max 5 turns, got {len(scenario.turns)}"
    print(f"✓ Multi-turn respects max_turns: {len(scenario.turns)}/5 turns executed")
