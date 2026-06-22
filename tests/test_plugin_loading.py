from engine.scenario_loader import PluginLoader
from core.schemas import ScanSettings


def test_discovers_llm01_scenarios_and_detectors():
    loader = PluginLoader()
    scenarios = loader.discover_scenarios("LLM01-Prompt Injection")
    detectors = loader.discover_detectors("LLM01-Prompt Injection")

    assert "llm01.prompt_injection" in scenarios
    assert "llm01.crescendo_attack" in scenarios
    assert "llm01.injection_compliance_detector" in detectors
    assert "llm01.compliance_drift_detector" in detectors


def test_prompt_injection_includes_multi_turn_attack_taxonomy():
    scenario = PluginLoader().discover_scenarios("LLM01-Prompt Injection")["llm01.prompt_injection"]
    chains = scenario.build_multi_turn_attack_chains(target=None, settings=None)
    attack_types = {chain[0].metadata["attack_type"] for chain in chains}

    assert attack_types == {
        "Indirect Prompt Injection",
        "RAG Injection",
        "Tool Injection",
        "Encoding Obfuscation",
        "Context Saturation",
        "Delayed Triggering",
        "Agent-to-Agent Injection",
    }
    assert all(len(chain) == 3 for chain in chains)


def test_prompt_injection_attack_taxonomy_can_be_filtered():
    scenario = PluginLoader().discover_scenarios("LLM01-Prompt Injection")["llm01.prompt_injection"]
    chains = scenario.build_multi_turn_attack_chains(
        target=None,
        settings=ScanSettings(prompt_injection_attack_types=["rag_injection", "tool_injection"]),
    )

    assert [chain[0].metadata["chain_id"] for chain in chains] == ["rag_injection", "tool_injection"]


def test_prompt_injection_single_turn_payloads_can_be_disabled():
    scenario = PluginLoader().discover_scenarios("LLM01-Prompt Injection")["llm01.prompt_injection"]
    payloads = scenario.build_payloads(
        target=None,
        settings=ScanSettings(prompt_injection_include_single_turn=False),
    )

    assert payloads == []


def test_discovers_llm02_sensitive_information_plugins():
    loader = PluginLoader()
    scenarios = loader.discover_scenarios("LLM02-Sensitive Information Disclosure")
    detectors = loader.discover_detectors("LLM02-Sensitive Information Disclosure")

    assert "llm02.sensitive_information_disclosure" in scenarios
    assert "llm02.sensitive_disclosure_detector" in detectors
    assert len(scenarios["llm02.sensitive_information_disclosure"].build_payloads()) >= 29
    attack_types = {attack["attack_id"] for attack in scenarios["llm02.sensitive_information_disclosure"].attack_definitions()}
    assert attack_types == {
        "credentials_leakage",
        "pii_exfiltration",
        "training_data_extraction",
        "confidential_business_logic_exposure",
        "indirect_disclosure_via_inference",
    }


def test_llm02_payloads_can_be_filtered_by_attack_type():
    scenario = PluginLoader().discover_scenarios("LLM02-Sensitive Information Disclosure")["llm02.sensitive_information_disclosure"]
    payloads = scenario.build_payloads(ScanSettings(sensitive_information_attack_types=["credentials_leakage"]))

    assert payloads
    assert {payload.category for payload in payloads} == {"credentials_leakage"}


def test_llm02_attack_family_probe_counts():
    scenario = PluginLoader().discover_scenarios("LLM02-Sensitive Information Disclosure")[
        "llm02.sensitive_information_disclosure"
    ]
    payloads = scenario.build_payloads()
    counts = {}
    for payload in payloads:
        counts[payload.category] = counts.get(payload.category, 0) + 1

    assert counts == {
        "credentials_leakage": 12,
        "pii_exfiltration": 14,
        "training_data_extraction": 1,
        "confidential_business_logic_exposure": 1,
        "indirect_disclosure_via_inference": 12,
    }


def test_llm02_indirect_disclosure_has_full_probe_set():
    scenario = PluginLoader().discover_scenarios("LLM02-Sensitive Information Disclosure")["llm02.sensitive_information_disclosure"]
    payloads = scenario.build_payloads(
        ScanSettings(sensitive_information_attack_types=["indirect_disclosure_via_inference"])
    )

    assert len(payloads) == 12
    assert {payload.category for payload in payloads} == {"indirect_disclosure_via_inference"}


def test_discovers_llm03_supply_chain_plugins():
    loader = PluginLoader()
    scenarios = loader.discover_scenarios("LLM03-Supply Chain")
    detectors = loader.discover_detectors("LLM03-Supply Chain")

    assert "llm03.supply_chain" in scenarios
    assert "llm03.supply_chain_detector" in detectors
    assert len(scenarios["llm03.supply_chain"].build_payloads()) >= 34
    attack_types = {attack["attack_id"] for attack in scenarios["llm03.supply_chain"].attack_definitions()}
    assert attack_types == {
        "behavioural_validation",
        "provenance_integrity",
        "training_data_dataset_poisoning",
        "compromised_plugins_integrations",
        "model_tampering",
        "ai_bom_gaps",
    }


def test_llm03_payloads_can_be_filtered_by_attack_type():
    scenario = PluginLoader().discover_scenarios("LLM03-Supply Chain")["llm03.supply_chain"]
    payloads = scenario.build_payloads(ScanSettings(supply_chain_attack_types=["ai_bom_gaps"]))

    assert payloads
    assert {payload.category for payload in payloads} == {"ai_bom_gaps"}
