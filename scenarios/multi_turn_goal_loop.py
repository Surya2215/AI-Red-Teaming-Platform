"""Shared goal-driven multi-turn execution helper for attack scenarios."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from core.schemas import AttackPrompt, AttackTurn, ScenarioResult, ScanSettings, TargetConfig


async def execute_goal_driven_multi_turn(
    *,
    scenario_id: str,
    scenario_name: str,
    owasp_category: str,
    target: TargetConfig,
    settings: ScanSettings,
    target_executor,
    judge_agent,
    staged_payloads: list[AttackPrompt],
    attack_context: dict,
) -> ScenarioResult:
    """Run a multi-turn scenario with one opening prompt and judge-driven follow-ups."""

    started = datetime.now(UTC)
    conversation_id = str(uuid4())
    turns: list[AttackTurn] = []

    if not staged_payloads:
        return ScenarioResult(
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            owasp_category=owasp_category,
            turns=[],
            started_at=started,
            completed_at=datetime.now(UTC),
        )

    next_payload = staged_payloads[0]

    for turn_number in range(1, settings.max_turns + 1):
        response = await target_executor.execute(target, next_payload, conversation_id)
        turn = AttackTurn(turn=turn_number, prompt=next_payload, response=response)
        turns.append(turn)

        if turn_number >= settings.max_turns:
            break

        decision = await judge_agent.decide(target, turns, attack_context=attack_context)
        turn.judge_decision = decision

        # Keep attacking until max_turns. The judge controls prompt content, not loop length.
        fallback_seed = staged_payloads[min(turn_number, len(staged_payloads) - 1)]
        adaptive_prompt = (decision.suggested_prompt or "").strip() or fallback_seed.prompt
        next_payload = AttackPrompt(
            category=fallback_seed.category,
            stage=fallback_seed.stage if turn_number < len(staged_payloads) else f"adaptive_turn_{turn_number + 1}",
            prompt=adaptive_prompt,
            metadata={
                **fallback_seed.metadata,
                **attack_context,
                "adaptive": True,
                "judge_next_action": decision.next_action,
                "judge_risk_score": decision.risk_score,
                "judge_reasoning": decision.reasoning,
                "judge_suggested_prompt": decision.suggested_prompt,
            },
        )

    return ScenarioResult(
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        owasp_category=owasp_category,
        turns=turns,
        started_at=started,
        completed_at=datetime.now(UTC),
    )
