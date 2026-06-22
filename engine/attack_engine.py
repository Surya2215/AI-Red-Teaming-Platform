"""Attack engine that executes dynamically loaded scenarios."""

from __future__ import annotations

from collections.abc import AsyncIterator

from core.logging import get_logger
from core.schemas import ScanRequest, ScenarioResult
from engine.judge_agent import JudgeAgent
from engine.scenario_loader import PluginLoader
from engine.target_executor import TargetExecutor


logger = get_logger(__name__)


class AttackEngine:
    """Load scenarios and execute them asynchronously."""

    def __init__(
        self,
        loader: PluginLoader | None = None,
        target_executor: TargetExecutor | None = None,
        judge_agent: JudgeAgent | None = None,
    ) -> None:
        self.loader = loader or PluginLoader()
        self.target_executor = target_executor
        self.judge_agent = judge_agent

    async def run(self, request: ScanRequest) -> AsyncIterator[ScenarioResult]:
        scenarios = self.loader.discover_scenarios(request.owasp_category)
        selected_ids = request.scenario_ids or list(scenarios)
        for scenario_id in selected_ids:
            scenario = scenarios.get(scenario_id)
            if scenario is None:
                logger.warning("Requested scenario not found.", extra={"scenario": scenario_id, "scan_id": request.scan_id})
                continue
            executor = self.target_executor or TargetExecutor(request.settings, scan_id=request.scan_id)
            judge = self.judge_agent or JudgeAgent(settings=request.settings)
            logger.info("Executing scenario.", extra={"scenario": scenario_id, "scan_id": request.scan_id})
            yield await scenario.run(
                target=request.target,
                settings=request.settings,
                target_executor=executor,
                judge_agent=judge,
                scan_id=request.scan_id,
            )

