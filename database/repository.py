"""Persistence helpers for scans, targets, logs, and detector results."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.schemas import ScanRequest, ScanResult, ScanStatus, ScenarioResult, TargetConfig
from database.models import AttackLogRecord, DetectorResultRecord, ScanRecord, ScanResultRecord, TargetRecord


class Repository:
    """Thin repository abstraction for easy PostgreSQL migration."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert_target(self, target: TargetConfig) -> TargetRecord:
        result = await self.session.execute(select(TargetRecord).where(TargetRecord.name == target.name))
        record = result.scalar_one_or_none()
        payload = target.model_dump(mode="json")
        if record is None:
            record = TargetRecord(**payload)
            self.session.add(record)
        else:
            for key, value in payload.items():
                setattr(record, key, value)
        await self.session.commit()
        return record

    async def list_targets(self) -> list[TargetRecord]:
        result = await self.session.execute(select(TargetRecord).order_by(TargetRecord.name))
        return list(result.scalars().all())

    async def create_scan(self, request: ScanRequest) -> ScanRecord:
        record = ScanRecord(
            scan_id=request.scan_id,
            scan_name=request.scan_name,
            target_name=request.target.name,
            status=ScanStatus.RUNNING.value,
            settings=request.settings.model_dump(),
        )
        self.session.add(record)
        await self.session.commit()
        return record

    async def complete_scan(self, result: ScanResult) -> None:
        scan = await self._get_scan(result.scan_id)
        scan.status = result.status.value
        scan.completed_at = result.completed_at
        scan.error = result.error
        for scenario in result.scenario_results:
            await self.add_scenario_result(result.scan_id, scenario)
        await self.session.commit()

    async def add_scenario_result(self, scan_id: str, scenario: ScenarioResult) -> None:
        result_record = ScanResultRecord(
            scan_id=scan_id,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.scenario_name,
            owasp_category=scenario.owasp_category,
            result_json=scenario.model_dump(mode="json"),
        )
        self.session.add(result_record)
        await self.session.flush()

        for turn in scenario.turns:
            self.session.add(
                AttackLogRecord(
                    scan_id=scan_id,
                    scenario_id=scenario.scenario_id,
                    turn=turn.turn,
                    stage=turn.prompt.stage,
                    prompt=turn.prompt.prompt,
                    response=turn.response.body,
                    elapsed_ms=turn.response.elapsed_ms,
                )
            )

        for detector in scenario.detector_results:
            self.session.add(
                DetectorResultRecord(
                    scan_result_id=result_record.id,
                    detector_id=detector.detector_id,
                    vulnerable=detector.vulnerable,
                    confidence=detector.confidence,
                    severity=detector.severity.value,
                    reason=detector.reason,
                    evidence=detector.evidence,
                )
            )

    async def list_scans(self) -> list[ScanRecord]:
        result = await self.session.execute(select(ScanRecord).order_by(ScanRecord.started_at.desc()))
        return list(result.scalars().all())

    async def list_scan_results(self) -> list[ScanResultRecord]:
        result = await self.session.execute(select(ScanResultRecord).order_by(ScanResultRecord.created_at.desc()))
        return list(result.scalars().all())

    async def _get_scan(self, scan_id: str) -> ScanRecord:
        result = await self.session.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
        scan = result.scalar_one()
        return scan
