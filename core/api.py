"""FastAPI application for programmatic scans."""

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from core.schemas import ScanRequest, ScanResult, TargetConfig
from database.repository import Repository
from database.session import get_session, init_db
from engine.scan_orchestrator import ScanOrchestrator
from engine.target_executor import TargetExecutor


app = FastAPI(title="AI Red Teaming Platform", version="1.0.0")


@app.on_event("startup")
async def startup() -> None:
    await init_db()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/targets")
async def save_target(target: TargetConfig, session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    await Repository(session).upsert_target(target)
    return {"status": "saved", "target": target.name}


@app.post("/targets/test")
async def test_target(target: TargetConfig) -> dict[str, object]:
    executor = TargetExecutor()
    return await executor.test_connection(target)


@app.post("/scans", response_model=ScanResult)
async def run_scan(request: ScanRequest, session: AsyncSession = Depends(get_session)) -> ScanResult:
    orchestrator = ScanOrchestrator(repository=Repository(session))
    return await orchestrator.run_scan(request)

