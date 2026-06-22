"""Async SQLAlchemy session setup."""

from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.config import get_settings


settings = get_settings()
engine = create_async_engine(settings.database_url, future=True, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    from database.models import Base

    async with engine.begin() as conn:
        if conn.dialect.name == "sqlite":
            tables = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            existing_tables = {row[0] for row in tables}
            if {"targets", "scans", "scan_results", "attack_logs", "detector_results"}.issubset(existing_tables):
                await _migrate_sqlite(conn)
                return
        await conn.run_sync(Base.metadata.create_all)
        if conn.dialect.name == "sqlite":
            await _migrate_sqlite(conn)


async def _migrate_sqlite(conn) -> None:
    columns = await conn.execute(text("PRAGMA table_info(targets)"))
    existing = {row[1] for row in columns}
    if "timeout_seconds" not in existing:
        await conn.execute(text("ALTER TABLE targets ADD COLUMN timeout_seconds FLOAT"))
