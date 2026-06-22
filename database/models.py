"""Database models designed to migrate from SQLite to PostgreSQL."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class TargetRecord(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(12))
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    request_template: Mapped[dict] = mapped_column(JSON, default=dict)
    auth: Mapped[dict] = mapped_column(JSON, default=dict)
    timeout_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scan_name: Mapped[str] = mapped_column(String(180), index=True)
    target_name: Mapped[str] = mapped_column(String(160), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)

    results: Mapped[list[ScanResultRecord]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    logs: Mapped[list[AttackLogRecord]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanResultRecord(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.scan_id"), index=True)
    scenario_id: Mapped[str] = mapped_column(String(160), index=True)
    scenario_name: Mapped[str] = mapped_column(String(180))
    owasp_category: Mapped[str] = mapped_column(String(120), index=True)
    result_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    scan: Mapped[ScanRecord] = relationship(back_populates="results")
    detector_results: Mapped[list[DetectorResultRecord]] = relationship(back_populates="scan_result", cascade="all, delete-orphan")


class AttackLogRecord(Base):
    __tablename__ = "attack_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.scan_id"), index=True)
    scenario_id: Mapped[str] = mapped_column(String(160), index=True)
    turn: Mapped[int] = mapped_column(Integer)
    stage: Mapped[str] = mapped_column(String(120))
    prompt: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text)
    elapsed_ms: Mapped[float] = mapped_column(Float, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    scan: Mapped[ScanRecord] = relationship(back_populates="logs")


class DetectorResultRecord(Base):
    __tablename__ = "detector_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_result_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id"), index=True)
    detector_id: Mapped[str] = mapped_column(String(180), index=True)
    vulnerable: Mapped[bool] = mapped_column()
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    scan_result: Mapped[ScanResultRecord] = relationship(back_populates="detector_results")
