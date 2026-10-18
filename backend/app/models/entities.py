"""Persistence models for scans, endpoints and findings."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    target_base_url: Mapped[str] = mapped_column(String(500))
    discovery_mode: Mapped[str] = mapped_column(String(20))
    spec_document: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    manual_endpoints: Mapped[list | None] = mapped_column(JSON, nullable=True)
    auth_profiles: Mapped[list] = mapped_column(JSON, default=list)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    scope_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    request_body: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    security: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="endpoints")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True
    )
    endpoint_label: Mapped[str | None] = mapped_column(String(520), nullable=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    owasp_id: Mapped[str] = mapped_column(String(40))
    owasp_web: Mapped[str | None] = mapped_column(String(16), nullable=True)
    remediation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")
