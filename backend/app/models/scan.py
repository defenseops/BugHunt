import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    mode: Mapped[str] = mapped_column(String(50), nullable=False)           # auto | step
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)      # recon | full
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending", index=True
    )
    # pending | running | recon_complete | analyzing | exploiting | done | failed
    current_phase: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="scans")
    findings: Mapped[list["ScanFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    logs: Mapped[list["ScanLog"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
