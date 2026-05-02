import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    level: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    # info | success | warning | error
    module: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # nmap | sqlmap | hydra | ffuf | etc.
    message: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="logs")
