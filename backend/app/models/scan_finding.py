import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # port | dns | ssl | header | dir | osint | cve | misconfig | sqli | xss
    # lfi | ssti | cmdi | ssrf | xxe | cors | smuggling | jwt | brute | postex | ddos
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str | None] = mapped_column(
        String(50), nullable=True, index=True
    )  # critical | high | medium | low | info
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(4, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    msf_module: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
