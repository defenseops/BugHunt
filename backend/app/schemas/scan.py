import uuid
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, Field, field_validator
import ipaddress
import re


# ── helpers ────────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def _validate_target(v: str) -> str:
    v = v.strip()
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    try:
        ipaddress.ip_network(v, strict=False)
        return v
    except ValueError:
        pass
    if _DOMAIN_RE.match(v):
        return v
    raise ValueError("Target must be a valid IP, CIDR, or domain name")


# ── requests ───────────────────────────────────────────────────────────────

ScanTypeT = Literal["full", "port", "vuln", "web"]

class CreateScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    scan_type: ScanTypeT = "full"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)


# ── responses ──────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: uuid.UUID
    type: str
    severity: str | None
    title: str
    description: str | None
    evidence: str | None
    cvss_score: Decimal | None
    cvss_vector: str | None
    cve_id: str | None
    port: int | None
    protocol: str | None
    service: str | None
    version: str | None
    remediation: str | None
    msf_module: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: uuid.UUID
    target: str
    scan_type: str
    status: str
    current_phase: str | None
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    findings_count: int = 0

    model_config = {"from_attributes": True}


class ScanDetailOut(ScanOut):
    findings: list[FindingOut] = []


class ScanListOut(BaseModel):
    items: list[ScanOut]
    total: int
    page: int
    limit: int
