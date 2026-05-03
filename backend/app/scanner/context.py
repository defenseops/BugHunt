"""
ScanContext — shared state passed between scanner modules.
Handles DB writes and Redis pub/sub for live logs.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.scan_log import ScanLog
from app.scanner.base import Finding


class ScanContext:
    def __init__(self, db: AsyncSession, scan: Scan, redis):
        self.db = db
        self.scan = scan
        self.redis = redis
        self._channel = f"scan:{scan.id}:logs"

    async def log(self, message: str, level: str = "info", module: str | None = None) -> None:
        """Write log to DB and publish to Redis for WebSocket clients."""
        entry = ScanLog(
            scan_id=self.scan.id,
            level=level,
            module=module,
            message=message,
        )
        self.db.add(entry)
        await self.db.flush()

        payload = json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "module": module,
            "message": message,
        })
        await self.redis.publish(self._channel, payload)

    async def set_phase(self, phase: str) -> None:
        self.scan.current_phase = phase
        await self.db.flush()
        await self.log(f"Phase: {phase}", level="info")

    async def set_status(self, status: str) -> None:
        self.scan.status = status
        if status == "running" and not self.scan.started_at:
            self.scan.started_at = datetime.now(timezone.utc)
        if status in ("completed", "failed"):
            self.scan.finished_at = datetime.now(timezone.utc)
        await self.db.flush()

    async def save_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            row = ScanFinding(
                scan_id=self.scan.id,
                type=f.type,
                severity=f.severity,
                title=f.title,
                description=f.description,
                evidence=f.evidence,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                cve_id=f.cve_id,
                port=f.port,
                protocol=f.protocol,
                service=f.service,
                version=f.version,
                remediation=f.remediation,
                msf_module=f.msf_module,
                raw_output=f.raw_output,
            )
            self.db.add(row)
        await self.db.flush()
        await self.log(f"Saved {len(findings)} findings", level="success")

    async def commit(self) -> None:
        await self.db.commit()
