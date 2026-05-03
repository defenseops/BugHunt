"""
Base classes and helpers shared across scanner modules.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


@dataclass
class Finding:
    type: str
    title: str
    severity: str | None = None          # critical | high | medium | low | info
    description: str | None = None
    evidence: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_id: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    version: str | None = None
    remediation: str | None = None
    msf_module: str | None = None
    raw_output: str | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def run_cmd(
    cmd: list[str],
    timeout: int = 300,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """Run subprocess, return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
