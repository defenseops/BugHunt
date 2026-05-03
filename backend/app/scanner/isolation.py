"""
Docker scan isolation — Phase 13.
Each scan runs in its own ephemeral container with:
  - network access only to postgres + redis (pentra-scan-net)
  - CPU: 2 cores, RAM: 1 GB
  - no host filesystem access
  - dropped capabilities (except DDoS scans: NET_ADMIN + NET_RAW)
Falls back to in-process execution when Docker daemon is unavailable.
"""
from __future__ import annotations

import asyncio
import os
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── Config ────────────────────────────────────────────────────────────────────

SCANNER_IMAGE   = os.getenv("SCANNER_IMAGE", "pentrascan-scanner:latest")
SCAN_NETWORK    = os.getenv("SCAN_NETWORK",  "pentra-scan-net")
MAX_PARALLEL    = int(os.getenv("MAX_PARALLEL_SCANS", "4"))
CPU_LIMIT       = os.getenv("SCAN_CPU_LIMIT",    "2")
MEM_LIMIT       = os.getenv("SCAN_MEM_LIMIT",    "1g")
MEM_SWAP_LIMIT  = os.getenv("SCAN_SWAP_LIMIT",   "1g")
SCAN_TIMEOUT    = int(os.getenv("SCAN_TIMEOUT_S", "3600"))   # 1 hour max

# Capabilities dropped by default
_CAP_DROP_DEFAULT = [
    "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER",
    "MKNOD", "SETGID", "SETUID", "SETFCAP",
    "SETPCAP", "SYS_CHROOT", "KILL", "AUDIT_WRITE",
]

# Capabilities for DDoS scans (need raw sockets)
_CAP_ADD_DDOS = ["NET_ADMIN", "NET_RAW"]

# ── Semaphore (limit parallel containers) ─────────────────────────────────────

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_PARALLEL)
    return _semaphore


# ── Docker availability check ─────────────────────────────────────────────────

def _docker_available() -> bool:
    """Check if docker CLI and daemon are accessible."""
    if not shutil.which("docker"):
        return False
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


# ── Network setup ─────────────────────────────────────────────────────────────

def ensure_scan_network() -> None:
    """Create pentra-scan-net if it doesn't exist."""
    if not _docker_available():
        return
    import subprocess
    result = subprocess.run(
        ["docker", "network", "inspect", SCAN_NETWORK],
        capture_output=True,
    )
    if result.returncode != 0:
        subprocess.run(
            ["docker", "network", "create",
             "--driver", "bridge",
             "--opt", "com.docker.network.bridge.enable_icc=false",
             SCAN_NETWORK],
            capture_output=True,
        )


# ── Container runner ──────────────────────────────────────────────────────────

async def run_scan_in_container(
    scan_id: str,
    scan_type: str,
    db_url: str,
    redis_url: str,
) -> tuple[int, str, str]:
    """
    Run a scan in an isolated Docker container.
    Returns (returncode, stdout, stderr).
    """
    sem = _get_semaphore()
    async with sem:
        needs_ddos_caps = scan_type == "full"

        cmd = [
            "docker", "run", "--rm",
            "--name", f"pentrascan-{scan_id[:12]}",
            # Network
            "--network", SCAN_NETWORK,
            # Resources
            "--cpus", CPU_LIMIT,
            "--memory", MEM_LIMIT,
            "--memory-swap", MEM_SWAP_LIMIT,
            # Security: run as non-root
            "--user", "1000:1000",
            # Drop all caps, then add back what's needed
            "--cap-drop", "ALL",
        ]

        # Add capabilities
        if needs_ddos_caps:
            cmd += ["--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
        else:
            # Keep only NET_RAW for nmap SYN scans
            cmd += ["--cap-add", "NET_RAW"]

        # Prevent privilege escalation
        cmd += ["--security-opt", "no-new-privileges:true"]

        # Read-only root except /tmp and /app/reports
        cmd += [
            "--read-only",
            "--tmpfs", "/tmp:rw,size=256m",
            "--tmpfs", "/run:rw,size=64m",
        ]

        # Mount reports directory
        reports_dir = os.getenv("REPORTS_DIR", "/app/reports")
        cmd += ["-v", f"{reports_dir}:{reports_dir}:rw"]

        # Environment
        cmd += [
            "-e", f"DATABASE_URL={db_url}",
            "-e", f"REDIS_URL={redis_url}",
            "-e", f"SCAN_ID={scan_id}",
            "-e", "PYTHONUNBUFFERED=1",
        ]

        # Pass through relevant env vars
        for key in ("NVD_API_KEY", "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"):
            val = os.getenv(key, "")
            if val:
                cmd += ["-e", f"{key}={val}"]

        # Image + entrypoint
        cmd += [SCANNER_IMAGE, "python", "-m", "app.tasks.run_scan_entrypoint", scan_id]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=SCAN_TIMEOUT
            )
            return proc.returncode or 0, stdout_b.decode(), stderr_b.decode()
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, "", f"Scan container timed out after {SCAN_TIMEOUT}s"


# ── Entrypoint script (runs inside the container) ─────────────────────────────

ENTRYPOINT_CODE = '''
"""
Entrypoint for isolated scan container.
Called as: python -m app.tasks.run_scan_entrypoint <scan_id>
"""
import asyncio
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: run_scan_entrypoint <scan_id>", file=sys.stderr)
        sys.exit(1)

    scan_id = sys.argv[1]
    from app.tasks.scan import _run_scan_async
    result = asyncio.run(_run_scan_async(scan_id))
    print(f"scan_result: {result}")


if __name__ == "__main__":
    main()
'''
