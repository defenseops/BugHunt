"""
Hydra brute-force module — Phase 7.1.
Primary: Hydra. Fallback: Medusa (then ncrack for SSH/RDP).
Targets auth services found by nmap.
Only runs on scan_type in ('full', 'vuln').
"""
from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# Services hydra supports, mapped from nmap service names
_HYDRA_SERVICES: dict[str, str] = {
    "ssh":     "ssh",
    "ftp":     "ftp",
    "telnet":  "telnet",
    "rdp":     "rdp",
    "smb":     "smb",
    "smbv2":   "smb",
    "mysql":   "mysql",
    "mssql":   "mssql",
    "vnc":     "vnc",
    "smtp":    "smtp",
    "imap":    "imap",
    "pop3":    "pop3",
    "http":    "http-get",
    "https":   "https-get",
    "mongodb": "mongodb",
    "redis":   "redis",
    "postgresql": "postgres",
}

# Minimal but effective credential wordlist for quick scan
_USERNAMES = [
    "root", "admin", "administrator", "user", "test", "guest",
    "oracle", "postgres", "mysql", "ftp", "anonymous", "pi",
    "ubuntu", "kali", "vagrant", "deploy", "service",
]

_PASSWORDS = [
    "", "root", "admin", "admin123", "password", "password1",
    "123456", "12345678", "test", "guest", "1234", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master",
    "changeme", "default", "toor", "alpine", "raspberry",
    "vagrant", "ubuntu", "kali", "pass", "secret",
]

# For anonymous/blank-password services
_BLANK_ONLY = ["", "anonymous", "ftp"]


def _extract_hydra_targets(nmap_findings: list[Finding]) -> list[tuple[int, str]]:
    """Return (port, hydra_service) pairs from nmap port findings."""
    targets: list[tuple[int, str]] = []
    seen: set[int] = set()

    for f in nmap_findings:
        if f.type != "port" or f.port is None:
            continue
        svc = (f.service or "").lower()
        hydra_svc = _HYDRA_SERVICES.get(svc)
        if hydra_svc and f.port not in seen:
            targets.append((f.port, hydra_svc))
            seen.add(f.port)

    return targets


def _parse_hydra_output(output: str, port: int, service: str, target: str) -> list[Finding]:
    """
    Hydra success lines look like:
    [port][service] host: <ip>   login: <user>   password: <pass>
    """
    findings: list[Finding] = []
    pattern = re.compile(
        r"\[(\d+)\]\[([^\]]+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s*(.*)",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        m = pattern.search(line)
        if not m:
            continue

        found_port    = int(m.group(1))
        found_service = m.group(2).strip()
        login         = m.group(3).strip()
        password      = m.group(4).strip()

        display_pass  = "(blank)" if password == "" else password
        title = f"Weak credential on {found_service}:{found_port} — {login}:{display_pass}"

        findings.append(Finding(
            type="brute",
            title=title,
            severity="critical",
            description=(
                f"Hydra found valid credentials for {found_service} on port {found_port}.\n"
                f"Login: {login}\nPassword: {display_pass}\nTarget: {target}"
            ),
            evidence=f"{login}:{display_pass} → {target}:{found_port}/{found_service}",
            port=found_port,
            protocol="tcp",
            service=found_service,
            remediation=(
                "Change credentials immediately. "
                "Disable default accounts. "
                "Enforce strong password policy and consider disabling password auth "
                "(use SSH keys for SSH, certificates for other services). "
                "Enable account lockout after failed attempts."
            ),
        ))

    return findings


async def run_hydra(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type not in ("full", "vuln"):
        return result

    targets = _extract_hydra_targets(nmap_findings)
    if not targets:
        await ctx.log("Hydra: no brute-forceable services found", module="hydra")
        return result

    await ctx.log(
        f"Hydra: testing {len(targets)} service(s): {[(p, s) for p, s in targets]}",
        module="hydra",
    )

    # Write temp wordlist files
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
        uf.write("\n".join(_USERNAMES))
        users_file = uf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
        pf.write("\n".join(_PASSWORDS))
        pass_file = pf.name

    try:
        for port, hydra_svc in targets:
            await ctx.log(f"Hydra: brute {hydra_svc} on port {port}", module="hydra")

            # For VNC/Redis — single user, password list only
            if hydra_svc in ("vnc", "redis"):
                cmd = [
                    "hydra", "-P", pass_file,
                    "-s", str(port),
                    "-t", "4",
                    "-f",          # stop after first found
                    "-q",          # quiet
                    target, hydra_svc,
                ]
            # For FTP — also try anonymous
            elif hydra_svc == "ftp":
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as af:
                    af.write("\n".join(_BLANK_ONLY + _USERNAMES))
                    anon_file = af.name
                cmd = [
                    "hydra", "-L", anon_file, "-P", pass_file,
                    "-s", str(port), "-t", "4", "-f", "-q",
                    target, hydra_svc,
                ]
            else:
                cmd = [
                    "hydra", "-L", users_file, "-P", pass_file,
                    "-s", str(port),
                    "-t", "4",     # 4 threads (polite)
                    "-f",          # stop after first found per host
                    "-q",          # quiet
                    target, hydra_svc,
                ]

            rc, stdout, stderr = run_cmd(cmd, timeout=120)

            if rc == -1:
                err = stderr or "hydra timed out or not found"
                await ctx.log(f"Hydra error on {hydra_svc}:{port}: {err}", level="error", module="hydra")
                result.errors.append(err)
                continue

            combined = stdout + stderr
            port_findings = _parse_hydra_output(combined, port, hydra_svc, target)

            if port_findings:
                await ctx.log(
                    f"Hydra CRITICAL: {len(port_findings)} credential(s) found on {hydra_svc}:{port}",
                    level="error",
                    module="hydra",
                )
            else:
                await ctx.log(
                    f"Hydra: no weak credentials on {hydra_svc}:{port}",
                    level="info",
                    module="hydra",
                )

            result.findings.extend(port_findings)

    finally:
        Path(users_file).unlink(missing_ok=True)
        Path(pass_file).unlink(missing_ok=True)

    return result


# ── Medusa fallback ────────────────────────────────────────────────────────────

_MEDUSA_SERVICES: dict[str, str] = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet",
    "smtp": "smtp", "imap": "imap", "pop3": "pop3",
    "mysql": "mysql", "mssql": "mssql", "vnc": "vnc",
}


def _parse_medusa_output(output: str, port: int, service: str, target: str) -> list[Finding]:
    """Medusa success: ACCOUNT FOUND: [ssh] Host: ... User: ... Password: ..."""
    findings: list[Finding] = []
    pattern = re.compile(
        r"ACCOUNT FOUND:.*?User:\s+(\S+).*?Password:\s+(.*)", re.IGNORECASE
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        login = m.group(1).strip()
        password = m.group(2).strip()
        display_pass = "(blank)" if password == "" else password
        findings.append(Finding(
            type="brute",
            title=f"Weak credential on {service}:{port} — {login}:{display_pass}",
            severity="critical",
            description=(
                f"Medusa found valid credentials for {service} on port {port}.\n"
                f"Login: {login}\nPassword: {display_pass}\nTarget: {target}"
            ),
            evidence=f"{login}:{display_pass} → {target}:{port}/{service}",
            port=port,
            protocol="tcp",
            service=service,
            remediation=(
                "Change credentials immediately. Enforce strong password policy. "
                "Disable default/shared accounts. Consider certificate-based auth."
            ),
        ))
    return findings


async def run_medusa_fallback(
    ctx: "ScanContext",
    target: str,
    port: int,
    service: str,
    users_file: str,
    pass_file: str,
) -> list[Finding]:
    medusa_svc = _MEDUSA_SERVICES.get(service)
    if not medusa_svc or not shutil.which("medusa"):
        return []

    await ctx.log(f"Medusa fallback: {medusa_svc}:{port}", module="hydra")
    cmd = [
        "medusa", "-h", target, "-U", users_file, "-P", pass_file,
        "-M", medusa_svc, "-n", str(port),
        "-t", "4", "-f",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=120)
    if rc == -1:
        return []
    return _parse_medusa_output(stdout + stderr, port, service, target)


# ── ncrack fallback for SSH/RDP ────────────────────────────────────────────────

async def run_ncrack_fallback(
    ctx: "ScanContext",
    target: str,
    port: int,
    service: str,
    users_file: str,
    pass_file: str,
) -> list[Finding]:
    if service not in ("ssh", "rdp") or not shutil.which("ncrack"):
        return []

    await ctx.log(f"ncrack fallback: {service}:{port}", module="hydra")
    cmd = [
        "ncrack", "-U", users_file, "-P", pass_file,
        f"{service}://{target}:{port}",
        "--connection-limit", "4",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=120)
    if rc == -1:
        return []

    findings: list[Finding] = []
    pattern = re.compile(r"Discovered credentials.*?(\S+)\s+(\S+)\s*$", re.IGNORECASE)
    for line in (stdout + stderr).splitlines():
        m = pattern.search(line)
        if not m:
            continue
        login, password = m.group(1), m.group(2)
        findings.append(Finding(
            type="brute",
            title=f"Weak credential on {service}:{port} — {login}:{password}",
            severity="critical",
            description=(
                f"ncrack found valid credentials for {service} on port {port}.\n"
                f"Login: {login}\nPassword: {password}\nTarget: {target}"
            ),
            evidence=f"{login}:{password} → {target}:{port}/{service}",
            port=port,
            protocol="tcp",
            service=service,
            remediation=(
                "Change credentials immediately. Use key-based authentication. "
                "Enforce account lockout and multi-factor authentication."
            ),
        ))
    return findings
