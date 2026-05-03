"""
SMB / Active Directory / Kerberos attack module — Phase 7.3.
Tools: CrackMapExec/NetExec, enum4linux-ng, smbmap, kerbrute,
       impacket GetNPUsers (AS-REP Roasting), impacket GetUserSPNs (Kerberoasting).
Only runs on scan_type in ('full', 'vuln').
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext

# Common AD/Windows ports
_SMB_PORTS = {445, 139}
_WINRM_PORTS = {5985, 5986}
_LDAP_PORTS = {389, 636}
_KERBEROS_PORTS = {88}

# Wordlist for kerbrute username enumeration
_AD_USERNAMES = [
    "administrator", "admin", "guest", "krbtgt", "user", "test",
    "service", "backup", "helpdesk", "sysadmin", "readonly",
    "operator", "auditor", "scanner",
]

# Common domain names to try when domain is unknown
_DEFAULT_DOMAIN = "WORKGROUP"


def _has_port(nmap_findings: list[Finding], ports: set[int]) -> bool:
    return any(f.port in ports for f in nmap_findings if f.port)


def _get_domain(nmap_findings: list[Finding]) -> str:
    """Try to extract domain name from nmap findings."""
    for f in nmap_findings:
        if f.evidence:
            m = re.search(r"domain[:\s]+([a-zA-Z0-9.\-]+)", f.evidence, re.IGNORECASE)
            if m:
                return m.group(1)
        if f.description:
            m = re.search(r"Domain:\s*([a-zA-Z0-9.\-]+)", f.description, re.IGNORECASE)
            if m:
                return m.group(1)
    return _DEFAULT_DOMAIN


# ── enum4linux-ng ──────────────────────────────────────────────────────────────

async def _run_enum4linux(
    ctx: "ScanContext",
    target: str,
) -> list[Finding]:
    if not shutil.which("enum4linux-ng"):
        await ctx.log("smb_ad: enum4linux-ng not found", level="warning", module="smb_ad")
        return []

    await ctx.log(f"smb_ad: running enum4linux-ng on {target}", module="smb_ad")
    rc, stdout, stderr = run_cmd(
        ["enum4linux-ng", "-A", "-oJ", "/tmp/enum4linux_out", target],
        timeout=120,
    )

    findings: list[Finding] = []
    combined = stdout + stderr

    # Parse JSON output if available
    try:
        out_path = Path("/tmp/enum4linux_out.json")
        if out_path.exists():
            data = json.loads(out_path.read_text())
            out_path.unlink(missing_ok=True)

            users = data.get("users", {})
            shares = data.get("shares", {})
            domain_info = data.get("domain_info", {})

            if users:
                user_list = list(users.keys())[:30]
                findings.append(Finding(
                    type="recon",
                    title=f"SMB user enumeration: {len(users)} accounts found",
                    severity="medium",
                    description=(
                        f"enum4linux-ng enumerated {len(users)} user accounts via SMB/RPC.\n"
                        f"Users: {', '.join(user_list)}"
                    ),
                    evidence=f"Users: {', '.join(user_list)}",
                    port=445,
                    protocol="tcp",
                    service="smb",
                    remediation=(
                        "Disable null sessions (RestrictAnonymous=2 in registry). "
                        "Restrict RPC access to authenticated users only."
                    ),
                    cvss_score=5.3,
                ))

            if shares:
                readable = [s for s, v in shares.items() if isinstance(v, dict) and v.get("access")]
                if readable:
                    findings.append(Finding(
                        type="vuln",
                        title=f"SMB readable shares: {', '.join(readable)}",
                        severity="medium",
                        description=(
                            f"Accessible SMB shares found on {target}:\n"
                            + "\n".join(f"  - {s}" for s in readable)
                        ),
                        evidence=f"Readable shares: {', '.join(readable)}",
                        port=445,
                        protocol="tcp",
                        service="smb",
                        remediation=(
                            "Restrict SMB share permissions. "
                            "Remove world-readable shares. "
                            "Audit share ACLs regularly."
                        ),
                        cvss_score=6.5,
                    ))
    except Exception:
        pass

    # Fallback: check raw output for null-session
    if "null session" in combined.lower() or "anonymous" in combined.lower():
        findings.append(Finding(
            type="vuln",
            title="SMB null session allowed",
            severity="high",
            description=(
                f"SMB null session (unauthenticated access) is allowed on {target}. "
                "This permits enumeration of users, shares, and policies."
            ),
            evidence="enum4linux-ng: null session confirmed",
            port=445,
            protocol="tcp",
            service="smb",
            remediation=(
                "Set RestrictAnonymous=2 and RestrictAnonymousSAM=1 in the registry. "
                "Block anonymous PIPE access."
            ),
            cvss_score=7.5,
        ))

    return findings


# ── smbmap ─────────────────────────────────────────────────────────────────────

async def _run_smbmap(
    ctx: "ScanContext",
    target: str,
) -> list[Finding]:
    if not shutil.which("smbmap"):
        return []

    await ctx.log(f"smb_ad: running smbmap on {target}", module="smb_ad")
    rc, stdout, stderr = run_cmd(
        ["smbmap", "-H", target, "--no-banner"],
        timeout=60,
    )

    findings: list[Finding] = []
    if rc == -1:
        return []

    # Look for READ or WRITE access
    for line in stdout.splitlines():
        m = re.search(r"\s+([A-Za-z0-9_$\-]+)\s+(READ|WRITE|READ, WRITE)", line, re.IGNORECASE)
        if not m:
            continue
        share = m.group(1)
        access = m.group(2).upper()
        severity = "high" if "WRITE" in access else "medium"
        cvss = 7.5 if "WRITE" in access else 5.3
        findings.append(Finding(
            type="vuln",
            title=f"SMB share {share!r} accessible ({access})",
            severity=severity,
            description=(
                f"smbmap found {access} access to share '{share}' on {target} "
                "without authentication."
            ),
            evidence=f"smbmap: {share} [{access}] on {target}",
            port=445,
            protocol="tcp",
            service="smb",
            remediation=(
                "Remove anonymous share access. "
                "Require authentication for all SMB shares. "
                "Audit and restrict share permissions."
            ),
            cvss_score=cvss,
        ))

    return findings


# ── kerbrute ──────────────────────────────────────────────────────────────────

async def _run_kerbrute(
    ctx: "ScanContext",
    target: str,
    domain: str,
) -> list[Finding]:
    if not shutil.which("kerbrute"):
        return []

    await ctx.log(f"smb_ad: kerbrute user enum on {target} (domain={domain})", module="smb_ad")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(_AD_USERNAMES))
        users_file = f.name

    try:
        rc, stdout, stderr = run_cmd(
            ["kerbrute", "userenum", "--dc", target, "--domain", domain, users_file],
            timeout=60,
        )
    finally:
        Path(users_file).unlink(missing_ok=True)

    if rc == -1:
        return []

    valid_users = re.findall(r"VALID USERNAME:\s+(\S+)", stdout + stderr, re.IGNORECASE)
    if not valid_users:
        return []

    return [Finding(
        type="recon",
        title=f"Kerberos valid users enumerated: {', '.join(valid_users)}",
        severity="medium",
        description=(
            f"kerbrute found {len(valid_users)} valid Kerberos user(s) on {target} "
            f"(domain: {domain}):\n" + "\n".join(f"  - {u}" for u in valid_users)
        ),
        evidence=f"Valid users: {', '.join(valid_users)}",
        port=88,
        protocol="tcp",
        service="kerberos",
        remediation=(
            "Enable Kerberos pre-authentication for all accounts. "
            "Monitor for Kerberos enumeration activity. "
            "Implement account lockout policy."
        ),
        cvss_score=5.3,
    )]


# ── AS-REP Roasting (impacket GetNPUsers) ─────────────────────────────────────

async def _run_asrep_roast(
    ctx: "ScanContext",
    target: str,
    domain: str,
    valid_users: list[str],
) -> list[Finding]:
    if not shutil.which("GetNPUsers.py") and not shutil.which("impacket-GetNPUsers"):
        return []

    tool = "GetNPUsers.py" if shutil.which("GetNPUsers.py") else "impacket-GetNPUsers"
    await ctx.log(f"smb_ad: AS-REP Roasting on {domain}\\* via {target}", module="smb_ad")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        users = valid_users if valid_users else _AD_USERNAMES
        f.write("\n".join(users))
        users_file = f.name

    try:
        rc, stdout, stderr = run_cmd(
            [tool, f"{domain}/", "-dc-ip", target, "-usersfile", users_file, "-no-pass", "-format", "hashcat"],
            timeout=60,
        )
    finally:
        Path(users_file).unlink(missing_ok=True)

    if rc == -1:
        return []

    hashes = re.findall(r"\$krb5asrep\$[^\s]+", stdout + stderr)
    if not hashes:
        return []

    return [Finding(
        type="vuln",
        title=f"AS-REP Roastable account(s) found: {len(hashes)} hash(es)",
        severity="high",
        description=(
            "One or more AD accounts have Kerberos pre-authentication disabled "
            "(UF_DONT_REQUIRE_PREAUTH). An attacker can request AS-REP tickets and "
            "crack them offline to recover plaintext passwords.\n\n"
            f"Hashes captured: {len(hashes)}\n"
            + "\n".join(h[:80] + "..." for h in hashes[:3])
        ),
        evidence="\n".join(hashes[:3]),
        port=88,
        protocol="tcp",
        service="kerberos",
        remediation=(
            "Enable Kerberos pre-authentication for all accounts. "
            "Use the AD attribute 'Do not require Kerberos preauthentication' = OFF. "
            "Enforce strong passwords on all service accounts."
        ),
        cvss_score=8.1,
        cve_id="CVE-2022-33679",
    )]


# ── Kerberoasting (impacket GetUserSPNs) ─────────────────────────────────────

async def _run_kerberoast(
    ctx: "ScanContext",
    target: str,
    domain: str,
) -> list[Finding]:
    if not shutil.which("GetUserSPNs.py") and not shutil.which("impacket-GetUserSPNs"):
        return []

    tool = "GetUserSPNs.py" if shutil.which("GetUserSPNs.py") else "impacket-GetUserSPNs"
    await ctx.log(f"smb_ad: Kerberoasting {domain} via {target} (null session)", module="smb_ad")

    rc, stdout, stderr = run_cmd(
        [tool, f"{domain}/", "-dc-ip", target, "-no-pass", "-request", "-outputfile", "/tmp/kerberoast_hashes.txt"],
        timeout=60,
    )

    if rc == -1:
        return []

    hashes: list[str] = []
    hash_file = Path("/tmp/kerberoast_hashes.txt")
    if hash_file.exists():
        hashes = [l for l in hash_file.read_text().splitlines() if l.startswith("$krb5tgs$")]
        hash_file.unlink(missing_ok=True)

    if not hashes:
        hashes = re.findall(r"\$krb5tgs\$[^\s]+", stdout + stderr)

    if not hashes:
        return []

    return [Finding(
        type="vuln",
        title=f"Kerberoastable service account(s): {len(hashes)} TGS hash(es)",
        severity="high",
        description=(
            "Service Principal Names (SPNs) were found with accessible TGS tickets. "
            "An attacker can crack these offline to obtain service account passwords.\n\n"
            f"TGS hashes captured: {len(hashes)}\n"
            + "\n".join(h[:80] + "..." for h in hashes[:3])
        ),
        evidence="\n".join(hashes[:3]),
        port=88,
        protocol="tcp",
        service="kerberos",
        remediation=(
            "Use Managed Service Accounts (gMSA) with auto-rotating passwords. "
            "Set service account passwords to 25+ random characters. "
            "Remove unnecessary SPNs. "
            "Monitor for unusual TGS requests."
        ),
        cvss_score=8.8,
    )]


# ── CrackMapExec / NetExec ────────────────────────────────────────────────────

async def _run_cme(
    ctx: "ScanContext",
    target: str,
    domain: str,
) -> list[Finding]:
    tool = shutil.which("netexec") or shutil.which("crackmapexec") or shutil.which("cme")
    if not tool:
        return []

    tool_name = Path(tool).name
    await ctx.log(f"smb_ad: {tool_name} SMB sweep on {target}", module="smb_ad")

    rc, stdout, stderr = run_cmd(
        [tool, "smb", target, "--shares", "--no-bruteforce"],
        timeout=60,
    )
    if rc == -1:
        return []

    findings: list[Finding] = []
    combined = stdout + stderr

    # Check for signing disabled
    if "signing:False" in combined or "SMB Signing: False" in combined.lower():
        findings.append(Finding(
            type="vuln",
            title="SMB Signing disabled — relay attack possible",
            severity="high",
            description=(
                f"SMB signing is disabled on {target}. "
                "This allows NTLM relay attacks where an attacker can intercept "
                "authentication and relay credentials to gain unauthorized access."
            ),
            evidence=f"{tool_name}: SMB signing disabled on {target}",
            port=445,
            protocol="tcp",
            service="smb",
            remediation=(
                "Enable SMB signing via Group Policy: "
                "'Microsoft network server: Digitally sign communications (always)'. "
                "Also enable 'Microsoft network client: Digitally sign communications'."
            ),
            cvss_score=8.1,
            cve_id="CVE-2017-0144",
        ))

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_smb_ad(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type not in ("full", "vuln"):
        return result

    has_smb = _has_port(nmap_findings, _SMB_PORTS)
    has_kerberos = _has_port(nmap_findings, _KERBEROS_PORTS)

    if not has_smb and not has_kerberos:
        await ctx.log("smb_ad: no SMB/Kerberos ports found, skipping", module="smb_ad")
        return result

    domain = _get_domain(nmap_findings)
    await ctx.log(
        f"smb_ad: SMB={has_smb}, Kerberos={has_kerberos}, domain={domain}",
        module="smb_ad",
    )

    # SMB enumeration
    if has_smb:
        enum_findings = await _run_enum4linux(ctx, target)
        result.findings.extend(enum_findings)

        smbmap_findings = await _run_smbmap(ctx, target)
        result.findings.extend(smbmap_findings)

        cme_findings = await _run_cme(ctx, target, domain)
        result.findings.extend(cme_findings)

    # Kerberos attacks
    valid_users: list[str] = []
    if has_kerberos:
        kerb_findings = await _run_kerbrute(ctx, target, domain)
        result.findings.extend(kerb_findings)

        # Extract validated usernames for AS-REP roast
        for f in kerb_findings:
            if f.evidence:
                for m in re.finditer(r"[\w\-\.]+@[\w\-\.]+|[\w\-\.]+\\[\w\-\.]+", f.evidence):
                    valid_users.append(m.group(0).split("\\")[-1].split("@")[0])

        asrep_findings = await _run_asrep_roast(ctx, target, domain, valid_users)
        result.findings.extend(asrep_findings)

        kerb_findings2 = await _run_kerberoast(ctx, target, domain)
        result.findings.extend(kerb_findings2)

    total = len(result.findings)
    await ctx.log(f"smb_ad: completed — {total} finding(s)", module="smb_ad")
    return result
