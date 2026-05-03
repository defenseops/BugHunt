"""
Metasploit exploit verification module.
Connects to msfrpcd, maps CVEs/services to MSF modules,
runs check() (NOT exploit) to verify exploitability.
Only runs on scan_type == 'full'.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from app.core.config import settings
from app.scanner.base import Finding, ScanResult

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── CVE → MSF module mapping ───────────────────────────────────────────────
# Format: CVE-ID → (msf_module_path, default_port, description)
CVE_MODULE_MAP: dict[str, tuple[str, int, str]] = {
    "CVE-2017-0144": ("exploit/windows/smb/ms17_010_eternalblue",  445,  "EternalBlue SMB RCE (WannaCry)"),
    "CVE-2017-0145": ("exploit/windows/smb/ms17_010_psexec",        445,  "EternalBlue variant SMB RCE"),
    "CVE-2019-0708": ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", 3389, "BlueKeep RDP RCE"),
    "CVE-2021-34527": ("exploit/windows/smb/printspooler_rce_nightmare", 445, "PrintNightmare"),
    "CVE-2021-44228": ("exploit/multi/http/log4shell_header_injection", 80,  "Log4Shell"),
    "CVE-2014-0160": ("auxiliary/scanner/ssl/openssl_heartbleed",    443,  "OpenSSL Heartbleed"),
    "CVE-2014-6271": ("exploit/multi/http/apache_mod_cgi_bash_env_exec", 80, "Shellshock"),
    "CVE-2017-5638": ("exploit/multi/http/struts2_content_type_ognl", 80,  "Apache Struts2 RCE"),
    "CVE-2018-11776": ("exploit/multi/http/struts2_namespace_ognl",  80,   "Apache Struts2 namespace RCE"),
    "CVE-2019-11510": ("auxiliary/scanner/http/pulse_secure_file_read", 443, "Pulse Secure VPN LFI"),
    "CVE-2020-1472":  ("auxiliary/admin/dcerpc/cve_2020_1472_zerologon", 445, "Zerologon"),
    "CVE-2021-26855": ("auxiliary/scanner/http/exchange_proxylogon",  443,  "ProxyLogon Exchange"),
    "CVE-2022-26134": ("exploit/multi/http/confluence_namespace_ognl_injection", 8090, "Confluence RCE"),
    "CVE-2023-23397": ("auxiliary/scanner/smtp/cve_2023_23397",       25,   "Outlook NTLM hash leak"),
}

# ── Service+version → MSF module mapping ──────────────────────────────────
# (service_name_pattern, version_pattern) → (module, description, severity)
SERVICE_MODULE_MAP: list[tuple[re.Pattern, re.Pattern | None, str, str, str]] = [
    # SSH
    (re.compile(r"ssh",   re.I), re.compile(r"OpenSSH [1-6]\.", re.I),
     "auxiliary/scanner/ssh/ssh_version",   "Outdated OpenSSH — check for known CVEs", "high"),
    # Samba / SMB
    (re.compile(r"smb|netbios|microsoft-ds", re.I), re.compile(r"Samba [23]\.", re.I),
     "exploit/linux/samba/is_known_pipename", "Samba RCE (CVE-2017-7494)", "critical"),
    # FTP
    (re.compile(r"ftp",  re.I), re.compile(r"vsftpd 2\.3\.4", re.I),
     "exploit/unix/ftp/vsftpd_234_backdoor", "vsFTPd 2.3.4 backdoor", "critical"),
    (re.compile(r"ftp",  re.I), re.compile(r"ProFTPD 1\.[23]\.", re.I),
     "exploit/unix/ftp/proftpd_133c_backdoor", "ProFTPd backdoor", "high"),
    # HTTP — shellshock via CGI
    (re.compile(r"http", re.I), None,
     "auxiliary/scanner/http/apache_optionsbleed", "Apache OptionsBleed info leak", "medium"),
    # MySQL
    (re.compile(r"mysql", re.I), re.compile(r"MySQL [45]\.", re.I),
     "auxiliary/scanner/mysql/mysql_authbypass_hashdump", "MySQL auth bypass", "high"),
    # RDP
    (re.compile(r"rdp|ms-wbt-server", re.I), None,
     "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",  "BlueKeep RDP check", "critical"),
    # VNC — no auth
    (re.compile(r"vnc",  re.I), None,
     "auxiliary/scanner/vnc/vnc_none_auth",           "VNC no-auth check", "critical"),
]


def _modules_for_findings(nmap_findings: list[Finding]) -> list[tuple[str, int, str, str]]:
    """
    Returns list of (msf_module, port, description, severity) to check.
    Deduplicates by module name.
    """
    to_check: dict[str, tuple[str, int, str, str]] = {}

    for f in nmap_findings:
        # CVE-based matching
        if f.cve_id and f.cve_id in CVE_MODULE_MAP:
            mod, default_port, desc = CVE_MODULE_MAP[f.cve_id]
            port = f.port or default_port
            to_check[mod] = (mod, port, desc, "critical")

        # Service+version matching
        if f.type == "port" and f.service:
            for svc_re, ver_re, mod, desc, sev in SERVICE_MODULE_MAP:
                if svc_re.search(f.service):
                    if ver_re is None or (f.version and ver_re.search(f.version)):
                        port = f.port or 0
                        if mod not in to_check:
                            to_check[mod] = (mod, port, desc, sev)

    return list(to_check.values())


def _connect_msf():
    """Connect to msfrpcd. Returns MsfRpcClient or None on failure."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        client = MsfRpcClient(
            settings.MSF_RPC_PASS,
            server=settings.MSF_RPC_HOST,
            port=settings.MSF_RPC_PORT,
            username=settings.MSF_RPC_USER,
            ssl=False,
        )
        return client
    except Exception:
        return None


def _run_module_check(client, module_path: str, target: str, port: int) -> str | None:
    """
    Load module, set RHOSTS/RPORT, run check().
    Returns 'vulnerable' | 'safe' | 'unknown' | None (error).
    """
    try:
        # Determine module type
        if module_path.startswith("exploit/"):
            mod = client.modules.use("exploit", module_path[len("exploit/"):])
        elif module_path.startswith("auxiliary/"):
            mod = client.modules.use("auxiliary", module_path[len("auxiliary/"):])
        else:
            return None

        mod["RHOSTS"] = target
        if port:
            mod["RPORT"] = port

        # check() returns a job result dict
        result = mod.check()
        if isinstance(result, dict):
            code = result.get("code", "")
            if code == "vulnerable":
                return "vulnerable"
            elif code == "safe":
                return "safe"
        return "unknown"

    except Exception:
        return None


async def run_msf(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    modules = _modules_for_findings(nmap_findings)
    if not modules:
        await ctx.log("MSF: no applicable modules for discovered services", module="msf")
        return result

    await ctx.log(f"MSF: connecting to msfrpcd at {settings.MSF_RPC_HOST}:{settings.MSF_RPC_PORT}", module="msf")
    client = _connect_msf()

    if client is None:
        msg = "MSF: cannot connect to msfrpcd — skipping exploit verification"
        await ctx.log(msg, level="warning", module="msf")
        result.errors.append(msg)
        return result

    await ctx.log(f"MSF: running check() on {len(modules)} module(s)", module="msf")

    for mod_path, port, description, severity in modules:
        await ctx.log(f"MSF: checking {mod_path} on port {port}", module="msf")

        check_result = _run_module_check(client, mod_path, target, port)

        if check_result == "vulnerable":
            await ctx.log(
                f"MSF CRITICAL: {mod_path} — target IS vulnerable!",
                level="error",
                module="msf",
            )
            result.findings.append(Finding(
                type="cve",
                title=f"EXPLOITABLE: {description}",
                severity=severity,
                description=(
                    f"Metasploit module '{mod_path}' confirmed the target is vulnerable.\n"
                    f"Description: {description}\n"
                    f"Port: {port}\nTarget: {target}"
                ),
                evidence=f"msf check() → code:vulnerable | module:{mod_path}",
                port=port,
                protocol="tcp",
                msf_module=mod_path,
                remediation=(
                    "Apply the vendor security patch immediately. "
                    "Isolate the system from the network until patched. "
                    "Review vendor advisory for workarounds."
                ),
            ))

        elif check_result == "safe":
            await ctx.log(f"MSF: {mod_path} — not vulnerable", module="msf")

        else:
            await ctx.log(f"MSF: {mod_path} — check inconclusive", level="warning", module="msf")

    vuln_count = len(result.findings)
    await ctx.log(
        f"MSF: completed — {vuln_count} exploitable service(s) confirmed",
        level="success" if vuln_count == 0 else "error",
        module="msf",
    )
    return result
