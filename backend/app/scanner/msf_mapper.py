"""
MSF Mapper — step 5.3.
Passive enrichment: annotates CVE and port findings with Metasploit module info
(module path, type, rank) without executing anything.

Sources (in priority order):
  1. Expanded static CVE → module table (instant, no msfrpcd needed)
  2. Live msfrpcd module search (search cve:<id> via RPC)
  3. Keyword search on service/version strings

Runs on all scan types. Feeds msf_module field into Rule Engine attack paths
and into the MSF exploit phase (full scans only).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Expanded CVE → MSF module table ──────────────────────────────────────────
# Format: CVE-ID → (module_path, module_type, rank, port, description)
# Ranks: excellent > great > good > normal > average > low > manual

_CVE_MODULE: dict[str, tuple[str, str, str, int, str]] = {
    # Windows / SMB
    "CVE-2017-0144": ("exploit/windows/smb/ms17_010_eternalblue",       "exploit",   "average",   445,  "EternalBlue SMB RCE (WannaCry / NotPetya)"),
    "CVE-2017-0145": ("exploit/windows/smb/ms17_010_psexec",             "exploit",   "great",     445,  "EternalBlue SMB psexec variant"),
    "CVE-2020-1472":  ("auxiliary/admin/dcerpc/cve_2020_1472_zerologon", "auxiliary", "normal",    445,  "Zerologon — AD DC privilege escalation"),
    "CVE-2021-34527": ("exploit/windows/smb/cve_2021_1675_printspooler", "exploit",   "excellent", 445,  "PrintNightmare — Windows Print Spooler RCE"),
    "CVE-2019-0708":  ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce","exploit",   "manual",   3389, "BlueKeep — pre-auth RDP RCE"),
    "CVE-2021-34473": ("exploit/windows/http/exchange_proxyshell_rce",   "exploit",   "excellent", 443,  "ProxyShell — Exchange RCE chain"),
    "CVE-2021-26855": ("auxiliary/scanner/http/exchange_proxylogon",     "auxiliary", "normal",    443,  "ProxyLogon — Exchange SSRF → RCE"),

    # Linux / Apache / Web
    "CVE-2014-6271":  ("exploit/multi/http/apache_mod_cgi_bash_env_exec","exploit",   "excellent",  80, "Shellshock — Apache mod_cgi bash env"),
    "CVE-2017-5638":  ("exploit/multi/http/struts2_content_type_ognl",  "exploit",   "excellent",  80, "Apache Struts2 Content-Type RCE"),
    "CVE-2018-11776": ("exploit/multi/http/struts2_namespace_ognl",     "exploit",   "excellent",  80, "Apache Struts2 namespace RCE"),
    "CVE-2021-41773": ("exploit/multi/http/apache_normalize_path_rce",  "exploit",   "excellent",  80, "Apache 2.4.49 path traversal RCE"),
    "CVE-2021-42013": ("exploit/multi/http/apache_normalize_path_rce",  "exploit",   "excellent",  80, "Apache 2.4.50 path traversal RCE"),
    "CVE-2021-44228": ("exploit/multi/http/log4shell_header_injection",  "exploit",   "excellent",  80, "Log4Shell — Log4j2 JNDI RCE"),
    "CVE-2022-22965": ("exploit/multi/http/spring_framework_rce_spring4shell","exploit","excellent",80, "Spring4Shell — Spring Framework RCE"),
    "CVE-2018-7600":  ("exploit/unix/webapp/drupal_drupalgeddon2",       "exploit",   "excellent",  80, "Drupalgeddon2 — Drupal RCE"),
    "CVE-2019-0192":  ("exploit/multi/misc/solr_velocity_template",      "exploit",   "excellent",8983, "Apache Solr Velocity template RCE"),
    "CVE-2020-14882": ("exploit/multi/http/oracle_weblogic_post_rce",    "exploit",   "excellent",7001, "Oracle WebLogic console RCE"),
    "CVE-2022-1388":  ("exploit/multi/http/f5_bigip_tmui_rce",           "exploit",   "excellent",443,  "F5 BIG-IP TMUI auth bypass + RCE"),
    "CVE-2022-26134": ("exploit/multi/http/confluence_namespace_ognl_injection","exploit","excellent",8090,"Confluence OGNL RCE"),

    # SSL / TLS
    "CVE-2014-0160":  ("auxiliary/scanner/ssl/openssl_heartbleed",       "auxiliary", "normal",   443,  "Heartbleed — OpenSSL memory read"),
    "CVE-2016-0703":  ("auxiliary/scanner/ssl/openssl_ccs",              "auxiliary", "normal",   443,  "OpenSSL CCS injection"),

    # VPN / Remote access
    "CVE-2018-13379": ("auxiliary/scanner/http/fortios_path_traversal",  "auxiliary", "normal",   443,  "Fortinet SSL-VPN path traversal (creds)"),
    "CVE-2019-11510": ("auxiliary/scanner/http/pulse_secure_file_read",  "auxiliary", "normal",   443,  "Pulse Secure VPN arbitrary file read"),
    "CVE-2023-23397": ("auxiliary/scanner/smtp/cve_2023_23397",          "auxiliary", "normal",    25,  "Outlook NTLM hash leak via calendar invite"),

    # Network services
    "CVE-2012-1823":  ("exploit/multi/http/php_cgi_arg_injection",       "exploit",   "excellent",  80, "PHP-CGI argument injection RCE"),
    "CVE-2010-4478":  ("exploit/multi/ssh/sshexec",                      "exploit",   "manual",     22, "Generic SSH post-auth shell"),
    "CVE-2017-7494":  ("exploit/linux/samba/is_known_pipename",          "exploit",   "excellent", 445, "SambaCry — Samba RCE (CVE-2017-7494)"),
    "CVE-2011-2523":  ("exploit/unix/ftp/vsftpd_234_backdoor",           "exploit",   "excellent",  21, "vsFTPd 2.3.4 backdoor"),
    "CVE-2015-3306":  ("exploit/unix/ftp/proftpd_modcopy_exec",          "exploit",   "excellent",  21, "ProFTPd mod_copy RCE"),
    "CVE-2020-7247":  ("exploit/linux/smtp/opensmtpd_mail_from_rce",     "exploit",   "excellent",  25, "OpenSMTPD mail from RCE"),
    "CVE-2021-21985": ("exploit/multi/http/vmware_vcenter_virtual_san",  "exploit",   "excellent", 443, "VMware vCenter Virtual SAN Health Check RCE"),
}


# ── Service+version → MSF module (for port findings without CVE) ─────────────
# (service_re, version_re_or_None) → (module_path, module_type, rank, description)

_SERVICE_MODULE: list[tuple[re.Pattern, re.Pattern | None, str, str, str, str]] = [
    # vsFTPd 2.3.4 backdoor
    (re.compile(r"ftp",   re.I), re.compile(r"vsftpd\s*2\.3\.4",   re.I),
     "exploit/unix/ftp/vsftpd_234_backdoor",   "exploit", "excellent", "vsFTPd 2.3.4 backdoor"),
    # ProFTPd 1.3.3c backdoor
    (re.compile(r"ftp",   re.I), re.compile(r"ProFTPD\s*1\.3\.[0-3]", re.I),
     "exploit/unix/ftp/proftpd_133c_backdoor", "exploit", "excellent", "ProFTPd 1.3.x backdoor"),
    # Samba 3.x / 4.x
    (re.compile(r"smb|samba|microsoft-ds", re.I), re.compile(r"Samba\s*[34]\.", re.I),
     "exploit/linux/samba/is_known_pipename",   "exploit", "excellent", "SambaCry — Samba named pipe RCE"),
    # OpenSSH old versions
    (re.compile(r"ssh",   re.I), re.compile(r"OpenSSH\s*[1-5]\.", re.I),
     "auxiliary/scanner/ssh/ssh_enumusers",     "auxiliary", "normal",  "OpenSSH username enumeration (old version)"),
    # RDP — BlueKeep scanner
    (re.compile(r"rdp|ms-wbt-server", re.I), None,
     "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "auxiliary", "normal", "BlueKeep RDP scanner"),
    # VNC no-auth
    (re.compile(r"vnc",   re.I), None,
     "auxiliary/scanner/vnc/vnc_none_auth",     "auxiliary", "normal",  "VNC no-authentication check"),
    # Telnet
    (re.compile(r"telnet", re.I), None,
     "auxiliary/scanner/telnet/telnet_version", "auxiliary", "normal",  "Telnet version scanner"),
    # MySQL
    (re.compile(r"mysql", re.I), re.compile(r"MySQL\s*[45]\.", re.I),
     "auxiliary/scanner/mysql/mysql_authbypass_hashdump", "auxiliary", "normal", "MySQL auth bypass hash dump"),
    # Redis unauthenticated
    (re.compile(r"redis", re.I), None,
     "auxiliary/scanner/redis/redis_server",    "auxiliary", "normal",  "Redis unauthenticated access check"),
    # MongoDB unauthenticated
    (re.compile(r"mongodb", re.I), None,
     "auxiliary/scanner/mongodb/mongodb_login", "auxiliary", "normal",  "MongoDB unauthenticated access check"),
    # Tomcat manager
    (re.compile(r"tomcat|ajp", re.I), None,
     "auxiliary/scanner/http/tomcat_mgr_login", "auxiliary", "normal",  "Tomcat manager brute-force"),
    # Jenkins script console
    (re.compile(r"jenkins|http", re.I), re.compile(r"Jetty|Jenkins", re.I),
     "exploit/multi/http/jenkins_script_console","exploit", "excellent", "Jenkins unauthenticated script console RCE"),
    # WordPress
    (re.compile(r"http", re.I), re.compile(r"WordPress", re.I),
     "auxiliary/scanner/http/wordpress_login_enum", "auxiliary", "normal", "WordPress login enumeration"),
    # SMB — EternalBlue scanner
    (re.compile(r"smb|netbios|microsoft-ds", re.I), None,
     "auxiliary/scanner/smb/smb_ms17_010",      "auxiliary", "normal",  "EternalBlue SMB scanner (MS17-010)"),
]

_RANK_ORDER = {"excellent": 0, "great": 1, "good": 2, "normal": 3, "average": 4, "low": 5, "manual": 6}


# ── Live msfrpcd search ───────────────────────────────────────────────────────

def _live_msf_search(cve_id: str) -> tuple[str, str, str] | None:
    """
    Query msfrpcd for modules matching a CVE ID.
    Returns (module_path, module_type, rank) or None.
    """
    try:
        from app.core.config import settings
        from pymetasploit3.msfrpc import MsfRpcClient
        client = MsfRpcClient(
            settings.MSF_RPC_PASS,
            server=settings.MSF_RPC_HOST,
            port=settings.MSF_RPC_PORT,
            username=settings.MSF_RPC_USER,
            ssl=False,
        )
        results = client.modules.search(f"cve:{cve_id.replace('CVE-', '').replace('cve-', '')}")
        if not results:
            return None
        # Pick best-ranked exploit first, then auxiliary
        exploits = [r for r in results if r.get("type") == "exploit"]
        auxs     = [r for r in results if r.get("type") == "auxiliary"]
        candidates = sorted(exploits, key=lambda r: _RANK_ORDER.get(r.get("rank", "low"), 5))
        candidates += sorted(auxs,    key=lambda r: _RANK_ORDER.get(r.get("rank", "low"), 5))
        if candidates:
            best = candidates[0]
            return best["fullname"], best["type"], best.get("rank", "normal")
    except Exception:
        pass
    return None


# ── Annotator logic ───────────────────────────────────────────────────────────

def _annotate_finding(f: Finding, mod_path: str, mod_type: str, rank: str, desc: str) -> None:
    if not f.msf_module:
        f.msf_module = mod_path
    if not f.description:
        f.description = desc
    # Attach MSF info to evidence
    msf_line = f"MSF: {mod_path} [{mod_type}/{rank}]"
    f.evidence = (f.evidence + "\n" + msf_line) if f.evidence else msf_line


def _enrich_from_cve(findings: list[Finding], use_live: bool) -> tuple[int, int]:
    """Annotate CVE findings with MSF module. Returns (static_hits, live_hits)."""
    static_hits = 0
    live_hits = 0

    for f in findings:
        if not f.cve_id or f.msf_module:
            continue

        cve_upper = f.cve_id.upper()

        # Static table first
        if cve_upper in _CVE_MODULE:
            mod, mtype, rank, _, desc = _CVE_MODULE[cve_upper]
            _annotate_finding(f, mod, mtype, rank, desc)
            static_hits += 1
            continue

        # Live msfrpcd search
        if use_live:
            live_result = _live_msf_search(cve_upper)
            if live_result:
                mod, mtype, rank = live_result
                _annotate_finding(f, mod, mtype, rank, f"MSF live search for {cve_upper}")
                live_hits += 1

    return static_hits, live_hits


def _enrich_from_service(findings: list[Finding]) -> int:
    """Annotate port findings without CVE using service+version table."""
    hits = 0
    for f in findings:
        if f.type != "port" or not f.service or f.msf_module:
            continue
        for svc_re, ver_re, mod, mtype, rank, desc in _SERVICE_MODULE:
            if svc_re.search(f.service or ""):
                if ver_re is None or (f.version and ver_re.search(f.version)):
                    _annotate_finding(f, mod, mtype, rank, desc)
                    hits += 1
                    break
    return hits


# ── Summary finding ───────────────────────────────────────────────────────────

def _make_summary(findings: list[Finding]) -> Finding | None:
    msf_annotated = [f for f in findings if f.msf_module]
    if not msf_annotated:
        return None

    exploits = [f for f in msf_annotated if "exploit/" in (f.msf_module or "")]
    auxs     = [f for f in msf_annotated if "auxiliary/" in (f.msf_module or "")]

    lines = []
    for f in sorted(msf_annotated, key=lambda x: x.cvss_score or 0, reverse=True)[:15]:
        lines.append(f"  [{f.severity or 'info'.upper()}] {f.cve_id or f.title[:60]} → {f.msf_module}")

    return Finding(
        type="msf_mapping",
        title=f"Metasploit: {len(msf_annotated)} finding(s) mapped to MSF modules",
        severity="high" if exploits else "medium",
        description=(
            f"Metasploit module mapping summary:\n"
            f"  Exploits:   {len(exploits)}\n"
            f"  Auxiliaries: {len(auxs)}\n\n"
            "Mapped findings:\n" + "\n".join(lines)
        ),
        remediation=(
            "Patch all services with mapped MSF modules. "
            "Exploits with 'excellent' rank are most likely to succeed. "
            "Run full scan to execute exploit verification via Metasploit check()."
        ),
        evidence=f"total_mapped={len(msf_annotated)} exploits={len(exploits)} aux={len(auxs)}",
    )


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_msf_mapper(
    ctx: "ScanContext",
    all_findings: list[Finding],
) -> ScanResult:
    """
    Passive MSF module annotation.
    Enriches findings in-place with msf_module field.
    Also creates a summary finding listing all mapped modules.
    """
    result = ScanResult()

    await ctx.log(
        f"MSF Mapper: annotating {len(all_findings)} finding(s) with Metasploit modules",
        module="msf_mapper",
    )

    # Try to connect to msfrpcd for live search (best-effort)
    use_live = False
    try:
        from app.core.config import settings
        from pymetasploit3.msfrpc import MsfRpcClient
        client = MsfRpcClient(
            settings.MSF_RPC_PASS,
            server=settings.MSF_RPC_HOST,
            port=settings.MSF_RPC_PORT,
            username=settings.MSF_RPC_USER,
            ssl=False,
        )
        use_live = True
        await ctx.log("MSF Mapper: connected to msfrpcd — live search enabled", module="msf_mapper")
    except Exception:
        await ctx.log(
            "MSF Mapper: msfrpcd unavailable — using static table only",
            level="info",
            module="msf_mapper",
        )

    # Enrich CVE findings
    static_hits, live_hits = _enrich_from_cve(all_findings, use_live)

    # Enrich port findings by service/version
    service_hits = _enrich_from_service(all_findings)

    total_mapped = sum(1 for f in all_findings if f.msf_module)

    await ctx.log(
        f"MSF Mapper: {total_mapped} finding(s) annotated "
        f"(static={static_hits} live={live_hits} service={service_hits})",
        level="warning" if total_mapped else "info",
        module="msf_mapper",
    )

    # Add summary finding
    summary = _make_summary(all_findings)
    if summary:
        result.findings.append(summary)

    return result
