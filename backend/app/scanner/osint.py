"""
OSINT module.
Sources: Shodan API, Censys API, theHarvester (CLI), waybackurls (CLI).
All sources are optional — missing API keys or tools produce warnings, not errors.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _strip_domain(target: str) -> str:
    t = re.sub(r"^https?://", "", target)
    return t.split("/")[0].split(":")[0]


# ── Shodan ────────────────────────────────────────────────────────────────────

def _run_shodan(target: str, api_key: str) -> tuple[list[Finding], list[str]]:
    """Query Shodan host info via the shodan CLI."""
    findings: list[Finding] = []
    errors: list[str] = []

    rc, stdout, stderr = run_cmd(
        ["shodan", "host", target, "--format", "json"],
        timeout=30,
        env={"SHODAN_API_KEY": api_key},
    )
    if rc != 0:
        errors.append(f"shodan: {stderr.strip() or 'no data'}")
        return findings, errors

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        errors.append("shodan: invalid JSON response")
        return findings, errors

    ip = data.get("ip_str", target)
    country = data.get("country_name", "")
    org = data.get("org", "")
    isp = data.get("isp", "")
    hostnames = data.get("hostnames", [])
    vulns = data.get("vulns", {})
    ports_data = data.get("data", [])

    # General host info
    findings.append(Finding(
        type="osint",
        title=f"Shodan: host info for {ip}",
        severity="info",
        description=(
            f"IP: {ip}\n"
            f"Organisation: {org}\n"
            f"ISP: {isp}\n"
            f"Country: {country}\n"
            f"Hostnames: {', '.join(hostnames) or 'none'}"
        ),
        evidence=json.dumps({"org": org, "isp": isp, "country": country, "hostnames": hostnames}),
    ))

    # Open ports seen by Shodan
    for svc in ports_data:
        port = svc.get("port")
        transport = svc.get("transport", "tcp")
        product = svc.get("product", "")
        version = svc.get("version", "")
        banner = (svc.get("data", "") or "")[:300]

        findings.append(Finding(
            type="osint",
            title=f"Shodan: port {port}/{transport} open ({product} {version})".strip(),
            severity="info",
            description=f"Shodan has indexed port {port}/{transport} on {ip}.\nBanner: {banner}",
            port=port,
            protocol=transport,
            service=product or None,
            version=version or None,
            evidence=banner,
        ))

    # Known CVEs from Shodan
    for cve_id, cve_info in vulns.items():
        cvss = float(cve_info.get("cvss", 0) or 0)
        summary = cve_info.get("summary", "")
        severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"

        findings.append(Finding(
            type="cve",
            title=f"Shodan CVE: {cve_id} (CVSS {cvss})",
            severity=severity,
            description=f"Shodan reports {cve_id} affecting {ip}.\n{summary}",
            cve_id=cve_id,
            cvss_score=cvss or None,
            remediation="Apply vendor patch for this CVE. Check Shodan for affected service version.",
            evidence=json.dumps(cve_info)[:500],
        ))

    return findings, errors


# ── Censys ────────────────────────────────────────────────────────────────────

def _run_censys(target: str, api_id: str, api_secret: str) -> tuple[list[Finding], list[str]]:
    """Query Censys hosts API via Python SDK (censys library)."""
    findings: list[Finding] = []
    errors: list[str] = []

    try:
        from censys.search import CensysHosts  # type: ignore
    except ImportError:
        errors.append("censys: library not installed")
        return findings, errors

    try:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
        host = h.view(target)
    except Exception as exc:
        errors.append(f"censys: {exc}")
        return findings, errors

    ip = host.get("ip", target)
    services = host.get("services", [])
    labels = host.get("labels", [])

    for svc in services:
        port = svc.get("port")
        transport = svc.get("transport_protocol", "TCP").lower()
        service_name = svc.get("service_name", "")
        product = svc.get("software", [{}])[0].get("product", "") if svc.get("software") else ""
        banner = (svc.get("banner", "") or "")[:200]
        cert = svc.get("tls", {}).get("certificate", {}).get("parsed", {})

        severity = "info"
        title = f"Censys: {ip}:{port}/{transport} ({service_name})"

        # Flag unexpected/risky services
        risky_services = {"TELNET", "FTP", "NETBIOS", "SMB", "MSSQL", "MYSQL", "REDIS", "MONGODB"}
        if service_name.upper() in risky_services:
            severity = "medium"

        findings.append(Finding(
            type="osint",
            title=title,
            severity=severity,
            description=(
                f"Censys indexed {ip}:{port}/{transport}\n"
                f"Service: {service_name}\n"
                f"Product: {product}\n"
                f"Banner: {banner}"
            ),
            port=port,
            protocol=transport,
            service=service_name or None,
            version=product or None,
            evidence=banner,
        ))

        # TLS cert info
        if cert:
            subject = cert.get("subject", {})
            cn = subject.get("common_name", [""])[0] if isinstance(subject.get("common_name"), list) else subject.get("common_name", "")
            not_after = cert.get("validity", {}).get("end", "")
            findings.append(Finding(
                type="osint",
                title=f"Censys: TLS cert on {ip}:{port} — CN={cn}",
                severity="info",
                description=f"Certificate CN: {cn}\nValid until: {not_after}",
                port=port,
                evidence=f"CN={cn}, expires={not_after}",
            ))

    if labels:
        findings.append(Finding(
            type="osint",
            title=f"Censys: host labels for {ip}",
            severity="info",
            description=f"Censys labels: {', '.join(labels)}",
            evidence=str(labels),
        ))

    return findings, errors


# ── theHarvester ──────────────────────────────────────────────────────────────

def _run_theharvester(domain: str, timeout: int = 120) -> tuple[list[Finding], list[str]]:
    """Run theHarvester for emails, subdomains, IPs."""
    findings: list[Finding] = []
    errors: list[str] = []

    rc, stdout, stderr = run_cmd(
        [
            "theHarvester",
            "-d", domain,
            "-b", "bing,google,dnsdumpster,crtsh,hackertarget",
            "-l", "200",
            "-f", "/tmp/theharvester_out",
        ],
        timeout=timeout,
    )
    if rc == -1:
        errors.append(stderr or "theHarvester timed out")
        return findings, errors

    # Parse plain text output
    emails: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []

    section = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("[*]") or line.startswith("---"):
            continue
        if "Emails found" in line or "emails found" in line:
            section = "email"
            continue
        if "Hosts found" in line or "hosts found" in line or "IPs found" in line:
            section = "host"
            continue
        if "IPs" in line:
            section = "ip"
            continue

        if section == "email" and "@" in line:
            emails.append(line)
        elif section in ("host", "ip"):
            if re.match(r"[a-z0-9]", line, re.I):
                hosts.append(line)

    if emails:
        findings.append(Finding(
            type="osint",
            title=f"theHarvester: {len(emails)} email(s) found for {domain}",
            severity="low",
            description="Email addresses discovered via OSINT. May be used for phishing/spear-phishing.",
            evidence="\n".join(emails[:50]),
            remediation="Review email exposure. Train staff on phishing awareness.",
        ))

    for host in hosts[:100]:
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", host)
        hostname = re.sub(r":\d+", "", host.split(":")[0])
        findings.append(Finding(
            type="osint",
            title=f"theHarvester: host {hostname}",
            severity="info",
            description=f"OSINT discovered host: {host}",
            evidence=host,
        ))

    return findings, errors


# ── waybackurls ───────────────────────────────────────────────────────────────

_WAYBACK_INTERESTING_RE = re.compile(
    r"\.(php|asp|aspx|jsp|cgi|pl|py|sh|env|bak|sql|zip|tar|gz|config|xml|json|yaml|yml)\b"
    r"|(/admin|/api/|/login|/backup|/upload|/debug|/test|/dev|/internal)",
    re.I,
)

_WAYBACK_PARAM_RE = re.compile(r"[?&](id|user|name|file|path|url|redirect|token|key|pass|debug)=", re.I)


def _run_waybackurls(domain: str, timeout: int = 90) -> tuple[list[Finding], list[str]]:
    """Fetch archived URLs from Wayback Machine / Common Crawl."""
    findings: list[Finding] = []
    errors: list[str] = []

    rc, stdout, stderr = run_cmd(
        ["waybackurls", domain],
        timeout=timeout,
    )
    if rc == -1:
        errors.append(stderr or "waybackurls timed out")
        return findings, errors

    all_urls = [u.strip() for u in stdout.splitlines() if u.strip()]
    interesting = [u for u in all_urls if _WAYBACK_INTERESTING_RE.search(u)]
    param_urls  = [u for u in all_urls if _WAYBACK_PARAM_RE.search(u)]

    if all_urls:
        findings.append(Finding(
            type="osint",
            title=f"Wayback Machine: {len(all_urls)} archived URLs for {domain}",
            severity="info",
            description=(
                f"Wayback Machine/Common Crawl has {len(all_urls)} archived URLs.\n"
                f"Interesting paths: {len(interesting)}, Parameter URLs: {len(param_urls)}"
            ),
            evidence=f"Total: {len(all_urls)}, Interesting: {len(interesting)}",
        ))

    for url in interesting[:50]:
        severity = "low"
        if re.search(r"\.(bak|sql|zip|tar|gz|env)\b", url, re.I):
            severity = "medium"
        if re.search(r"(/admin|/backup|/debug|/internal)", url, re.I):
            severity = "medium"

        findings.append(Finding(
            type="osint",
            title=f"Wayback: interesting URL — {url[:100]}",
            severity=severity,
            description=f"Archived URL with sensitive path/extension: {url}",
            evidence=url,
            remediation="Verify this URL is no longer accessible. Remove or restrict sensitive files.",
        ))

    # Parameter injection candidates
    if param_urls:
        findings.append(Finding(
            type="osint",
            title=f"Wayback: {len(param_urls)} parameter URL(s) — potential injection points",
            severity="low",
            description=(
                f"URLs with query parameters (id, user, file, url, redirect…) "
                f"may be injection candidates.\nSample: {param_urls[0][:200]}"
            ),
            evidence="\n".join(param_urls[:20]),
            remediation="Test parameter URLs for SQLi, XSS, open redirect, and path traversal.",
        ))

    return findings, errors


# ── main entry point ──────────────────────────────────────────────────────────

async def run_osint(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
) -> ScanResult:
    """
    OSINT phase: Shodan, Censys, theHarvester, waybackurls.
    Runs on all scan types. API sources skipped if keys not configured.
    """
    from app.core.config import settings

    result = ScanResult()
    domain = _strip_domain(target)
    is_ip  = _is_ip(domain)

    await ctx.log(f"OSINT starting for {domain}", module="osint")

    # ── Shodan ────────────────────────────────────────────────────────────────
    if settings.SHODAN_API_KEY:
        shodan_target = domain  # works for both IP and domain
        await ctx.log(f"Querying Shodan for {shodan_target}...", module="osint")
        sh_findings, errs = _run_shodan(shodan_target, settings.SHODAN_API_KEY)
        for e in errs:
            await ctx.log(e, level="warning", module="shodan")
        result.findings.extend(sh_findings)
        cve_count = sum(1 for f in sh_findings if f.type == "cve")
        await ctx.log(
            f"Shodan: {len(sh_findings)} findings ({cve_count} CVEs)",
            level="warning" if cve_count else "success",
            module="shodan",
        )
    else:
        await ctx.log("Shodan skipped (SHODAN_API_KEY not set)", level="info", module="shodan")

    # ── Censys ────────────────────────────────────────────────────────────────
    if settings.CENSYS_API_ID and settings.CENSYS_API_SECRET and is_ip:
        await ctx.log(f"Querying Censys for {domain}...", module="osint")
        ce_findings, errs = _run_censys(domain, settings.CENSYS_API_ID, settings.CENSYS_API_SECRET)
        for e in errs:
            await ctx.log(e, level="warning", module="censys")
        result.findings.extend(ce_findings)
        await ctx.log(f"Censys: {len(ce_findings)} findings", level="success", module="censys")
    elif not is_ip:
        await ctx.log("Censys skipped (requires IP address target)", level="info", module="censys")
    else:
        await ctx.log("Censys skipped (API keys not set)", level="info", module="censys")

    # ── theHarvester (domain targets only) ───────────────────────────────────
    if not is_ip:
        await ctx.log(f"Running theHarvester for {domain}...", module="osint")
        th_findings, errs = _run_theharvester(domain)
        for e in errs:
            await ctx.log(e, level="warning", module="theHarvester")
        result.findings.extend(th_findings)
        await ctx.log(
            f"theHarvester: {len(th_findings)} findings",
            level="success" if th_findings else "info",
            module="theHarvester",
        )
    else:
        await ctx.log("theHarvester skipped (IP target)", level="info", module="theHarvester")

    # ── waybackurls (domain targets, web/full only) ───────────────────────────
    if not is_ip and scan_type in ("web", "full"):
        await ctx.log(f"Running waybackurls for {domain}...", module="osint")
        wb_findings, errs = _run_waybackurls(domain)
        for e in errs:
            await ctx.log(e, level="warning", module="waybackurls")
        result.findings.extend(wb_findings)
        await ctx.log(
            f"waybackurls: {len(wb_findings)} findings",
            level="success" if wb_findings else "info",
            module="waybackurls",
        )
    else:
        await ctx.log("waybackurls skipped (IP or non-web scan)", level="info", module="waybackurls")

    await ctx.log(
        f"OSINT complete: {len(result.findings)} total findings",
        level="success",
        module="osint",
    )
    return result
