"""
CVE Mapper — step 5.2.
For each open service found by nmap, queries:
  1. NVD API v2 (authoritative CVSS 3.1 scores, CWE, descriptions)
  2. searchsploit / ExploitDB CLI (known PoCs and exploits)
Returns Finding objects with type="cve".

Rate limits:
  - Without NVD_API_KEY: 5 req / 30 s  → sleep 6 s between calls
  - With NVD_API_KEY:   50 req / 30 s  → sleep 0.6 s between calls
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

import httpx

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── NVD API v2 ────────────────────────────────────────────────────────────────

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TOP_N = 5          # max CVEs to keep per service
_TIMEOUT = 20       # httpx request timeout


def _nvd_headers(api_key: str) -> dict[str, str]:
    h: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        h["apiKey"] = api_key
    return h


def _parse_nvd_response(data: dict, source_label: str) -> list[Finding]:
    findings: list[Finding] = []
    vulns = data.get("vulnerabilities", [])

    for item in vulns:
        cve_node = item.get("cve", {})
        cve_id = cve_node.get("id", "")
        descriptions = cve_node.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # CVSS v3.1 preferred, fallback to v3.0 then v2
        metrics = cve_node.get("metrics", {})
        cvss_score: float | None = None
        cvss_vector: str | None = None
        severity: str | None = None

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data_block = entries[0].get("cvssData", {})
                cvss_score = float(data_block.get("baseScore", 0) or 0)
                cvss_vector = data_block.get("vectorString")
                severity_raw = data_block.get("baseSeverity", "")
                severity = severity_raw.lower() if severity_raw else None
                break

        if not cvss_score:
            continue  # skip CVEs with no CVSS data

        # Normalise severity
        if not severity:
            severity = (
                "critical" if cvss_score >= 9.0
                else "high" if cvss_score >= 7.0
                else "medium" if cvss_score >= 4.0
                else "low"
            )

        # CWE
        weaknesses = cve_node.get("weaknesses", [])
        cwes = [
            d["value"]
            for w in weaknesses
            for d in w.get("description", [])
            if d.get("lang") == "en"
        ]
        cwe_str = ", ".join(cwes[:3]) if cwes else ""

        # References
        refs = cve_node.get("references", [])
        ref_urls = [r["url"] for r in refs[:3] if r.get("url")]
        ref_str = "\n".join(ref_urls) if ref_urls else ""

        findings.append(Finding(
            type="cve",
            title=f"{cve_id} — {source_label} (CVSS {cvss_score})",
            severity=severity,
            description=(
                f"{description}\n\n"
                + (f"CWE: {cwe_str}\n" if cwe_str else "")
                + (f"References:\n{ref_str}" if ref_str else "")
            ),
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            remediation=f"Check vendor advisory for {cve_id}. Apply patch or workaround.",
            evidence=f"Source: NVD API | Product: {source_label}",
        ))

    # Return top N by CVSS score
    findings.sort(key=lambda f: f.cvss_score or 0, reverse=True)
    return findings[:_TOP_N]


async def _query_nvd_keyword(
    keyword: str,
    api_key: str,
    delay: float,
) -> list[Finding]:
    """Query NVD by keyword (e.g. 'apache httpd 2.4.49')."""
    await asyncio.sleep(delay)
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
        "noRejected": "",
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _NVD_BASE,
                params=params,
                headers=_nvd_headers(api_key),
            )
            if resp.status_code != 200:
                return []
            return _parse_nvd_response(resp.json(), keyword)
    except Exception:
        return []


async def _query_nvd_cpe(
    cpe: str,
    api_key: str,
    delay: float,
) -> list[Finding]:
    """Query NVD by CPE string (more precise than keyword)."""
    await asyncio.sleep(delay)
    params = {
        "cpeName": cpe,
        "resultsPerPage": 20,
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _NVD_BASE,
                params=params,
                headers=_nvd_headers(api_key),
            )
            if resp.status_code != 200:
                return []
            return _parse_nvd_response(resp.json(), cpe)
    except Exception:
        return []


# ── searchsploit (ExploitDB) ──────────────────────────────────────────────────

def _run_searchsploit(product: str, version: str) -> list[Finding]:
    query = f"{product} {version}".strip()
    rc, stdout, stderr = run_cmd(
        ["searchsploit", "--json", query],
        timeout=30,
    )
    if rc != 0 or not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
    if not exploits:
        return []

    titles = [e.get("Title", "") for e in exploits[:10]]
    edb_ids = [str(e.get("EDB-ID", "")) for e in exploits[:10]]
    paths = [e.get("Path", "") for e in exploits[:10]]

    lines = [
        f"[EDB-{edb}] {title}" + (f" — {path}" if path else "")
        for edb, title, path in zip(edb_ids, titles, paths)
    ]

    # severity based on count and type
    has_rce = any(re.search(r"remote|rce|exec|shell|overflow|inject", t, re.I) for t in titles)
    severity = "high" if has_rce else "medium"

    return [Finding(
        type="exploit",
        title=f"ExploitDB: {len(exploits)} exploit(s) for {query}",
        severity=severity,
        description=(
            f"searchsploit found {len(exploits)} public exploit(s) for '{query}':\n\n"
            + "\n".join(lines)
        ),
        service=product or None,
        version=version or None,
        remediation=f"Public exploits exist for {query}. Patch or upgrade immediately.",
        evidence="\n".join(lines),
    )]


# ── Service → CPE / keyword mapping ──────────────────────────────────────────

_SERVICE_TO_CPE_PREFIX: dict[str, str] = {
    "http":        "cpe:2.3:a:apache:http_server",
    "apache":      "cpe:2.3:a:apache:http_server",
    "nginx":       "cpe:2.3:a:nginx:nginx",
    "iis":         "cpe:2.3:a:microsoft:internet_information_services",
    "tomcat":      "cpe:2.3:a:apache:tomcat",
    "openssh":     "cpe:2.3:a:openbsd:openssh",
    "ssh":         "cpe:2.3:a:openbsd:openssh",
    "vsftpd":      "cpe:2.3:a:vsftpd_project:vsftpd",
    "proftpd":     "cpe:2.3:a:proftpd:proftpd",
    "ftp":         "cpe:2.3:a:vsftpd_project:vsftpd",
    "samba":       "cpe:2.3:a:samba:samba",
    "smb":         "cpe:2.3:a:samba:samba",
    "mysql":       "cpe:2.3:a:mysql:mysql",
    "postgresql":  "cpe:2.3:a:postgresql:postgresql",
    "mssql":       "cpe:2.3:a:microsoft:sql_server",
    "oracle":      "cpe:2.3:a:oracle:database_server",
    "mongodb":     "cpe:2.3:a:mongodb:mongodb",
    "redis":       "cpe:2.3:a:redis:redis",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "php":         "cpe:2.3:a:php:php",
    "wordpress":   "cpe:2.3:a:wordpress:wordpress",
    "drupal":      "cpe:2.3:a:drupal:drupal",
    "joomla":      "cpe:2.3:a:joomla:joomla",
    "exim":        "cpe:2.3:a:exim:exim",
    "postfix":     "cpe:2.3:a:postfix:postfix",
    "sendmail":    "cpe:2.3:a:sendmail:sendmail",
    "dovecot":     "cpe:2.3:a:dovecot:dovecot",
    "bind":        "cpe:2.3:a:isc:bind",
    "jenkins":     "cpe:2.3:a:jenkins:jenkins",
    "gitlab":      "cpe:2.3:a:gitlab:gitlab",
    "spring":      "cpe:2.3:a:pivotal_software:spring_framework",
}

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)*)")


def _extract_version(version_str: str | None) -> str:
    if not version_str:
        return ""
    m = _VERSION_RE.search(version_str)
    return m.group(1) if m else ""


def _service_queries(service: str, version: str) -> tuple[str | None, str]:
    """Return (cpe_string_or_None, keyword_query)."""
    svc_low = (service or "").lower()
    ver = _extract_version(version)

    # Try CPE lookup
    for key, cpe_prefix in _SERVICE_TO_CPE_PREFIX.items():
        if key in svc_low:
            cpe = f"{cpe_prefix}:{ver}:*:*:*:*:*:*:*" if ver else None
            keyword = f"{key} {ver}".strip()
            return cpe, keyword

    # Generic keyword fallback
    keyword = f"{svc_low} {ver}".strip()
    return None, keyword


# ── Dedup by CVE ID ───────────────────────────────────────────────────────────

def _dedup_cves(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    result: list[Finding] = []
    for f in findings:
        key = f.cve_id or f.title
        if key not in seen:
            seen[key] = f
            result.append(f)
    return result


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_cve_mapper(
    ctx: "ScanContext",
    nmap_findings: list[Finding],
) -> ScanResult:
    """
    CVE mapping phase: query NVD API v2 + searchsploit for each discovered service.
    Only processes findings with type='port' that carry service and version info.
    """
    from app.core.config import settings

    result = ScanResult()
    api_key = settings.NVD_API_KEY
    delay = 0.6 if api_key else 6.0  # NVD rate limit

    # Collect unique (service, version) pairs from nmap port findings
    seen_services: set[str] = set()
    service_list: list[tuple[str, str]] = []

    for f in nmap_findings:
        if f.type != "port" or not f.service:
            continue
        svc = (f.service or "").lower()
        ver = _extract_version(f.version)
        key = f"{svc}:{ver}"
        if key not in seen_services:
            seen_services.add(key)
            service_list.append((svc, ver))

    if not service_list:
        await ctx.log(
            "CVE Mapper: no versioned services from nmap — skipping NVD queries",
            level="info",
            module="cve_mapper",
        )
        return result

    await ctx.log(
        f"CVE Mapper: querying NVD + searchsploit for {len(service_list)} service(s)"
        + (" (with API key)" if api_key else " (no API key — slow mode)"),
        module="cve_mapper",
    )

    all_cve_findings: list[Finding] = []

    for service, version in service_list:
        label = f"{service} {version}".strip()
        await ctx.log(f"  Querying CVEs for: {label}", module="cve_mapper")

        cpe, keyword = _service_queries(service, version)

        # NVD: CPE (precise) first, keyword as fallback
        nvd_findings: list[Finding] = []
        if cpe:
            nvd_findings = await _query_nvd_cpe(cpe, api_key, delay)

        if not nvd_findings and keyword:
            nvd_findings = await _query_nvd_keyword(keyword, api_key, delay)

        all_cve_findings.extend(nvd_findings)

        if nvd_findings:
            await ctx.log(
                f"  NVD: {len(nvd_findings)} CVE(s) for {label} "
                f"(top CVSS: {max(f.cvss_score or 0 for f in nvd_findings):.1f})",
                level="warning" if any((f.cvss_score or 0) >= 7.0 for f in nvd_findings) else "info",
                module="cve_mapper",
            )
        else:
            await ctx.log(f"  NVD: no CVEs found for {label}", level="info", module="cve_mapper")

        # searchsploit (version required for meaningful results)
        if version:
            ss_findings = _run_searchsploit(service, version)
            if ss_findings:
                all_cve_findings.extend(ss_findings)
                await ctx.log(
                    f"  searchsploit: {ss_findings[0].title}",
                    level="warning",
                    module="cve_mapper",
                )

    # Dedup
    result.findings = _dedup_cves(all_cve_findings)

    cve_count = sum(1 for f in result.findings if f.type == "cve")
    exploit_count = sum(1 for f in result.findings if f.type == "exploit")
    critical_high = sum(
        1 for f in result.findings
        if f.severity in ("critical", "high")
    )

    await ctx.log(
        f"CVE Mapper complete: {cve_count} CVE(s), {exploit_count} ExploitDB entry(ies) "
        f"— {critical_high} critical/high",
        level="warning" if critical_high else "success",
        module="cve_mapper",
    )
    return result
