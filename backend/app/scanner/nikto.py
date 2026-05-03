"""
Nikto web scanner module.
Runs: nikto -h <target> -Format xml -output -
Parses XML/text output → Finding list.

Only triggered when scan_type in ('web', 'full') AND
an HTTP/HTTPS port was found by nmap.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# Nikto OSVDB IDs → severity mapping (common ones)
_OSVDB_SEVERITY: dict[str, str] = {
    # Critical
    "3268": "critical",   # PHP remote file include
    "40": "critical",     # Backdoor / webshell
    # High
    "877": "high",        # HTTP TRACE enabled (XST)
    "3092": "high",       # Default files exposing info
    "5765": "high",       # PUT method allowed
    "397": "high",        # HTTP methods dangerous
    "12184": "high",      # phpMyAdmin default install
    # Medium
    "3233": "medium",     # Apache default files
    "719": "medium",      # robots.txt disclosure
    "2798": "medium",     # Server banner disclosure
}

_TITLE_SEVERITY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(remote file inclusion|rfi|command injection|rce)", re.I), "critical"),
    (re.compile(r"(sql injection|sqli|xss|csrf|ssrf|xxe|lfi|ssti)", re.I),  "high"),
    (re.compile(r"(default (page|install|credential)|phpmyadmin|webshell|backdoor)", re.I), "high"),
    (re.compile(r"(put method|http trace|dangerous method)", re.I),           "high"),
    (re.compile(r"(directory (listing|index)|path disclosure)", re.I),        "medium"),
    (re.compile(r"(server (header|banner|version)|x-powered-by)", re.I),      "low"),
    (re.compile(r"(robots\.txt|sitemap\.xml)", re.I),                          "low"),
    (re.compile(r"(cookie.*httponly|cookie.*secure)", re.I),                   "low"),
]

_DEFAULT_REMEDIATIONS: dict[str, str] = {
    "critical": "Patch immediately. Disable or restrict the vulnerable component.",
    "high":     "Apply vendor patch. Review server configuration and access controls.",
    "medium":   "Review and harden server configuration. Disable unnecessary features.",
    "low":      "Remove server banners and unnecessary headers. Follow hardening guides.",
    "info":     "Informational finding. Review for potential information disclosure.",
}


def _severity_from_title(title: str, osvdb: str) -> str:
    if osvdb in _OSVDB_SEVERITY:
        return _OSVDB_SEVERITY[osvdb]
    for pattern, sev in _TITLE_SEVERITY_RULES:
        if pattern.search(title):
            return sev
    return "info"


def _parse_nikto_xml(xml_text: str, port: int, scheme: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    # Nikto XML: <niktoscan><scandetails><item>...</item></scandetails></niktoscan>
    for item in root.findall(".//item"):
        description = (item.findtext("description") or "").strip()
        uri         = (item.findtext("uri") or "").strip()
        osvdbid     = (item.findtext("osvdbid") or "").strip()
        method      = (item.findtext("method") or "GET").strip()

        if not description:
            continue

        severity   = _severity_from_title(description, osvdbid)
        title      = description[:120]
        evidence   = f"{method} {scheme}://HOST:{port}{uri}" if uri else None
        remediation = _DEFAULT_REMEDIATIONS.get(severity, _DEFAULT_REMEDIATIONS["info"])

        osvdb_ref = f"OSVDB-{osvdbid}" if osvdbid and osvdbid != "0" else None

        findings.append(Finding(
            type="web",
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            port=port,
            protocol="tcp",
            service=scheme,
            cve_id=osvdb_ref,
            remediation=remediation,
            raw_output=description,
        ))

    return findings


def _parse_nikto_text(text: str, port: int, scheme: str) -> list[Finding]:
    """Fallback: parse nikto plain-text output line by line."""
    findings: list[Finding] = []

    for line in text.splitlines():
        line = line.strip()
        # Nikto result lines start with + or -
        if not (line.startswith("+ ") or line.startswith("- ")):
            continue
        # Skip summary lines
        if any(skip in line for skip in ["Target IP:", "Target Hostname:", "Target Port:",
                                          "Start Time:", "End Time:", "requests made",
                                          "Nikto v", "host(s) tested"]):
            continue

        # Extract OSVDB id if present
        osvdb_match = re.search(r"OSVDB-(\d+)", line)
        osvdb_id    = osvdb_match.group(1) if osvdb_match else "0"

        description = re.sub(r"OSVDB-\d+:\s*", "", line.lstrip("+-").strip())
        severity    = _severity_from_title(description, osvdb_id)
        remediation = _DEFAULT_REMEDIATIONS.get(severity, _DEFAULT_REMEDIATIONS["info"])

        findings.append(Finding(
            type="web",
            title=description[:120],
            severity=severity,
            description=description,
            port=port,
            protocol="tcp",
            service=scheme,
            cve_id=f"OSVDB-{osvdb_id}" if osvdb_id != "0" else None,
            remediation=remediation,
            raw_output=line,
        ))

    return findings


def _extract_web_ports(nmap_findings: list[Finding]) -> list[tuple[int, str]]:
    """Extract (port, scheme) pairs from nmap findings for web scanning."""
    web_ports: list[tuple[int, str]] = []
    seen: set[int] = set()

    for f in nmap_findings:
        if f.type != "port" or f.port is None:
            continue
        port = f.port
        svc  = (f.service or "").lower()
        if port in seen:
            continue

        if svc == "https" or port in (443, 8443):
            web_ports.append((port, "https"))
            seen.add(port)
        elif svc in ("http", "http-alt", "http-proxy") or port in (80, 8080, 8000, 8888, 3000, 5000):
            web_ports.append((port, "http"))
            seen.add(port)

    # If no web ports found from nmap, default to 80
    if not web_ports:
        web_ports = [(80, "http")]

    return web_ports


async def run_nikto(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    """Entry point called by scan orchestrator."""
    result = ScanResult()

    if scan_type == "port":
        # Port-only scan — skip web checks
        return result

    web_ports = _extract_web_ports(nmap_findings)
    await ctx.log(
        f"Nikto: scanning {len(web_ports)} web port(s): {[p for p,_ in web_ports]}",
        module="nikto",
    )

    for port, scheme in web_ports:
        await ctx.log(f"Nikto: scanning {scheme}://{target}:{port}", module="nikto")

        cmd = [
            "nikto",
            "-h", f"{scheme}://{target}",
            "-p", str(port),
            "-Format", "xml",
            "-output", "-",
            "-nointeractive",
            "-Tuning", "1234567890abcde",   # all checks
            "-timeout", "10",
        ]

        rc, stdout, stderr = run_cmd(cmd, timeout=300)

        if rc == -1:
            err = stderr or "nikto timed out or not found"
            await ctx.log(f"Nikto error on port {port}: {err}", level="error", module="nikto")
            result.errors.append(err)
            continue

        # Try XML parse first, fall back to text
        if "<niktoscan" in stdout:
            port_findings = _parse_nikto_xml(stdout, port, scheme)
        else:
            port_findings = _parse_nikto_text(stdout or stderr, port, scheme)

        await ctx.log(
            f"Nikto port {port}: {len(port_findings)} findings",
            level="success" if port_findings else "info",
            module="nikto",
        )
        result.findings.extend(port_findings)

    return result
