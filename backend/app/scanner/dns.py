"""
DNS reconnaissance module.
Runs: subfinder (passive subdomains), dnsx (record enumeration),
      dnsrecon (zone transfer / SRV / reverse), fierce (DNS walking).
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


def _extract_domain(target: str) -> str:
    """Strip scheme / path, return bare domain or IP."""
    target = re.sub(r"^https?://", "", target)
    return target.split("/")[0].split(":")[0]


# ── subfinder ─────────────────────────────────────────────────────────────────

def _run_subfinder(domain: str, timeout: int = 120) -> tuple[list[str], list[str]]:
    """Return (subdomains, errors)."""
    rc, stdout, stderr = run_cmd(
        ["subfinder", "-d", domain, "-silent", "-json"],
        timeout=timeout,
    )
    if rc == -1:
        return [], [stderr]

    subdomains: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host", "")
            if host:
                subdomains.append(host)
        except json.JSONDecodeError:
            if line and not line.startswith("{"):
                subdomains.append(line)

    return subdomains, []


def _parse_subfinder_findings(subdomains: list[str], domain: str) -> list[Finding]:
    if not subdomains:
        return []
    unique = sorted(set(subdomains))
    return [
        Finding(
            type="subdomain",
            title=f"Subdomain discovered: {sub}",
            severity="info",
            description=f"Passive DNS enumeration found subdomain '{sub}' for domain '{domain}'.",
            remediation="Review exposed subdomains. Remove dev/staging subdomains from public DNS if not needed.",
            evidence=sub,
        )
        for sub in unique
    ]


# ── dnsx ──────────────────────────────────────────────────────────────────────

_DNS_SEVERITY: dict[str, str] = {
    "MX":    "info",
    "NS":    "info",
    "TXT":   "info",
    "CNAME": "info",
    "A":     "info",
    "AAAA":  "info",
    "SOA":   "low",
    "PTR":   "low",
}

_INTERESTING_TXT = re.compile(
    r"(spf|dkim|dmarc|verification|token|api|key|secret|password|aws|azure|google)",
    re.I,
)

_DMARC_MISSING = "v=DMARC1"
_SPF_MISSING   = "v=spf1"


def _run_dnsx(domain: str, timeout: int = 60) -> tuple[list[dict], list[str]]:
    """Run dnsx for common record types. Return (records, errors)."""
    record_types = ["a", "mx", "txt", "ns", "cname", "soa", "aaaa"]
    args = []
    for rt in record_types:
        args += [f"-{rt}"]

    rc, stdout, stderr = run_cmd(
        ["dnsx", "-d", domain, "-resp", "-json"] + args,
        timeout=timeout,
    )
    if rc == -1:
        return [], [stderr]

    records: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    return records, []


def _parse_dnsx_findings(records: list[dict], domain: str) -> list[Finding]:
    findings: list[Finding] = []
    has_spf   = False
    has_dmarc = False
    txt_values: list[str] = []

    for rec in records:
        host = rec.get("host", domain)

        for rtype in ("a", "mx", "ns", "cname", "soa", "aaaa", "ptr"):
            values = rec.get(rtype, [])
            if not values:
                continue
            rtype_upper = rtype.upper()
            for val in (values if isinstance(values, list) else [values]):
                findings.append(Finding(
                    type="dns_record",
                    title=f"DNS {rtype_upper}: {host} → {val}",
                    severity=_DNS_SEVERITY.get(rtype_upper, "info"),
                    description=f"DNS record {rtype_upper} for {host} resolves to {val}.",
                    evidence=f"{rtype_upper} {val}",
                ))

        for val in rec.get("txt", []):
            txt_values.append(val)
            if _SPF_MISSING in val:
                has_spf = True
            if _DMARC_MISSING in val:
                has_dmarc = True

            severity = "info"
            if _INTERESTING_TXT.search(val):
                severity = "low"

            findings.append(Finding(
                type="dns_record",
                title=f"DNS TXT: {host}",
                severity=severity,
                description=f"TXT record for {host}: {val[:300]}",
                evidence=val[:500],
                remediation="Review TXT records for sensitive data exposure." if severity != "info" else None,
            ))

    if not has_spf:
        findings.append(Finding(
            type="misconfig",
            title="Missing SPF record",
            severity="medium",
            description=f"No SPF TXT record found for {domain}. Domain may be used for email spoofing.",
            remediation="Add SPF record: 'v=spf1 include:<your-mail-provider> -all'",
        ))

    if not has_dmarc:
        findings.append(Finding(
            type="misconfig",
            title="Missing DMARC record",
            severity="medium",
            description=f"No DMARC TXT record found for {domain}. Phishing/spoofing attacks are easier without DMARC.",
            remediation="Add DMARC record at _dmarc.{domain}: 'v=DMARC1; p=reject; rua=mailto:...'",
        ))

    return findings


# ── dnsrecon ──────────────────────────────────────────────────────────────────

def _run_dnsrecon(domain: str, timeout: int = 120) -> tuple[list[Finding], list[str]]:
    """Zone transfer attempt + SRV + reverse lookup."""
    findings: list[Finding] = []
    errors: list[str] = []

    # Zone transfer (AXFR)
    rc, stdout, stderr = run_cmd(
        ["dnsrecon", "-d", domain, "-t", "axfr"],
        timeout=timeout,
    )
    if rc == -1:
        errors.append(stderr)
    else:
        if "Zone Transfer was successful" in stdout or "AXFR" in stdout.upper():
            findings.append(Finding(
                type="misconfig",
                title="DNS zone transfer allowed (AXFR)",
                severity="high",
                description=(
                    f"DNS zone transfer (AXFR) succeeded for {domain}. "
                    "This exposes the full internal DNS structure."
                ),
                remediation="Restrict zone transfers to authorised secondary name servers only.",
                raw_output=stdout[:1000],
            ))

    # SRV records
    rc2, stdout2, stderr2 = run_cmd(
        ["dnsrecon", "-d", domain, "-t", "srv"],
        timeout=60,
    )
    if rc2 == 0:
        for line in stdout2.splitlines():
            if "SRV" in line:
                findings.append(Finding(
                    type="dns_record",
                    title=f"SRV record: {line.strip()[:120]}",
                    severity="info",
                    description=f"SRV record discovered: {line.strip()}",
                    evidence=line.strip(),
                ))

    return findings, errors


# ── fierce ────────────────────────────────────────────────────────────────────

def _run_fierce(domain: str, timeout: int = 90) -> tuple[list[Finding], list[str]]:
    """DNS hostname brute-force walking."""
    rc, stdout, stderr = run_cmd(
        ["fierce", "--domain", domain, "--subdomain-file",
         "/usr/share/dnsrecon/subdomains-top1mil-5000.txt",
         "--delay", "0"],
        timeout=timeout,
    )
    if rc == -1:
        # Try without wordlist
        rc, stdout, stderr = run_cmd(
            ["fierce", "--domain", domain, "--delay", "0"],
            timeout=60,
        )
    if rc == -1:
        return [], [stderr]

    findings: list[Finding] = []
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("NS:") or line.startswith("SOA:"):
            continue
        if "Found:" in line or re.search(r"[a-z0-9-]+\." + re.escape(domain), line, re.I):
            host_match = re.search(r"([a-z0-9._-]+\." + re.escape(domain) + r")", line, re.I)
            if host_match:
                host = host_match.group(1)
                ip = (ip_re.search(line) or type("", (), {"group": lambda *a: None})()).group(0)
                findings.append(Finding(
                    type="subdomain",
                    title=f"Hostname brute-forced: {host}",
                    severity="info",
                    description=f"fierce found hostname {host}" + (f" → {ip}" if ip else ""),
                    evidence=line,
                    remediation="Review brute-forced hostnames and remove unnecessary public entries.",
                ))

    return findings, []


# ── main entry point ──────────────────────────────────────────────────────────

async def run_dns(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
) -> ScanResult:
    """
    DNS recon phase.
    Called for domain targets only (skipped for bare IPs in port/vuln scan types).
    """
    result = ScanResult()
    domain = _extract_domain(target)

    if _is_ip(domain) and scan_type in ("port", "vuln"):
        await ctx.log("DNS recon skipped (IP target with port/vuln scan)", module="dns")
        return result

    await ctx.log(f"DNS recon starting for {domain}", module="dns")

    # ── subfinder ─────────────────────────────────────────────────────────────
    if not _is_ip(domain):
        await ctx.log("Running subfinder (passive subdomain discovery)...", module="dns")
        subdomains, errs = _run_subfinder(domain)
        for e in errs:
            await ctx.log(e, level="warning", module="subfinder")
        sub_findings = _parse_subfinder_findings(subdomains, domain)
        result.findings.extend(sub_findings)
        await ctx.log(
            f"subfinder: {len(subdomains)} subdomains found",
            level="success" if subdomains else "info",
            module="subfinder",
        )

    # ── dnsx ──────────────────────────────────────────────────────────────────
    await ctx.log("Running dnsx (DNS record enumeration)...", module="dns")
    records, errs = _run_dnsx(domain)
    for e in errs:
        await ctx.log(e, level="warning", module="dnsx")
    dnsx_findings = _parse_dnsx_findings(records, domain)
    result.findings.extend(dnsx_findings)
    dns_record_count = sum(1 for f in dnsx_findings if f.type == "dns_record")
    await ctx.log(f"dnsx: {dns_record_count} DNS records collected", level="success", module="dnsx")

    # ── dnsrecon ──────────────────────────────────────────────────────────────
    if not _is_ip(domain):
        await ctx.log("Running dnsrecon (zone transfer + SRV)...", module="dns")
        dnsrecon_findings, errs = _run_dnsrecon(domain)
        for e in errs:
            await ctx.log(e, level="warning", module="dnsrecon")
        result.findings.extend(dnsrecon_findings)
        axfr = any("zone transfer" in f.title.lower() for f in dnsrecon_findings)
        await ctx.log(
            f"dnsrecon: {'AXFR succeeded!' if axfr else 'zone transfer not allowed'} + "
            f"{len(dnsrecon_findings)} findings",
            level="warning" if axfr else "info",
            module="dnsrecon",
        )

    # ── fierce (full scan only) ───────────────────────────────────────────────
    if scan_type == "full" and not _is_ip(domain):
        await ctx.log("Running fierce (DNS hostname brute-force)...", module="dns")
        fierce_findings, errs = _run_fierce(domain)
        for e in errs:
            await ctx.log(e, level="warning", module="fierce")
        result.findings.extend(fierce_findings)
        await ctx.log(
            f"fierce: {len(fierce_findings)} hostnames found",
            level="success" if fierce_findings else "info",
            module="fierce",
        )

    total = len(result.findings)
    await ctx.log(f"DNS recon complete: {total} total findings", level="success", module="dns")
    return result
