"""
HTTP security headers + SSL/TLS analysis module.
Runs: httpx (headers grab), sslyze (TLS configuration).
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Security header definitions ───────────────────────────────────────────────

_SECURITY_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "severity": "high",
        "title": "Missing HSTS header",
        "description": "HTTP Strict Transport Security (HSTS) not set. Browsers may connect over plain HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "severity": "high",
        "title": "Missing Content-Security-Policy header",
        "description": "No CSP header. XSS attacks have a wider impact without CSP restrictions.",
        "remediation": "Define a strict CSP: Content-Security-Policy: default-src 'self'; ...",
    },
    "x-frame-options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options header",
        "description": "Page can be embedded in iframes, enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors directive)",
    },
    "x-content-type-options": {
        "severity": "medium",
        "title": "Missing X-Content-Type-Options header",
        "description": "Browser may MIME-sniff response, leading to XSS via content confusion.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy header",
        "description": "Referrer header sent in full, potentially leaking sensitive URL parameters.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy header",
        "description": "No restrictions on browser features (camera, microphone, geolocation, etc.).",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
    "x-xss-protection": {
        "severity": "low",
        "title": "Missing X-XSS-Protection header",
        "description": "Legacy XSS filter not enabled (matters for older browsers).",
        "remediation": "Add: X-XSS-Protection: 1; mode=block",
    },
}

# Headers that disclose server info
_INFO_DISCLOSURE_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"}

# Weak TLS versions
_WEAK_TLS = {"TLS_1_0", "TLS_1_1", "SSL_2_0", "SSL_3_0"}

# Weak cipher patterns
_WEAK_CIPHER_RE = re.compile(
    r"(RC4|DES|3DES|NULL|EXPORT|ANON|MD5|RC2|ADH|AECDH)", re.I
)

_HSTS_MIN_AGE = 15768000  # 6 months


# ── httpx ─────────────────────────────────────────────────────────────────────

def _run_httpx(target: str, ports: list[int], timeout: int = 60) -> tuple[list[dict], list[str]]:
    """Probe each port with httpx, collect response headers as JSON."""
    results: list[dict] = []
    errors: list[str] = []

    # Build URL list
    urls: list[str] = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        urls.append(f"{scheme}://{target}:{port}")

    if not urls:
        # Generic probes
        urls = [f"http://{target}", f"https://{target}"]

    for url in urls:
        rc, stdout, stderr = run_cmd(
            [
                "httpx", "-u", url,
                "-include-response-headers",
                "-json",
                "-timeout", "10",
                "-follow-redirects",
                "-no-color",
                "-silent",
            ],
            timeout=timeout,
        )
        if rc == -1:
            errors.append(stderr or f"httpx timed out for {url}")
            continue
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return results, errors


def _parse_header_findings(httpx_results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []

    for result in httpx_results:
        url = result.get("url", result.get("input", "?"))
        raw_headers: dict = result.get("response_headers", {}) or result.get("headers", {})

        # Normalise header names to lowercase
        headers = {k.lower(): v for k, v in raw_headers.items()}

        # ── Missing security headers ───────────────────────────────────────
        for header_name, meta in _SECURITY_HEADERS.items():
            if header_name not in headers:
                findings.append(Finding(
                    type="misconfig",
                    title=f"{meta['title']} [{url}]",
                    severity=meta["severity"],
                    description=meta["description"],
                    remediation=meta["remediation"],
                    evidence=f"URL: {url}",
                ))

        # ── HSTS max-age too short ─────────────────────────────────────────
        hsts_val = headers.get("strict-transport-security", "")
        if hsts_val:
            age_match = re.search(r"max-age=(\d+)", hsts_val, re.I)
            if age_match and int(age_match.group(1)) < _HSTS_MIN_AGE:
                findings.append(Finding(
                    type="misconfig",
                    title=f"HSTS max-age too short [{url}]",
                    severity="medium",
                    description=f"HSTS max-age={age_match.group(1)}s is below recommended 6 months ({_HSTS_MIN_AGE}s).",
                    remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    evidence=hsts_val,
                ))

        # ── CSP unsafe directives ──────────────────────────────────────────
        csp_val = headers.get("content-security-policy", "")
        if csp_val:
            for unsafe in ("unsafe-inline", "unsafe-eval", "*"):
                if unsafe in csp_val:
                    findings.append(Finding(
                        type="misconfig",
                        title=f"CSP contains '{unsafe}' directive [{url}]",
                        severity="medium",
                        description=f"Content-Security-Policy uses '{unsafe}' which weakens XSS protection.",
                        remediation=f"Remove '{unsafe}' from CSP. Use nonces or hashes instead.",
                        evidence=csp_val[:400],
                    ))
                    break

        # ── Info disclosure headers ────────────────────────────────────────
        for h in _INFO_DISCLOSURE_HEADERS:
            val = headers.get(h)
            if val:
                findings.append(Finding(
                    type="info_disclosure",
                    title=f"Server info disclosed via {h.title()} header [{url}]",
                    severity="low",
                    description=f"Response header '{h}' reveals: {val}",
                    remediation=f"Remove or genericise the '{h}' response header.",
                    evidence=f"{h}: {val}",
                ))

        # ── HTTP (not HTTPS) for sensitive endpoint ────────────────────────
        if url.startswith("http://") and result.get("status_code", 0) in range(200, 400):
            findings.append(Finding(
                type="misconfig",
                title=f"Plain HTTP response on {url}",
                severity="medium",
                description="Server responds on plain HTTP. Data in transit is unencrypted.",
                remediation="Redirect all HTTP traffic to HTTPS. Enable HSTS.",
                evidence=f"Status: {result.get('status_code')}",
            ))

    return findings


# ── sslyze ────────────────────────────────────────────────────────────────────

def _run_sslyze(target: str, ports: list[int], timeout: int = 120) -> tuple[dict, list[str]]:
    """Run sslyze JSON scan. Return (parsed_json, errors)."""
    errors: list[str] = []

    tls_ports = [p for p in ports if p in (443, 8443, 465, 587, 993, 995, 8080)]
    if not tls_ports:
        tls_ports = [443]

    servers = [f"{target}:{p}" for p in tls_ports]
    cmd = ["sslyze", "--json_out", "-"] + servers

    rc, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if rc == -1:
        errors.append(stderr or "sslyze timed out")
        return {}, errors

    try:
        return json.loads(stdout), errors
    except json.JSONDecodeError:
        errors.append("sslyze output is not valid JSON")
        return {}, errors


def _parse_sslyze_findings(sslyze_data: dict) -> list[Finding]:
    findings: list[Finding] = []

    server_results = sslyze_data.get("server_scan_results") or []
    for server in server_results:
        server_info = server.get("server_location") or {}
        host = server_info.get("hostname", server_info.get("ip_address", "?"))
        port = server_info.get("port", 443)
        label = f"{host}:{port}"

        scan_result = server.get("scan_result") or {}

        # ── Weak protocol versions ─────────────────────────────────────────
        for proto_key in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
                          "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"):
            proto_data = scan_result.get(proto_key) or {}
            if not proto_data:
                continue
            accepted = (
                (proto_data.get("result") or {})
                .get("accepted_cipher_suites") or []
            )
            if accepted:
                proto_name = proto_key.replace("_cipher_suites", "").upper().replace("_", " ")
                severity = "critical" if "ssl" in proto_key else "high"
                findings.append(Finding(
                    type="ssl",
                    title=f"Weak protocol {proto_name} accepted [{label}]",
                    severity=severity,
                    description=f"Server accepts {proto_name}, which is cryptographically broken.",
                    remediation="Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1. Use TLS 1.2+ only.",
                    evidence=f"{proto_name}: {len(accepted)} cipher suites accepted",
                ))

        # ── Weak ciphers in TLS 1.2 ───────────────────────────────────────
        for proto_key in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
            proto_data = scan_result.get(proto_key) or {}
            if not proto_data:
                continue
            accepted = (
                (proto_data.get("result") or {})
                .get("accepted_cipher_suites") or []
            )
            for suite in accepted:
                name = suite.get("cipher_suite", {}).get("name", "")
                if name and _WEAK_CIPHER_RE.search(name):
                    findings.append(Finding(
                        type="ssl",
                        title=f"Weak cipher suite accepted: {name} [{label}]",
                        severity="high",
                        description=f"Server accepts weak cipher suite '{name}'.",
                        remediation="Disable weak ciphers. Prefer ECDHE+AES-GCM and ECDHE+CHACHA20.",
                        evidence=name,
                    ))

        # ── Certificate issues ─────────────────────────────────────────────
        cert_info = (scan_result.get("certificate_info") or {}).get("result") or {}
        cert_deployments = cert_info.get("certificate_deployments") or []

        for deployment in cert_deployments:
            # Expired / not yet valid
            verified = deployment.get("verified_certificate_chain") or []
            for cert in verified:
                subject = cert.get("subject", {})
                cn = subject.get("common_name") or subject.get("rfc4514_string", "")
                not_after = cert.get("not_valid_after")
                if not_after and "expired" in str(not_after).lower():
                    findings.append(Finding(
                        type="ssl",
                        title=f"SSL certificate expired [{label}]",
                        severity="critical",
                        description=f"Certificate for '{cn}' is expired.",
                        remediation="Renew the SSL certificate immediately.",
                        evidence=f"Not valid after: {not_after}",
                    ))

            # Hostname mismatch
            hostname_validation = deployment.get("leaf_certificate_subject_matches_hostname")
            if hostname_validation is False:
                findings.append(Finding(
                    type="ssl",
                    title=f"SSL certificate hostname mismatch [{label}]",
                    severity="high",
                    description="Certificate CN/SAN does not match the server hostname.",
                    remediation="Obtain a certificate that covers the correct hostname.",
                ))

            # Self-signed
            is_self_signed = deployment.get("leaf_certificate_is_self_signed")
            if is_self_signed:
                findings.append(Finding(
                    type="ssl",
                    title=f"Self-signed SSL certificate [{label}]",
                    severity="high",
                    description="Server presents a self-signed certificate. Clients cannot verify authenticity.",
                    remediation="Replace self-signed cert with a certificate from a trusted CA (e.g. Let's Encrypt).",
                ))

        # ── Heartbleed ─────────────────────────────────────────────────────
        heartbleed = (scan_result.get("heartbleed") or {}).get("result") or {}
        if heartbleed.get("is_vulnerable_to_heartbleed"):
            findings.append(Finding(
                type="cve",
                title=f"Heartbleed (CVE-2014-0160) [{label}]",
                severity="critical",
                description="Server is vulnerable to Heartbleed — private key material may be leaked.",
                cve_id="CVE-2014-0160",
                remediation="Upgrade OpenSSL to 1.0.1g+ or a patched version. Reissue private key and certificate.",
            ))

        # ── ROBOT attack ──────────────────────────────────────────────────
        robot = (scan_result.get("robot") or {}).get("result") or {}
        if robot.get("robot_result") in ("VULNERABLE_STRONG_ORACLE", "VULNERABLE_WEAK_ORACLE"):
            findings.append(Finding(
                type="ssl",
                title=f"ROBOT attack vulnerability [{label}]",
                severity="high",
                description="Server is vulnerable to the ROBOT (Return Of Bleichenbacher's Oracle Threat) attack.",
                remediation="Disable RSA key exchange ciphers. Use ECDHE only.",
            ))

        # ── CCS injection ─────────────────────────────────────────────────
        ccs = (scan_result.get("openssl_ccs_injection") or {}).get("result") or {}
        if ccs.get("is_vulnerable_to_ccs_injection"):
            findings.append(Finding(
                type="ssl",
                title=f"OpenSSL CCS Injection (CVE-2014-0224) [{label}]",
                severity="high",
                description="Server vulnerable to OpenSSL ChangeCipherSpec injection.",
                cve_id="CVE-2014-0224",
                remediation="Upgrade OpenSSL to 0.9.8za, 1.0.0m, or 1.0.1h+.",
            ))

    return findings


# ── main entry point ──────────────────────────────────────────────────────────

def _extract_web_ports(nmap_findings: list[Finding]) -> list[int]:
    ports: list[int] = []
    for f in nmap_findings:
        if f.type == "port" and f.port and f.service in (
            "http", "https", "http-alt", "http-proxy", "ssl/http"
        ):
            ports.append(f.port)
    # Fallback to common ports if nmap found none
    return ports or [80, 443]


async def run_ssl_headers(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    """
    HTTP security headers + SSL/TLS analysis.
    Called for web / full scan types.
    """
    result = ScanResult()

    web_ports = _extract_web_ports(nmap_findings)
    await ctx.log(f"SSL/headers analysis on ports: {web_ports}", module="ssl_headers")

    # ── httpx header analysis ─────────────────────────────────────────────────
    await ctx.log("Running httpx (HTTP security headers)...", module="ssl_headers")
    httpx_results, errs = _run_httpx(target, web_ports)
    for e in errs:
        await ctx.log(e, level="warning", module="httpx")

    header_findings = _parse_header_findings(httpx_results)
    result.findings.extend(header_findings)

    missing = sum(1 for f in header_findings if f.type == "misconfig")
    await ctx.log(
        f"httpx: {len(httpx_results)} responses analysed, {missing} header issues found",
        level="success" if httpx_results else "warning",
        module="httpx",
    )

    # ── sslyze TLS analysis ───────────────────────────────────────────────────
    tls_ports = [p for p in web_ports if p in (443, 8443, 465, 587, 993, 995)] or [443]
    await ctx.log(f"Running sslyze (TLS analysis) on ports {tls_ports}...", module="ssl_headers")

    sslyze_data, errs = _run_sslyze(target, tls_ports)
    for e in errs:
        await ctx.log(e, level="warning", module="sslyze")

    if sslyze_data:
        ssl_findings = _parse_sslyze_findings(sslyze_data)
        result.findings.extend(ssl_findings)
        await ctx.log(
            f"sslyze: {len(ssl_findings)} TLS issues found",
            level="warning" if any(f.severity in ("critical", "high") for f in ssl_findings) else "success",
            module="sslyze",
        )
    else:
        await ctx.log("sslyze: no data (target may not serve TLS)", level="info", module="sslyze")

    await ctx.log(
        f"SSL/headers complete: {len(result.findings)} total findings",
        level="success",
        module="ssl_headers",
    )
    return result
