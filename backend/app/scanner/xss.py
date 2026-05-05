"""
XSS scanner module — step 6.2.
Tool: dalfox (fast DOM/reflected/stored XSS with WAF bypass).
Fallback: manual payload probe via httpx if dalfox not found.
Only triggers on scan_type in ("web", "full").
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd
from app.scanner.flag_extractor import build_flag_pattern, search_flags_decoded

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── dalfox output parsers ─────────────────────────────────────────────────────

# [POC][G] Reflected XSS Triggered on https://...?q=<payload>
_POC_RE    = re.compile(r"\[POC\]\[([A-Z])\]\s+(.+?)(?:\s+Triggered on\s+)?(\S+)", re.I)
# [WEAK] ...
_WEAK_RE   = re.compile(r"\[WEAK\]\s+(.+)")
# [INFO] ...
_INFO_RE   = re.compile(r"\[INFO\]\s+(.+)")
# parameter: q  →  used in evidence
_PARAM_RE  = re.compile(r"param(?:eter)?[=:\s]+['\"]?(\w+)['\"]?", re.I)


def _xss_type_label(code: str) -> str:
    return {
        "G": "Reflected XSS",
        "V": "Verified XSS",
        "S": "Stored XSS candidate",
        "D": "DOM XSS",
        "B": "Blind XSS candidate",
    }.get(code.upper(), "XSS")


def _parse_dalfox(stdout: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        m = _POC_RE.search(line)
        if m:
            code    = m.group(1)
            detail  = m.group(2).strip()
            poc_url = m.group(3).strip() if m.group(3) else url

            key = f"{code}:{detail[:60]}"
            if key in seen:
                continue
            seen.add(key)

            label    = _xss_type_label(code)
            severity = "high" if code in ("V", "G", "D") else "medium"

            findings.append(Finding(
                type="xss",
                title=f"{label}: {url[:80]}",
                severity=severity,
                description=(
                    f"dalfox confirmed {label}.\n"
                    f"URL: {poc_url}\n"
                    f"Detail: {detail}"
                ),
                cvss_score=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                evidence=poc_url[:300],
                remediation=(
                    "Encode all user-controlled output (HTML entity encoding). "
                    "Implement a strict Content-Security-Policy header. "
                    "Use framework auto-escaping and avoid innerHTML/eval."
                ),
            ))

        # Weak findings (e.g. partial injection without full execution)
        elif _WEAK_RE.search(line):
            wm = _WEAK_RE.search(line)
            if wm:
                detail = wm.group(1).strip()
                key = f"weak:{detail[:60]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        type="xss",
                        title=f"XSS (weak signal): {url[:60]}",
                        severity="low",
                        description=f"dalfox detected a partial XSS indicator:\n{detail}",
                        cvss_score=3.1,
                        evidence=detail[:200],
                        remediation="Review output encoding and CSP policy.",
                    ))

    return findings


# ── URL helpers ───────────────────────────────────────────────────────────────

_PARAM_URL_RE = re.compile(r"https?://\S+\?\S+=\S*", re.I)


def _collect_urls(target: str, all_findings: list[Finding], max_urls: int = 20) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        u = u.strip().rstrip(".")
        if u and u not in seen and "?" in u:
            seen.add(u)
            urls.append(u)

    for f in all_findings:
        # wayback param URLs stored in evidence
        if f.type == "osint" and "parameter URL" in (f.title or ""):
            for line in (f.evidence or "").splitlines():
                m = _PARAM_URL_RE.search(line)
                if m:
                    _add(m.group(0))

        if f.evidence:
            m = _PARAM_URL_RE.search(f.evidence)
            if m:
                _add(m.group(0))

        if f.type in ("endpoint", "web") and f.title:
            m = _PARAM_URL_RE.search(f.title)
            if m:
                _add(m.group(0))

    if "?" in target:
        _add(target if target.startswith("http") else f"http://{target}")

    return urls[:max_urls]


def _base_urls_from_findings(target: str, nmap_findings: list[Finding]) -> list[str]:
    """Collect base URLs (no params) for dalfox pipe/crawl mode."""
    urls: list[str] = []
    seen: set[str] = set()
    for f in nmap_findings:
        if f.type == "port" and f.service in ("http", "https", "http-alt", "ssl/http"):
            scheme = "https" if (f.port or 0) in (443, 8443) else "http"
            port   = f.port or (443 if scheme == "https" else 80)
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                u = f"{scheme}://{target}"
            else:
                u = f"{scheme}://{target}:{port}"
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls or [f"http://{target}"]


# ── dalfox runners ────────────────────────────────────────────────────────────

def _run_dalfox_url(url: str, timeout: int = 120) -> tuple[str, str]:
    rc, stdout, stderr = run_cmd(
        [
            "dalfox", "url", url,
            "--silence",
            "--no-spinner",
            "--skip-bav",          # skip blind-always-vulnerable check (faster)
            "--timeout", "10",
            "--delay", "100",      # 100 ms between requests
            "--worker", "10",
        ],
        timeout=timeout,
    )
    if rc == -1:
        return "", stderr or "dalfox timed out"
    return stdout, stderr


def _run_dalfox_pipe(urls: list[str], timeout: int = 240) -> tuple[str, str]:
    """Feed multiple base URLs to dalfox via stdin pipe mode for crawl+fuzz."""
    import subprocess
    input_data = "\n".join(urls)
    try:
        proc = subprocess.run(
            [
                "dalfox", "pipe",
                "--silence",
                "--no-spinner",
                "--skip-bav",
                "--timeout", "10",
                "--delay", "150",
                "--worker", "8",
                "--follow-redirects",
            ],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return "", "dalfox pipe timed out"
    except FileNotFoundError:
        return "", "dalfox: command not found"


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_xss(
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

    await ctx.log("XSS: starting dalfox scan", module="xss")

    param_urls  = _collect_urls(target, all_findings)
    base_urls   = _base_urls_from_findings(target, nmap_findings)
    total_found = 0

    # ── Mode 1: direct URL scan for each parametric URL ───────────────────
    if param_urls:
        await ctx.log(f"XSS: scanning {len(param_urls)} parametric URL(s)", module="xss")
        for url in param_urls:
            stdout, stderr = _run_dalfox_url(url)
            if "not found" in stderr:
                result.errors.append("dalfox: command not found")
                await ctx.log("XSS: dalfox not installed — skipping", level="warning", module="xss")
                return result
            if "timed out" in stderr:
                await ctx.log(f"XSS: timeout on {url[:80]}", level="warning", module="xss")
                continue

            hits = _parse_dalfox(stdout, url)
            if hits:
                total_found += len(hits)
                result.findings.extend(hits)
                # CTF: check XSS output for flag patterns
                if ctf_pattern:
                    for flag in search_flags_decoded(stdout, ctf_pattern):
                        result.findings.append(Finding(
                            type="flag",
                            title=f"FLAG CAPTURED via XSS: {flag}",
                            severity="critical",
                            description=f"Flag found in XSS probe output.\nURL: {url}\nFlag: {flag}",
                            evidence=f"flag={flag} url={url}",
                            cvss_score=10.0,
                        ))
                await ctx.log(
                    f"XSS FOUND: {url[:80]} — {len(hits)} point(s)",
                    level="error",
                    module="xss",
                )
            else:
                await ctx.log(f"XSS: clean — {url[:80]}", level="info", module="xss")

    # ── Mode 2: pipe/crawl mode on base URLs (web scan without prior params) ─
    else:
        await ctx.log(
            f"XSS: no parametric URLs found, running pipe crawl on {len(base_urls)} base URL(s)",
            module="xss",
        )
        stdout, stderr = _run_dalfox_pipe(base_urls)
        if "not found" in stderr:
            result.errors.append("dalfox: command not found")
            await ctx.log("XSS: dalfox not installed — skipping", level="warning", module="xss")
            return result

        for base_url in base_urls:
            hits = _parse_dalfox(stdout, base_url)
            if hits:
                total_found += len(hits)
                result.findings.extend(hits)

    await ctx.log(
        f"XSS complete: {total_found} XSS point(s) found",
        level="warning" if total_found else "success",
        module="xss",
    )
    return result
