"""
Web form brute-force module — Phase 7.2.
Detects login forms from recon findings, then runs Hydra HTTP-POST.
Falls back to manual httpx probing if Hydra is unavailable.
Only runs on scan_type in ('full', 'vuln', 'web').
"""
from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext

# Common login form paths to probe
_LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/user/login", "/account/login",
    "/wp-login.php", "/admin/login", "/admin", "/panel", "/cpanel",
    "/phpmyadmin", "/dashboard/login", "/api/auth/login",
]

# Keywords that suggest a login page
_LOGIN_KEYWORDS = re.compile(
    r"login|sign.?in|password|username|email|passwd|credentials",
    re.IGNORECASE,
)

# Minimal credential pairs for web forms
_WEB_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest",
    "demo", "manager", "support", "info", "webmaster",
]

_WEB_PASSWORDS = [
    "admin", "admin123", "password", "password1", "123456", "12345678",
    "qwerty", "letmein", "welcome", "default", "changeme", "secret",
    "root", "toor", "test", "guest", "1234", "pass", "passw0rd",
]


def _extract_login_urls(
    pool_findings: list[Finding],
    target: str,
) -> list[str]:
    """Collect candidate login URLs from dirscan/osint/nikto findings."""
    urls: list[str] = []
    seen: set[str] = set()

    # Extract scheme+host from target
    if not target.startswith("http"):
        base = f"https://{target}"
    else:
        base = target.rstrip("/")

    # From findings
    for f in pool_findings:
        if not f.evidence:
            continue
        # Look for URLs in evidence
        for m in re.finditer(r'https?://[^\s"\'<>]+', f.evidence):
            url = m.group(0).rstrip("/")
            parsed = urlparse(url)
            path = parsed.path.lower()
            if _LOGIN_KEYWORDS.search(path) and url not in seen:
                urls.append(url)
                seen.add(url)

    # Probe common paths
    for path in _LOGIN_PATHS:
        url = base + path
        if url not in seen:
            urls.append(url)
            seen.add(url)

    return urls[:20]


async def _detect_login_form(url: str) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Returns (method, user_field, pass_field, fail_string) by fetching the page.
    Returns (None, None, None, None) if not a login form.
    """
    try:
        import httpx
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            r = await client.get(url)
            html = r.text
    except Exception:
        return None, None, None, None

    # Look for form with password input
    if not re.search(r'<input[^>]+type=["\']?password["\']?', html, re.IGNORECASE):
        return None, None, None, None

    # Guess user field name
    user_field = "username"
    for m in re.finditer(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']?(?:text|email)["\']?',
        html, re.IGNORECASE
    ):
        user_field = m.group(1)
        break

    # Guess pass field name
    pass_field = "password"
    for m in re.finditer(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']?password["\']?',
        html, re.IGNORECASE
    ):
        pass_field = m.group(1)
        break

    # Failure string = any common error phrase on current page
    fail_string = "incorrect"
    for phrase in ["invalid", "incorrect", "error", "failed", "wrong", "denied"]:
        if phrase.lower() in html.lower():
            fail_string = phrase
            break

    return "http-post-form", user_field, pass_field, fail_string


async def _run_hydra_web(
    target_url: str,
    method: str,
    user_field: str,
    pass_field: str,
    fail_string: str,
    users_file: str,
    pass_file: str,
) -> tuple[int, str, str]:
    """Build and run hydra http-post-form command."""
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    hydra_module = "https-post-form" if parsed.scheme == "https" else "http-post-form"
    form_spec = f"{path}:{user_field}=^USER^&{pass_field}=^PASS^:{fail_string}"

    cmd = [
        "hydra", "-L", users_file, "-P", pass_file,
        "-s", str(port),
        "-t", "4", "-f", "-q",
        host, hydra_module, form_spec,
    ]
    return run_cmd(cmd, timeout=180)


def _parse_hydra_web_output(
    output: str, url: str
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"\[.*?\]\[.*?\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s*(.*)",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        login = m.group(1).strip()
        password = m.group(2).strip() or "(blank)"
        findings.append(Finding(
            type="brute",
            title=f"Web form credentials found — {login}:{password}",
            severity="critical",
            description=(
                f"Hydra successfully authenticated to web login form at {url}.\n"
                f"Login: {login}\nPassword: {password}"
            ),
            evidence=f"{login}:{password} → {url}",
            port=443 if url.startswith("https") else 80,
            protocol="tcp",
            service="http",
            remediation=(
                "Change the compromised password immediately. "
                "Implement account lockout after 5 failed attempts. "
                "Enable multi-factor authentication. "
                "Use a CAPTCHA on the login form to prevent automated attacks."
            ),
            cvss_score=9.8,
        ))
    return findings


async def run_web_brute(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    pool_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type not in ("full", "vuln", "web"):
        return result

    if not shutil.which("hydra"):
        await ctx.log("web_brute: hydra not found, skipping", level="warning", module="web_brute")
        return result

    login_urls = _extract_login_urls(pool_findings, target)
    if not login_urls:
        await ctx.log("web_brute: no login URLs found", module="web_brute")
        return result

    await ctx.log(
        f"web_brute: probing {len(login_urls)} potential login URL(s)",
        module="web_brute",
    )

    # Write temp wordlist files
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as uf:
        uf.write("\n".join(_WEB_USERNAMES))
        users_file = uf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as pf:
        pf.write("\n".join(_WEB_PASSWORDS))
        pass_file = pf.name

    try:
        for url in login_urls:
            method, user_field, pass_field, fail_string = await _detect_login_form(url)
            if not method:
                continue

            await ctx.log(
                f"web_brute: attacking {url} (user={user_field}, pass={pass_field})",
                module="web_brute",
            )

            rc, stdout, stderr = await _run_hydra_web(
                url, method, user_field, pass_field, fail_string, users_file, pass_file
            )
            if rc == -1:
                await ctx.log(
                    f"web_brute: hydra error on {url}: {stderr[:200]}",
                    level="error", module="web_brute",
                )
                result.errors.append(f"hydra error on {url}")
                continue

            hits = _parse_hydra_web_output(stdout + stderr, url)
            if hits:
                await ctx.log(
                    f"web_brute CRITICAL: {len(hits)} credential(s) found at {url}",
                    level="error", module="web_brute",
                )
                result.findings.extend(hits)
            else:
                await ctx.log(f"web_brute: no creds found at {url}", module="web_brute")

    finally:
        Path(users_file).unlink(missing_ok=True)
        Path(pass_file).unlink(missing_ok=True)

    return result
