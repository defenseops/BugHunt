"""
Directory / endpoint enumeration module.
Runs: ffuf (fast fuzzing), feroxbuster (recursive), gobuster (fallback).
Only triggered for web / full scan types.
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Wordlists (inside scanner container from SecLists sparse checkout) ─────────

_WORDLISTS = [
    "/opt/tools/wordlists/Discovery/Web-Content/common.txt",
    "/opt/tools/wordlists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",    # fallback if SecLists missing
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

_API_WORDLISTS = [
    "/opt/tools/wordlists/Discovery/Web-Content/api/api-endpoints.txt",
    "/opt/tools/wordlists/Discovery/Web-Content/raft-small-words.txt",
]


def _best_wordlist(candidates: list[str]) -> str | None:
    import os
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


# ── Status code classification ─────────────────────────────────────────────────

_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

_CODE_SEVERITY: dict[int, str] = {
    200: "info",
    201: "info",
    204: "info",
    301: "info",
    302: "info",
    307: "info",
    308: "info",
    401: "low",     # auth required — endpoint exists
    403: "low",     # forbidden — endpoint exists
    405: "low",     # method not allowed — endpoint exists
    500: "medium",  # server error — may indicate injection point
}

# Paths that are high-value regardless of status
_SENSITIVE_PATH_RE = re.compile(
    r"(admin|backup|\.git|\.env|config|\.htaccess|\.htpasswd|wp-admin|"
    r"phpmyadmin|manager|console|actuator|api/v[0-9]|swagger|graphql|"
    r"\.bak|\.sql|\.zip|\.tar|debug|test|upload|shell|webshell)",
    re.I,
)


def _path_severity(path: str, status: int) -> str:
    base = _CODE_SEVERITY.get(status, "info")
    if _SENSITIVE_PATH_RE.search(path):
        # Bump severity one level for sensitive paths
        bumps = {"info": "low", "low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
        return bumps.get(base, base)
    return base


# ── ffuf ──────────────────────────────────────────────────────────────────────

def _run_ffuf(
    base_url: str,
    wordlist: str,
    timeout: int = 180,
    extensions: str = "php,html,js,txt,json,xml,bak,zip,sql",
) -> tuple[list[dict], list[str]]:
    rc, stdout, stderr = run_cmd(
        [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-e", f".{extensions.replace(',', ',.')}",
            "-mc", "200,201,204,301,302,307,308,401,403,405,500",
            "-c", "-t", "40",
            "-timeout", "10",
            "-of", "json",
            "-o", "-",
            "-s",           # silent mode — no progress bar
        ],
        timeout=timeout,
    )
    if rc == -1:
        return [], [stderr or "ffuf timed out"]

    results: list[dict] = []
    # ffuf json output is a single object with "results" array
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "results" in obj:
                results.extend(obj["results"])
            elif "status" in obj:
                results.append(obj)
        except json.JSONDecodeError:
            pass

    return results, []


def _parse_ffuf_findings(results: list[dict], base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for r in results:
        path   = r.get("input", {}).get("FUZZ", "") or r.get("url", "").replace(base_url, "")
        status = int(r.get("status", 0))
        length = r.get("length", 0)
        url    = r.get("url", f"{base_url}/{path}")

        if not path or url in seen:
            continue
        seen.add(url)

        severity = _path_severity(path, status)
        is_sensitive = bool(_SENSITIVE_PATH_RE.search(path))

        findings.append(Finding(
            type="endpoint",
            title=f"[{status}] {path}",
            severity=severity,
            description=(
                f"Directory/file found: {url}\n"
                f"Status: {status}, Response size: {length} bytes"
                + (" — SENSITIVE PATH" if is_sensitive else "")
            ),
            evidence=url,
            remediation=(
                "Restrict access to sensitive paths. Remove backup files, debug endpoints, "
                "and admin interfaces from public-facing servers."
                if is_sensitive else None
            ),
        ))

    return findings


# ── feroxbuster ───────────────────────────────────────────────────────────────

def _run_feroxbuster(
    base_url: str,
    wordlist: str,
    timeout: int = 240,
) -> tuple[list[dict], list[str]]:
    rc, stdout, stderr = run_cmd(
        [
            "feroxbuster",
            "--url", base_url,
            "--wordlist", wordlist,
            "--depth", "2",
            "--threads", "30",
            "--timeout", "10",
            "--status-codes", "200,201,204,301,302,307,308,401,403,405,500",
            "--extensions", "php,html,js,txt,json,xml,bak",
            "--json",
            "--quiet",
            "--no-state",
        ],
        timeout=timeout,
    )
    if rc == -1:
        return [], [stderr or "feroxbuster timed out"]

    results: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if obj.get("type") == "response":
                results.append(obj)
        except json.JSONDecodeError:
            pass

    return results, []


def _parse_feroxbuster_findings(results: list[dict], base_url: str, seen_urls: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    for r in results:
        url    = r.get("url", "")
        status = int(r.get("status", 0))
        length = r.get("content_length", r.get("response_length", 0))
        path   = url.replace(base_url, "") or "/"

        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        severity = _path_severity(path, status)
        is_sensitive = bool(_SENSITIVE_PATH_RE.search(path))

        findings.append(Finding(
            type="endpoint",
            title=f"[{status}] {path}",
            severity=severity,
            description=(
                f"Recursive scan found: {url}\n"
                f"Status: {status}, Size: {length}"
                + (" — SENSITIVE PATH" if is_sensitive else "")
            ),
            evidence=url,
            remediation=(
                "Restrict access to sensitive paths and remove unnecessary exposed files."
                if is_sensitive else None
            ),
        ))

    return findings


# ── gobuster (fallback) ────────────────────────────────────────────────────────

_GOBUSTER_LINE_RE = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)")


def _run_gobuster(
    base_url: str,
    wordlist: str,
    timeout: int = 180,
) -> tuple[list[Finding], list[str]]:
    rc, stdout, stderr = run_cmd(
        [
            "gobuster", "dir",
            "-u", base_url,
            "-w", wordlist,
            "-t", "30",
            "-x", "php,html,txt,js,json,bak",
            "--status-codes", "200,201,204,301,302,307,308,401,403,405,500",
            "-q",   # quiet
        ],
        timeout=timeout,
    )
    if rc == -1:
        return [], [stderr or "gobuster timed out"]

    findings: list[Finding] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        m = _GOBUSTER_LINE_RE.search(line)
        if not m:
            continue
        path   = m.group(1)
        status = int(m.group(2))
        url    = f"{base_url}{path}"

        if url in seen:
            continue
        seen.add(url)

        severity = _path_severity(path, status)
        is_sensitive = bool(_SENSITIVE_PATH_RE.search(path))

        findings.append(Finding(
            type="endpoint",
            title=f"[{status}] {path}",
            severity=severity,
            description=(
                f"gobuster found: {url} (status {status})"
                + (" — SENSITIVE PATH" if is_sensitive else "")
            ),
            evidence=url,
            remediation=(
                "Restrict access to sensitive paths and remove unnecessary exposed files."
                if is_sensitive else None
            ),
        ))

    return findings, []


# ── helpers ───────────────────────────────────────────────────────────────────

def _extract_web_ports(nmap_findings: list[Finding]) -> list[int]:
    ports: list[int] = []
    for f in nmap_findings:
        if f.type == "port" and f.port and f.service in (
            "http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"
        ):
            ports.append(f.port)
    return ports or [80, 443]


def _build_base_urls(target: str, ports: list[int]) -> list[str]:
    urls: list[str] = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            urls.append(f"{scheme}://{target}")
        else:
            urls.append(f"{scheme}://{target}:{port}")
    return urls or [f"http://{target}"]


# ── main entry point ──────────────────────────────────────────────────────────

async def run_dirscan(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    """Directory / endpoint enumeration (web + full scan types)."""
    result = ScanResult()

    wordlist = _best_wordlist(_WORDLISTS)
    if not wordlist:
        await ctx.log("No wordlist found — skipping directory scan", level="warning", module="dirscan")
        return result

    web_ports = _extract_web_ports(nmap_findings)
    base_urls = _build_base_urls(target, web_ports)

    await ctx.log(f"Directory scan on {len(base_urls)} URL(s) with wordlist {wordlist}", module="dirscan")

    seen_urls: set[str] = set()

    for base_url in base_urls:
        await ctx.log(f"Scanning {base_url}...", module="dirscan")

        # ── Try ffuf first ────────────────────────────────────────────────
        await ctx.log(f"Running ffuf on {base_url}...", module="dirscan")
        ffuf_raw, errs = _run_ffuf(base_url, wordlist)
        for e in errs:
            await ctx.log(e, level="warning", module="ffuf")

        if ffuf_raw:
            ffuf_findings = _parse_ffuf_findings(ffuf_raw, base_url)
            for f in ffuf_findings:
                if f.evidence not in seen_urls:
                    seen_urls.add(f.evidence or "")
                    result.findings.append(f)
            await ctx.log(
                f"ffuf: {len(ffuf_findings)} paths found on {base_url}",
                level="success" if ffuf_findings else "info",
                module="ffuf",
            )
        else:
            # ── Fallback: feroxbuster ─────────────────────────────────────
            await ctx.log(f"ffuf returned no results, trying feroxbuster on {base_url}...", module="dirscan")
            ferro_raw, errs = _run_feroxbuster(base_url, wordlist)
            for e in errs:
                await ctx.log(e, level="warning", module="feroxbuster")

            if ferro_raw:
                ferro_findings = _parse_feroxbuster_findings(ferro_raw, base_url, seen_urls)
                result.findings.extend(ferro_findings)
                await ctx.log(
                    f"feroxbuster: {len(ferro_findings)} paths found on {base_url}",
                    level="success" if ferro_findings else "info",
                    module="feroxbuster",
                )
            else:
                # ── Final fallback: gobuster ──────────────────────────────
                await ctx.log(f"Falling back to gobuster on {base_url}...", module="dirscan")
                go_findings, errs = _run_gobuster(base_url, wordlist)
                for e in errs:
                    await ctx.log(e, level="warning", module="gobuster")
                for f in go_findings:
                    if f.evidence not in seen_urls:
                        seen_urls.add(f.evidence or "")
                        result.findings.append(f)
                await ctx.log(
                    f"gobuster: {len(go_findings)} paths found on {base_url}",
                    level="success" if go_findings else "info",
                    module="gobuster",
                )

    sensitive_count = sum(1 for f in result.findings if f.severity in ("medium", "high", "critical"))
    await ctx.log(
        f"Directory scan complete: {len(result.findings)} paths found, {sensitive_count} sensitive",
        level="warning" if sensitive_count else "success",
        module="dirscan",
    )
    return result
