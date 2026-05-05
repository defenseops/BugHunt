"""
SQLmap module — step 6.1.
Runs sqlmap on URLs with parameters collected from previous phases.
Uses safe options only: level 1, risk 1, no destructive payloads.
Only triggers on scan_type in ("web", "full").
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd
from app.scanner.flag_extractor import build_flag_pattern, search_flags_decoded

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Output parsers ────────────────────────────────────────────────────────────

_INJECT_POINT_RE = re.compile(
    r"sqlmap identified the following injection point", re.I
)
_PARAM_RE   = re.compile(r"Parameter:\s*(\S+)\s*\((GET|POST|Cookie|Header|URI)\)", re.I)
_TYPE_RE    = re.compile(r"\s+Type:\s*(.+)")
_PAYLOAD_RE = re.compile(r"\s+Payload:\s*(.+)")
_DBMS_RE    = re.compile(r"back-end DBMS:\s*(.+)", re.I)
_TITLE_RE   = re.compile(r"\s+Title:\s*(.+)")


def _parse_sqlmap_output(stdout: str, url: str) -> list[Finding]:
    findings: list[Finding] = []

    if not _INJECT_POINT_RE.search(stdout):
        return findings

    dbms_match = _DBMS_RE.search(stdout)
    dbms = dbms_match.group(1).strip() if dbms_match else "unknown"

    # Parse each injection block
    current_param: str | None = None
    current_method: str | None = None
    injections: list[dict] = []
    current: dict = {}

    for line in stdout.splitlines():
        pm = _PARAM_RE.search(line)
        if pm:
            if current and current.get("param"):
                injections.append(current)
            current_param = pm.group(1)
            current_method = pm.group(2)
            current = {"param": current_param, "method": current_method, "types": [], "payloads": [], "titles": []}
            continue

        tm = _TYPE_RE.match(line)
        if tm and current:
            current["types"].append(tm.group(1).strip())
            continue

        pm2 = _PAYLOAD_RE.match(line)
        if pm2 and current:
            current["payloads"].append(pm2.group(1).strip()[:200])
            continue

        titm = _TITLE_RE.match(line)
        if titm and current:
            current["titles"].append(titm.group(1).strip())

    if current and current.get("param"):
        injections.append(current)

    for inj in injections:
        param   = inj.get("param", "?")
        method  = inj.get("method", "GET")
        types   = inj.get("types", [])
        payload = inj.get("payloads", [""])[0]
        titles  = inj.get("titles", [])

        # Severity by technique: error-based / UNION = high, boolean/time = medium
        has_high = any(re.search(r"error.based|UNION|stacked", t, re.I) for t in types)
        severity = "high" if has_high else "medium"
        cvss     = 8.8 if has_high else 6.3

        type_str  = ", ".join(types) if types else "unknown"
        title_str = "; ".join(titles) if titles else ""

        findings.append(Finding(
            type="sqli",
            title=f"SQL Injection: {param} ({method}) — {url[:80]}",
            severity=severity,
            description=(
                f"sqlmap confirmed SQL injection in parameter '{param}' ({method}).\n"
                f"URL: {url}\n"
                f"DBMS: {dbms}\n"
                f"Technique(s): {type_str}\n"
                + (f"Title(s): {title_str}\n" if title_str else "")
                + (f"Sample payload: {payload}" if payload else "")
            ),
            evidence=f"param={param} method={method} dbms={dbms} payload={payload[:150]}",
            cvss_score=cvss,
            cvss_vector=(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                if has_high else
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
            ),
            remediation=(
                "Use parameterized queries / prepared statements. "
                "Never concatenate user input into SQL strings. "
                "Apply input validation and a WAF as defence-in-depth."
            ),
        ))

    return findings


# ── URL collector ─────────────────────────────────────────────────────────────

_PARAM_URL_RE = re.compile(r"https?://\S+\?\S+=\S*", re.I)


def _collect_param_urls(
    target: str,
    all_findings: list[Finding],
    max_urls: int = 15,
) -> list[str]:
    """
    Gather parametric URLs from previous phase findings.
    Sources (in order): osint wayback, dirscan endpoints, nikto findings.
    """
    urls: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        u = u.strip().rstrip(".")
        if u and u not in seen and "?" in u:
            seen.add(u)
            urls.append(u)

    for f in all_findings:
        # Wayback param findings carry evidence with newline-separated URLs
        if f.type == "osint" and "parameter URL" in (f.title or ""):
            for line in (f.evidence or "").splitlines():
                m = _PARAM_URL_RE.search(line)
                if m:
                    _add(m.group(0))

        # Any finding whose evidence is a URL with params
        if f.evidence:
            m = _PARAM_URL_RE.search(f.evidence)
            if m:
                _add(m.group(0))

        # Dirscan/endpoint titles like "[200] /page.php?id=1"
        if f.type in ("endpoint", "web") and f.title:
            m = _PARAM_URL_RE.search(f.title)
            if m:
                _add(m.group(0))

    # Direct target URL if it has parameters
    if "?" in target:
        _add(target if target.startswith("http") else f"http://{target}")

    return urls[:max_urls]


# ── sqlmap runner ─────────────────────────────────────────────────────────────

def _run_sqlmap(
    url: str,
    output_dir: str,
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> tuple[str, str]:
    """Run sqlmap, return (stdout, stderr)."""
    cmd = [
        "sqlmap",
        "--url", url,
        "--batch",              # non-interactive
        "--level", "1",         # safe: basic injection tests only
        "--risk", "1",          # safe: no heavy/destructive payloads
        "--technique", "BEUST", # Boolean, Error, Union, Stacked, Time-based
        "--random-agent",
        "--timeout", "15",
        "--retries", "1",
        "--threads", "3",
        "--no-cast",
        "--flush-session",
        "--output-dir", output_dir,
        # Suppress interactive prompts
        "--answers", "crack=N,follow=N,quit=N,merge=N",
    ]
    if extra_args:
        cmd.extend(extra_args)

    rc, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if rc == -1:
        return "", stderr or "sqlmap timed out"
    return stdout, stderr


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_sqlmap(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    all_findings: list[Finding],
) -> ScanResult:
    """
    SQL Injection phase.
    Collects parametric URLs from previous findings, runs sqlmap on each.
    Only triggers for web / full scan types.
    """
    result = ScanResult()

    if scan_type not in ("web", "full", "ctf"):
        return result

    ctf_pattern = build_flag_pattern(getattr(ctx.scan, "ctf_flag_format", None)) if scan_type == "ctf" else None

    param_urls = _collect_param_urls(target, all_findings)

    if not param_urls:
        await ctx.log(
            "SQLmap: no parametric URLs found in previous findings — skipping",
            level="info",
            module="sqlmap",
        )
        return result

    await ctx.log(
        f"SQLmap: testing {len(param_urls)} parametric URL(s) for SQL injection",
        module="sqlmap",
    )

    # Unique temp dir per scan run
    output_dir = os.path.join(tempfile.gettempdir(), f"sqlmap_{uuid.uuid4().hex[:8]}")
    os.makedirs(output_dir, exist_ok=True)

    confirmed = 0

    for url in param_urls:
        await ctx.log(f"  SQLmap → {url[:100]}", module="sqlmap")

        stdout, stderr = _run_sqlmap(url, output_dir)

        if stderr and "timed out" in stderr:
            await ctx.log(f"  SQLmap timeout on {url[:80]}", level="warning", module="sqlmap")
            result.errors.append(f"sqlmap timeout: {url[:80]}")
            continue

        findings = _parse_sqlmap_output(stdout, url)

        if findings:
            confirmed += 1
            await ctx.log(
                f"  VULNERABLE: {url[:80]} — {len(findings)} injection point(s)",
                level="error",
                module="sqlmap",
            )
            result.findings.extend(findings)
            # CTF: search for flag in sqlmap dump output
            if ctf_pattern:
                for flag in search_flags_decoded(stdout, ctf_pattern):
                    result.findings.append(Finding(
                        type="flag",
                        title=f"FLAG CAPTURED via SQLi: {flag}",
                        severity="critical",
                        description=f"Flag found in SQLmap dump output.\nURL: {url}\nFlag: {flag}",
                        evidence=f"flag={flag} url={url}",
                        cvss_score=10.0,
                    ))
        else:
            await ctx.log(f"  Not vulnerable: {url[:80]}", level="info", module="sqlmap")

    await ctx.log(
        f"SQLmap complete: {confirmed}/{len(param_urls)} URL(s) vulnerable, "
        f"{len(result.findings)} injection point(s) found",
        level="warning" if confirmed else "success",
        module="sqlmap",
    )
    return result
