import asyncio

from redis.asyncio import Redis, from_url

from app.core.config import settings

_redis: Redis | None = None
_redis_loop: asyncio.AbstractEventLoop | None = None


async def get_redis() -> Redis:
    global _redis, _redis_loop

    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    # Re-create if no client yet, or if the event loop changed (new asyncio.run() call
    # in a Celery worker creates a fresh loop — the old client is unusable on it).
    if _redis is None or _redis_loop is not current_loop:
        if _redis is not None:
            try:
                await _redis.aclose()
            except Exception:
                pass
        _redis = await from_url(settings.REDIS_URL, decode_responses=True)
        _redis_loop = current_loop

    return _redis


async def close_redis() -> None:
    global _redis, _redis_loop
    if _redis:
        await _redis.aclose()
        _redis = None
        _redis_loop = None
