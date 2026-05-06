from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.logging import configure_logging
configure_logging()

from app.limiter import limiter
from app.api.v1.router import router as api_router
from app.api.v1.routers.ws import router as ws_router
from app.core.config import settings
from app.core.redis import close_redis, get_redis

logger = structlog.get_logger()


def _run_migrations() -> None:
    """Apply pending Alembic migrations on startup."""
    try:
        from alembic.config import Config
        from alembic import command
        import os
        alembic_ini = os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
        cfg = Config(alembic_ini)
        command.upgrade(cfg, "head")
        logger.info("alembic migrations applied")
    except Exception as exc:
        logger.warning("alembic migration failed", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting up", env=settings.APP_ENV)
    _run_migrations()
    await get_redis()
    yield
    logger.info("shutting down")
    await close_redis()


app = FastAPI(
    title="PentraScan API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global error handlers ─────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    structlog.get_logger().error(
        "unhandled_exception",
        method=request.method,
        path=request.url.path,
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": str(exc)},
    )

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(api_router)
app.include_router(ws_router)

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health():
    redis = await get_redis()
    redis_ok = await redis.ping()
    return {
        "status": "ok",
        "version": "1.0.0",
        "redis": "ok" if redis_ok else "error",
    }
