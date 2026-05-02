from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import router as api_router
from app.api.v1.routers.ws import router as ws_router
from app.core.config import settings
from app.core.redis import close_redis, get_redis

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("starting up", env=settings.APP_ENV)
    await get_redis()
    yield
    # Shutdown
    logger.info("shutting down")
    await close_redis()


app = FastAPI(
    title="BugHunt API",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ws_router)


@app.get("/health", tags=["system"])
async def health():
    redis = await get_redis()
    redis_ok = await redis.ping()
    return {
        "status": "ok",
        "redis": "ok" if redis_ok else "error",
    }
