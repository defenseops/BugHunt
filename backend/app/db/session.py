import asyncio
import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

_worker_mode = bool(os.getenv("CELERY_WORKER"))

if _worker_mode:
    # Celery workers: fresh engine per asyncio.run() call so asyncpg connections
    # are always bound to the current event loop. Avoids both
    # "Future attached to a different loop" and "Event loop is closed".
    _worker_engine = None
    _worker_loop: asyncio.AbstractEventLoop | None = None
    _worker_session_factory = None

    def _get_worker_session_factory():
        global _worker_engine, _worker_loop, _worker_session_factory
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if _worker_session_factory is None or _worker_loop is not current_loop:
            _worker_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
            _worker_session_factory = async_sessionmaker(
                _worker_engine, class_=AsyncSession, expire_on_commit=False
            )
            _worker_loop = current_loop

        return _worker_session_factory

    class _WorkerSessionProxy:
        """Proxy that always returns a session from the current loop's factory."""
        def __call__(self):
            return _get_worker_session_factory()()

    AsyncSessionLocal = _WorkerSessionProxy()
    engine = None  # not used in worker mode

else:
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.APP_ENV == "development",
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )
    AsyncSessionLocal = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
