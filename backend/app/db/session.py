import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

_worker_mode = bool(os.getenv("CELERY_WORKER"))

# Celery prefork workers call asyncio.run() per task, creating a new event loop
# each time. asyncpg futures are loop-bound, so a shared pool causes
# "Future attached to a different loop". NullPool avoids this by never reusing
# connections across asyncio.run() boundaries.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.APP_ENV == "development",
    pool_pre_ping=not _worker_mode,
    **({} if _worker_mode else {"pool_size": 10, "max_overflow": 20}),
    **({"poolclass": NullPool} if _worker_mode else {}),
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
