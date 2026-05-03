from celery import Celery

from app.core.config import settings

celery = Celery(
    "bughunt",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.scan", "app.tasks.report"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.scan.*": {"queue": "scans"},
    },
)
