from celery import Celery
from app.core.config import settings

celery = Celery(
    "bughunt",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery.conf.task_routes = {
    "app.tasks.scan.*": {"queue": "scans"},
}
