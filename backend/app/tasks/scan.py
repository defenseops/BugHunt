from app.worker import celery


@celery.task(name="app.tasks.scan.run_scan", bind=True, max_retries=0)
def run_scan(self, scan_id: str) -> dict:
    # Фаза 4 — реализация модуля разведки
    return {"scan_id": scan_id, "status": "not implemented"}
