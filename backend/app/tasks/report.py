"""
PDF report generation task.
Full WeasyPrint implementation — Phase 10.
This stub updates DB status so the API reflects the correct state.
"""
import os
import uuid
from pathlib import Path

from app.worker import celery

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/app/reports"))


@celery.task(name="app.tasks.report.generate_pdf", bind=True, max_retries=2)
def generate_pdf(self, report_id: str, scan_id: str, lang: str) -> dict:
    from app.db.session import AsyncSessionLocal
    from app.models.report import Report
    from sqlalchemy import select
    import asyncio

    async def _run() -> None:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Report).where(Report.id == uuid.UUID(report_id))
            )
            report = result.scalar_one_or_none()
            if not report:
                return

            report.status = "generating"
            await db.commit()

            try:
                pdf_path = _build_pdf(report_id, scan_id, lang)
                report.pdf_path = str(pdf_path)
                report.file_size = pdf_path.stat().st_size
                report.status = "ready"
            except Exception as exc:
                report.status = "failed"
                raise self.retry(exc=exc, countdown=10)
            finally:
                await db.commit()

    asyncio.run(_run())
    return {"report_id": report_id, "status": "ready"}


def _build_pdf(report_id: str, scan_id: str, lang: str) -> Path:
    """
    Phase 10 — replace with WeasyPrint rendering.
    Currently writes a minimal placeholder so the file exists.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / f"{report_id}_{lang}.pdf"

    # Minimal valid PDF so download endpoint can stream something real
    placeholder = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R"
        b"/Resources<<>>/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 44>>\nstream\n"
        b"BT /F1 14 Tf 72 720 Td (PentraScan Report) Tj ET\n"
        b"endstream\nendobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f \n"
        b"trailer<</Size 5/Root 1 0 R>>\n"
        b"startxref\n9\n%%EOF\n"
    )
    out.write_bytes(placeholder)
    return out
