"""
PDF report generation task — Phase 10.
Loads scan + findings from DB, renders Jinja2 template, converts to PDF via WeasyPrint.
"""
import asyncio
import os
import uuid
from pathlib import Path

from app.worker import celery

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/app/reports"))


@celery.task(name="app.tasks.report.generate_pdf", bind=True, max_retries=2)
def generate_pdf(self, report_id: str, scan_id: str, lang: str) -> dict:
    import asyncio

    from app.db.session import AsyncSessionLocal
    from app.models.report import Report
    from sqlalchemy import select

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
                pdf_path = await _build_pdf(db, report_id, scan_id, lang)
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


async def _build_pdf(db, report_id: str, scan_id: str, lang: str) -> Path:
    from sqlalchemy import select

    from app.models.scan import Scan
    from app.models.scan_finding import ScanFinding
    from app.models.user import User
    from app.reports.generator import build_report_context, render_html, render_pdf

    scan_result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = scan_result.scalar_one()

    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_id == uuid.UUID(scan_id))
    )
    findings = findings_result.scalars().all()

    user = None
    if scan.user_id:
        user_result = await db.execute(select(User).where(User.id == scan.user_id))
        user = user_result.scalar_one_or_none()

    context = build_report_context(scan, findings, user, lang)
    html = render_html(context)

    out = REPORTS_DIR / f"{report_id}_{lang}.pdf"
    return render_pdf(html, out)
