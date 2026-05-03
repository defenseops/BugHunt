import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.report import GenerateReportRequest, ReportOut

router = APIRouter(prefix="/reports", tags=["reports"])


async def _get_completed_scan(
    db: AsyncSession, scan_id: uuid.UUID, user_id: uuid.UUID
) -> Scan:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not completed yet (status: {scan.status})",
        )
    return scan


# ── generate ───────────────────────────────────────────────────────────────

@router.post("/{scan_id}/generate", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
async def generate_report(
    scan_id: uuid.UUID,
    body: GenerateReportRequest = Depends(),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _get_completed_scan(db, scan_id, user.id)

    # Re-use existing report for same scan+lang if not failed
    existing = await db.execute(
        select(Report).where(
            Report.scan_id == scan_id,
            Report.lang == body.lang,
            Report.status != "failed",
        )
    )
    report = existing.scalar_one_or_none()

    if report and report.status in ("pending", "generating", "ready"):
        return report

    # Create new report record
    report = Report(
        scan_id=scan_id,
        lang=body.lang,
        status="pending",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Dispatch Celery task
    from app.tasks.report import generate_pdf  # noqa: PLC0415
    generate_pdf.delay(str(report.id), str(scan_id), body.lang)

    return report


# ── download ───────────────────────────────────────────────────────────────

@router.get("/{scan_id}/download")
async def download_report(
    scan_id: uuid.UUID,
    lang: str = Query("ru", pattern="^(ru|en)$"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Ownership check (scan doesn't have to be completed for download lookup)
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    result = await db.execute(
        select(Report).where(
            Report.scan_id == scan_id,
            Report.lang == lang,
            Report.status == "ready",
        )
    )
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not ready. Generate it first via POST /reports/{scan_id}/generate",
        )

    pdf_path = Path(report.pdf_path)
    if not pdf_path.exists():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Report file missing from disk. Please regenerate.",
        )

    filename = f"pentrascan_{scan_id}_{lang}.pdf"
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── list reports for scan ──────────────────────────────────────────────────

@router.get("/{scan_id}", response_model=list[ReportOut])
async def list_reports(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    result = await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id)
        .order_by(Report.created_at.desc())
    )
    return result.scalars().all()
