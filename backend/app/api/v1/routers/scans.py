import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.scan import Scan
from app.models.subscription import Subscription
from app.models.user import User
from app.schemas.scan import CreateScanRequest, ScanDetailOut, ScanListOut, ScanOut

router = APIRouter(prefix="/scans", tags=["scans"])

FREE_SCAN_LIMIT = 3


# ── helpers ────────────────────────────────────────────────────────────────

async def _get_active_plan(db: AsyncSession, user_id: uuid.UUID) -> str:
    result = await db.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id, Subscription.status == "active")
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    sub = result.scalar_one_or_none()
    return sub.plan if sub else "free"


async def _count_all_scans(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Total scans ever created by user (counts towards free limit)."""
    result = await db.execute(
        select(func.count()).where(Scan.user_id == user_id)
    )
    return result.scalar_one()


async def _get_scan_or_404(db: AsyncSession, scan_id: uuid.UUID, user_id: uuid.UUID) -> Scan:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _enrich(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        current_phase=scan.current_phase,
        error_message=scan.error_message,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
        findings_count=len(scan.findings) if scan.findings else 0,
    )


# ── list ───────────────────────────────────────────────────────────────────

@router.get("", response_model=ScanListOut)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * limit

    q = select(Scan).where(Scan.user_id == user.id)
    if status_filter:
        q = q.where(Scan.status == status_filter)

    total_result = await db.execute(
        select(func.count()).select_from(q.subquery())
    )
    total = total_result.scalar_one()

    scans_result = await db.execute(
        q.order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    )
    scans = scans_result.scalars().all()

    return ScanListOut(
        items=[_enrich(s) for s in scans],
        total=total,
        page=page,
        limit=limit,
    )


# ── create ─────────────────────────────────────────────────────────────────

@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: CreateScanRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    plan = await _get_active_plan(db, user.id)

    if plan == "free":
        used = await _count_all_scans(db, user.id)
        if used >= FREE_SCAN_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=(
                    f"Free plan limit reached ({FREE_SCAN_LIMIT} scans lifetime). "
                    "Upgrade to Pro to run unlimited scans."
                ),
            )

    scan = Scan(
        user_id=user.id,
        target=body.target,
        scan_type=body.scan_type,
        mode="auto",
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Dispatch Celery task (imported lazily to avoid circular import)
    from app.tasks.scan import run_scan  # noqa: PLC0415
    run_scan.delay(str(scan.id))

    return _enrich(scan)


# ── get ────────────────────────────────────────────────────────────────────

@router.get("/{scan_id}", response_model=ScanDetailOut)
async def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id, Scan.user_id == user.id)
        .options(selectinload(Scan.findings))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return ScanDetailOut(
        **_enrich(scan).model_dump(),
        findings=scan.findings,
    )


# ── delete ─────────────────────────────────────────────────────────────────

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = await _get_scan_or_404(db, scan_id, user.id)

    if scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete a running scan. Wait for it to finish or it will time out.",
        )

    await db.delete(scan)
    await db.commit()
