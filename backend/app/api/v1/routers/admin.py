import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_admin
from app.db.session import get_db
from app.models.report import Report
from app.models.scan import Scan
from app.models.subscription import Subscription
from app.models.user import User
from app.schemas.admin import (
    AdminScanListOut,
    AdminScanOut,
    AdminUpdateUserRequest,
    AdminUserListOut,
    AdminUserOut,
    StatsOut,
)

router = APIRouter(prefix="/admin", tags=["admin"])


async def _get_user_tier(db: AsyncSession, user_id: uuid.UUID) -> str:
    result = await db.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id, Subscription.status == "active")
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    sub = result.scalar_one_or_none()
    return sub.plan if sub else "free"


# ── users ──────────────────────────────────────────────────────────────────

@router.get("/users", response_model=AdminUserListOut)
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    search: str | None = Query(None),
    plan: str | None = Query(None),
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(User)
    if search:
        q = q.where(User.email.ilike(f"%{search}%"))

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()

    users_result = await db.execute(
        q.order_by(User.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    users = users_result.scalars().all()

    items = []
    for u in users:
        tier = await _get_user_tier(db, u.id)
        if plan and tier != plan:
            continue
        items.append(AdminUserOut(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
            subscription_tier=tier,
        ))

    return AdminUserListOut(items=items, total=total, page=page, limit=limit)


@router.patch("/users/{user_id}", response_model=AdminUserOut)
async def update_user(
    user_id: uuid.UUID,
    body: AdminUpdateUserRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Prevent admin from locking themselves out
    if user.id == admin.id and body.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    if body.is_active is not None:
        user.is_active = body.is_active
    if body.role is not None:
        user.role = body.role
    if body.plan is not None:
        # Deactivate existing active subscriptions
        old = await db.execute(
            select(Subscription).where(
                Subscription.user_id == user.id,
                Subscription.status == "active",
            )
        )
        for sub in old.scalars().all():
            sub.status = "cancelled"
        if body.plan == "pro":
            db.add(Subscription(
                user_id=user.id,
                plan="pro",
                status="active",
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
                payment_provider="admin",
                payment_id=f"admin-grant-{uuid.uuid4().hex[:8]}",
            ))

    await db.commit()
    await db.refresh(user)

    tier = await _get_user_tier(db, user.id)
    return AdminUserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        subscription_tier=tier,
    )


# ── scans ──────────────────────────────────────────────────────────────────

@router.get("/scans", response_model=AdminScanListOut)
async def list_all_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(Scan, User.email).join(User, Scan.user_id == User.id)
    if status_filter:
        q = q.where(Scan.status == status_filter)

    total = (
        await db.execute(select(func.count()).select_from(select(Scan).subquery()))
    ).scalar_one()

    rows = await db.execute(
        q.order_by(Scan.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )

    items = [
        AdminScanOut(
            id=scan.id,
            user_id=scan.user_id,
            user_email=email,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
        )
        for scan, email in rows.all()
    ]

    return AdminScanListOut(items=items, total=total, page=page, limit=limit)


# ── stats ──────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=StatsOut)
async def get_stats(
    _admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    async def count(model, *where):
        q = select(func.count()).select_from(model)
        for cond in where:
            q = q.where(cond)
        return (await db.execute(q)).scalar_one()

    # Active users = logged in last 30 days → approximate as is_active=True for now
    total_users     = await count(User)
    active_users    = await count(User, User.is_active == True)   # noqa: E712
    pro_subs        = await count(Subscription, Subscription.plan != "free", Subscription.status == "active")
    total_scans     = await count(Scan)
    running_scans   = await count(Scan, Scan.status == "running")
    completed_scans = await count(Scan, Scan.status == "completed")
    failed_scans    = await count(Scan, Scan.status == "failed")
    total_reports   = await count(Report)

    return StatsOut(
        total_users=total_users,
        active_users=active_users,
        pro_users=pro_subs,
        total_scans=total_scans,
        running_scans=running_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        total_reports=total_reports,
    )


# ── system logs ────────────────────────────────────────────────────────────

@router.get("/logs", tags=["admin"])
async def get_system_logs(
    lines: int = Query(100, ge=1, le=1000),
    level: str = Query("ERROR", description="Minimum log level to show"),
    _admin: User = Depends(get_current_admin),
):
    """Return last N lines from the error log file."""
    log_path = Path(os.getenv("LOG_DIR", "/app/logs")) / "errors.log"
    if not log_path.exists():
        return {"lines": [], "path": str(log_path), "total": 0}

    try:
        content = log_path.read_text(errors="replace")
        all_lines = content.splitlines()
        tail = all_lines[-lines:]
        return {"lines": tail, "path": str(log_path), "total": len(all_lines)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read log: {exc}")
