from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_current_user
from app.core.redis import get_redis
from app.core.security import (
    TOKEN_TYPE_REFRESH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.subscription import Subscription
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])

bearer = HTTPBearer(auto_error=False)


# ── helpers ────────────────────────────────────────────────────────────────

async def _get_active_tier(db: AsyncSession, user_id) -> str:
    """Return user's active subscription tier (free / pro / enterprise)."""
    result = await db.execute(
        select(Subscription)
        .where(
            Subscription.user_id == user_id,
            Subscription.status == "active",
        )
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    sub = result.scalar_one_or_none()
    if sub is None:
        return "free"
    return sub.plan  # "free" | "pro" | "enterprise"


def _build_user_out(user: User, tier: str) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        subscription_tier=tier,  # type: ignore[arg-type]
    )


async def _create_free_subscription(db: AsyncSession, user: User) -> None:
    sub = Subscription(
        user_id=user.id,
        plan="free",
        status="active",
        expires_at=None,
    )
    db.add(sub)


# ── register ───────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check duplicate email
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        role="user",
        is_active=True,
    )
    db.add(user)
    await db.flush()  # get user.id before commit

    await _create_free_subscription(db, user)
    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(str(user.id))
    refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=_build_user_out(user, "free"),
    )


# ── login ──────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not user.password_hash or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account disabled",
        )

    tier = await _get_active_tier(db, user.id)
    access_token = create_access_token(str(user.id))
    refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=_build_user_out(user, tier),
    )


# ── refresh ────────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )
    try:
        payload = decode_token(body.refresh_token)
    except JWTError:
        raise exc

    if payload.get("type") != TOKEN_TYPE_REFRESH:
        raise exc

    # Check blacklist
    redis = await get_redis()
    if await redis.exists(f"bl:{body.refresh_token}"):
        raise exc

    import uuid as _uuid
    result = await db.execute(select(User).where(User.id == _uuid.UUID(payload["sub"])))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise exc

    tier = await _get_active_tier(db, user.id)
    new_access = create_access_token(str(user.id))
    new_refresh = create_refresh_token(str(user.id))

    # Invalidate used refresh token
    exp = payload.get("exp", 0)
    ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
    await redis.setex(f"bl:{body.refresh_token}", ttl, "1")

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        user=_build_user_out(user, tier),
    )


# ── logout ─────────────────────────────────────────────────────────────────

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    body: RefreshRequest | None = None,
):
    redis = await get_redis()

    if credentials:
        token = credentials.credentials
        try:
            payload = decode_token(token)
            exp = payload.get("exp", 0)
            ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
            await redis.setex(f"bl:{token}", ttl, "1")
        except JWTError:
            pass  # already expired — nothing to blacklist

    if body and body.refresh_token:
        try:
            payload = decode_token(body.refresh_token)
            exp = payload.get("exp", 0)
            ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
            await redis.setex(f"bl:{body.refresh_token}", ttl, "1")
        except JWTError:
            pass


# ── me ─────────────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserOut)
async def get_me(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    tier = await _get_active_tier(db, user.id)
    return _build_user_out(user, tier)


# ── Google OAuth (stub for Step 2.3) ──────────────────────────────────────

@router.get("/google")
async def google_login():
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Google OAuth not configured")
    return {"detail": "not implemented"}


@router.get("/google/callback")
async def google_callback():
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Google OAuth not configured")
