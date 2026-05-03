from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.core.security import hash_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import UserOut
from app.schemas.user import UpdateMeRequest
from app.api.v1.routers.auth import _build_user_out, _get_active_tier

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def get_me(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    tier = await _get_active_tier(db, user.id)
    return _build_user_out(user, tier)


@router.patch("/me", response_model=UserOut)
async def update_me(
    body: UpdateMeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.password is not None:
        user.password_hash = hash_password(body.password)

    await db.commit()
    await db.refresh(user)

    tier = await _get_active_tier(db, user.id)
    return _build_user_out(user, tier)
