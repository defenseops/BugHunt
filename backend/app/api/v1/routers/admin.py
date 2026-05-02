from fastapi import APIRouter

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
async def list_users():
    # Шаг 12.1
    return {"detail": "not implemented"}


@router.patch("/users/{user_id}")
async def update_user(user_id: str):
    return {"detail": "not implemented"}


@router.get("/scans")
async def list_all_scans():
    # Шаг 12.2
    return {"detail": "not implemented"}


@router.get("/stats")
async def get_stats():
    # Шаг 12.3
    return {"detail": "not implemented"}
