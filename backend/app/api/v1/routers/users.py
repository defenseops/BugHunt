from fastapi import APIRouter

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me")
async def get_me():
    # Шаг 3.1
    return {"detail": "not implemented"}


@router.patch("/me")
async def update_me():
    return {"detail": "not implemented"}
