from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
async def register():
    # Шаг 2.1
    return {"detail": "not implemented"}


@router.post("/login")
async def login():
    # Шаг 2.2
    return {"detail": "not implemented"}


@router.post("/refresh")
async def refresh():
    return {"detail": "not implemented"}


@router.post("/logout")
async def logout():
    return {"detail": "not implemented"}


@router.get("/google")
async def google_login():
    # Шаг 2.3
    return {"detail": "not implemented"}


@router.get("/google/callback")
async def google_callback():
    return {"detail": "not implemented"}
