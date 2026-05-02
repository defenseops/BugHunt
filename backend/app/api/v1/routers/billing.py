from fastapi import APIRouter

router = APIRouter(prefix="/billing", tags=["billing"])


@router.get("/status")
async def billing_status():
    # Шаг 11.3
    return {"detail": "not implemented"}


@router.post("/kaspi/create")
async def kaspi_create():
    # Шаг 11.1
    return {"detail": "not implemented"}


@router.post("/kaspi/webhook")
async def kaspi_webhook():
    return {"detail": "not implemented"}


@router.post("/stripe/create-checkout")
async def stripe_create_checkout():
    # Шаг 11.2
    return {"detail": "not implemented"}


@router.post("/stripe/webhook")
async def stripe_webhook():
    return {"detail": "not implemented"}
