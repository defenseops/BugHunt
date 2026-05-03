import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.subscription import Subscription
from app.models.user import User
from app.schemas.billing import BillingStatusOut, KaspiCreateOut, StripeCreateOut

router = APIRouter(prefix="/billing", tags=["billing"])


async def _get_active_sub(db: AsyncSession, user_id: uuid.UUID) -> Subscription | None:
    result = await db.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id, Subscription.status == "active")
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _activate_pro(db: AsyncSession, user: User, provider: str, payment_id: str) -> None:
    """Upgrade user to pro: deactivate old subs, create new active pro sub."""
    old = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.status == "active",
        )
    )
    for sub in old.scalars().all():
        sub.status = "cancelled"

    pro_sub = Subscription(
        user_id=user.id,
        plan="pro",
        status="active",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        payment_provider=provider,
        payment_id=payment_id,
    )
    db.add(pro_sub)
    await db.commit()


# ── status ─────────────────────────────────────────────────────────────────

@router.get("/status", response_model=BillingStatusOut)
async def billing_status(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    sub = await _get_active_sub(db, user.id)
    if not sub:
        return BillingStatusOut(plan="free", status="none", expires_at=None, payment_provider=None)

    # Mark expired subs
    if sub.expires_at and sub.expires_at < datetime.now(timezone.utc):
        sub.status = "expired"
        await db.commit()
        return BillingStatusOut(plan="free", status="expired", expires_at=sub.expires_at, payment_provider=sub.payment_provider)

    return BillingStatusOut(
        plan=sub.plan,
        status=sub.status,
        expires_at=sub.expires_at,
        payment_provider=sub.payment_provider,
    )


# ── Kaspi Pay ──────────────────────────────────────────────────────────────

PRO_PRICE_KZT = 4990

@router.post("/kaspi/create", response_model=KaspiCreateOut)
async def kaspi_create(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not settings.KASPI_API_KEY or not settings.KASPI_MERCHANT_ID:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Kaspi Pay not configured")

    order_id = f"PS-{uuid.uuid4().hex[:12].upper()}"

    # Kaspi Pay payment link format (merchant redirect flow)
    payment_url = (
        f"https://pay.kaspi.kz/pay/82000000"
        f"?service={settings.KASPI_MERCHANT_ID}"
        f"&account={user.id}"
        f"&amount={PRO_PRICE_KZT}"
        f"&order={order_id}"
        f"&comment=PentraScan+Pro"
    )

    return KaspiCreateOut(payment_url=payment_url, order_id=order_id)


@router.post("/kaspi/webhook", status_code=status.HTTP_200_OK)
async def kaspi_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Kaspi sends a GET/POST with txn_id, account, sum, command.
    Verify and activate subscription.
    """
    body = await request.json()

    command   = body.get("command")
    account   = body.get("account")   # user.id
    txn_id    = body.get("txn_id")
    amount    = body.get("sum", 0)

    if command == "check":
        # Verify user exists
        try:
            uid = uuid.UUID(account)
        except (ValueError, TypeError):
            return {"txn_id": txn_id, "result": 1, "comment": "User not found"}

        result = await db.execute(select(User).where(User.id == uid, User.is_active == True))  # noqa: E712
        if not result.scalar_one_or_none():
            return {"txn_id": txn_id, "result": 1, "comment": "User not found"}
        return {"txn_id": txn_id, "result": 0, "comment": "OK"}

    if command == "pay":
        if float(amount) < PRO_PRICE_KZT:
            return {"txn_id": txn_id, "result": 2, "comment": "Insufficient amount"}

        try:
            uid = uuid.UUID(account)
        except (ValueError, TypeError):
            return {"txn_id": txn_id, "result": 1, "comment": "Bad account"}

        result = await db.execute(select(User).where(User.id == uid))
        user = result.scalar_one_or_none()
        if not user:
            return {"txn_id": txn_id, "result": 1, "comment": "User not found"}

        await _activate_pro(db, user, "kaspi", str(txn_id))
        return {"txn_id": txn_id, "result": 0, "comment": "Subscribed"}

    return {"txn_id": txn_id, "result": 0, "comment": "OK"}


# ── Stripe ─────────────────────────────────────────────────────────────────

@router.post("/stripe/create-checkout", response_model=StripeCreateOut)
async def stripe_create_checkout(
    user: User = Depends(get_current_user),
):
    if not settings.STRIPE_SECRET_KEY or not settings.STRIPE_PRO_PRICE_ID:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Stripe not configured")

    import stripe  # lazy import — stripe not in requirements yet
    stripe.api_key = settings.STRIPE_SECRET_KEY

    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": settings.STRIPE_PRO_PRICE_ID, "quantity": 1}],
        customer_email=user.email,
        client_reference_id=str(user.id),
        success_url=f"{settings.APP_URL}/dashboard/billing?success=1",
        cancel_url=f"{settings.APP_URL}/dashboard/billing?cancelled=1",
    )
    return StripeCreateOut(checkout_url=session.url, session_id=session.id)


@router.post("/stripe/webhook", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Stripe not configured")

    import stripe  # noqa: PLC0415
    stripe.api_key = settings.STRIPE_SECRET_KEY

    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid signature")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id_str = session.get("client_reference_id")
        if not user_id_str:
            return {"status": "ignored"}

        try:
            uid = uuid.UUID(user_id_str)
        except ValueError:
            return {"status": "ignored"}

        result = await db.execute(select(User).where(User.id == uid))
        user = result.scalar_one_or_none()
        if user:
            await _activate_pro(db, user, "stripe", session["id"])

    elif event["type"] in ("customer.subscription.deleted", "customer.subscription.paused"):
        # Downgrade to free on cancellation — find by Stripe subscription ID
        sub_id = event["data"]["object"]["id"]
        result = await db.execute(
            select(Subscription).where(
                Subscription.payment_id == sub_id,
                Subscription.payment_provider == "stripe",
            )
        )
        sub = result.scalar_one_or_none()
        if sub:
            sub.status = "cancelled"
            await db.commit()

    return {"status": "ok"}
