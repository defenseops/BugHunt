from datetime import datetime
from pydantic import BaseModel


class BillingStatusOut(BaseModel):
    plan: str                   # free | pro | enterprise
    status: str                 # active | expired | cancelled | none
    expires_at: datetime | None
    payment_provider: str | None


class KaspiCreateOut(BaseModel):
    payment_url: str
    order_id: str


class StripeCreateOut(BaseModel):
    checkout_url: str
    session_id: str
