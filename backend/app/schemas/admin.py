import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr
from typing import Literal


class AdminUpdateUserRequest(BaseModel):
    is_active: bool | None = None
    role: Literal["user", "admin"] | None = None


class AdminUserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str | None
    role: str
    is_active: bool
    created_at: datetime
    subscription_tier: str

    model_config = {"from_attributes": True}


class AdminUserListOut(BaseModel):
    items: list[AdminUserOut]
    total: int
    page: int
    limit: int


class AdminScanOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    user_email: str
    target: str
    scan_type: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AdminScanListOut(BaseModel):
    items: list[AdminScanOut]
    total: int
    page: int
    limit: int


class StatsOut(BaseModel):
    total_users: int
    active_users: int
    pro_users: int
    total_scans: int
    running_scans: int
    completed_scans: int
    failed_scans: int
    total_reports: int
