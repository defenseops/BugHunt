import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ReportOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    lang: str
    status: str          # pending | generating | ready | failed
    file_size: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class GenerateReportRequest(BaseModel):
    lang: Literal["ru", "en"] = "ru"
