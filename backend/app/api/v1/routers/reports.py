from fastapi import APIRouter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/{scan_id}/generate")
async def generate_report(scan_id: str, lang: str = "ru"):
    # Шаг 10.5
    return {"detail": "not implemented"}


@router.get("/{scan_id}/download")
async def download_report(scan_id: str, lang: str = "ru"):
    return {"detail": "not implemented"}
