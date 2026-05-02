from fastapi import APIRouter

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("")
async def list_scans():
    # Шаг 3.5
    return {"detail": "not implemented"}


@router.post("")
async def create_scan():
    # Шаг 3.2
    return {"detail": "not implemented"}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    return {"detail": "not implemented"}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    return {"detail": "not implemented"}
