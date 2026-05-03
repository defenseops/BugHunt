from fastapi import APIRouter

from app.api.v1.routers import auth, users, scans, reports, admin, billing, ddos

router = APIRouter(prefix="/api/v1")

router.include_router(auth.router)
router.include_router(users.router)
router.include_router(scans.router)
router.include_router(reports.router)
router.include_router(admin.router)
router.include_router(billing.router)
router.include_router(ddos.router)
