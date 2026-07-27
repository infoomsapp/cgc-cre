from fastapi import APIRouter
from app.api.v1.endpoints.verify import router as verify_router
from app.api.v1.endpoints.govern import router as govern_router

router = APIRouter()
router.include_router(verify_router, prefix="/verify", tags=["Forensic Audit"])
router.include_router(govern_router, prefix="/govern", tags=["Governance"])