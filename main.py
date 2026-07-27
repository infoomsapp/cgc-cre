"""
CGC Core — FastAPI Application
AI Governance Engine: Proof-of-Decision + Judge Layer Agnóstico

Olympus Mont Systems LLC © 2026
"""

import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] [%(levelname)s] %(message)s"
)
logger = logging.getLogger("cgc.main")


# ============================================================================
# LIFESPAN — startup / shutdown
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """App startup: verify DB connection and create partitions."""
    logger.info("CGC Core starting up...")

    # Ensure Supabase partitions exist for current + next month
    try:
        import asyncpg
        conn = await asyncpg.connect(os.getenv("CGC_DATABASE_URL"))
        await conn.execute("SELECT cgc_ensure_partition(NOW())")
        await conn.execute("SELECT cgc_ensure_partition(NOW() + INTERVAL '1 month')")
        await conn.close()
        logger.info("Partitions verified OK")
    except Exception as e:
        logger.warning(f"Partition check failed (non-fatal): {e}")

    # Warm up db_loader cache
    try:
        from app.Core.db.cgc_db_loader import get_db_loader
        loader = get_db_loader()
        health = loader.health_check()
        logger.info(f"DB Loader: {health}")
    except Exception as e:
        logger.warning(f"DB Loader warmup failed: {e}")

    yield  # app runs here

    logger.info("CGC Core shutting down...")

    # Close asyncpg pool
    try:
        from app.modules.pod.pod_repository import close_pool
        await close_pool()
    except Exception:
        pass


# ============================================================================
# APP
# ============================================================================

app = FastAPI(
    title="CGC Core — AI Governance Engine",
    description="""
## CGC Core v2.0

**Proof-of-Decision (PoD):** Cryptographic non-repudiation of every AI decision.

**Judge Layer Agnóstico (JLA):** Provider-agnostic governance middleware.

### Key endpoints
- `GET /api/v1/verify/{decision_id}` — Forensic proof for any AI decision
- `GET /api/v1/verify/chain/integrity` — Full PoD chain verification
- `POST /api/v1/govern` — Submit a decision for governance
- `GET /health` — System health

*OlympusMont Systems LLC © 2025*
    """,
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS — adjust origins for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CGC_CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# GLOBAL ERROR HANDLER
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "path": str(request.url)
        }
    )


# ============================================================================
# ROUTES
# ============================================================================

from app.api.v1.router import router as v1_router
app.include_router(v1_router, prefix="/api/v1")


@app.get("/health", tags=["System"], summary="System health check")
async def health():
    """
    Returns DB connectivity, cache status, and module versions.
    Use this to verify the deployment is working correctly.
    """
    from app.Core.db.cgc_db_loader import get_db_loader
    db_health = get_db_loader().health_check()

    return {
        "status": "OK" if db_health.get("status") == "OK" else "DEGRADED",
        "version": "2.0.0",
        "db": db_health,
        "modules": {
            "pod":            "active",
            "jla":            "active",
            "compliance":     "active",
        }
    }