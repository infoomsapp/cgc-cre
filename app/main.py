"""
CGC CORE - Enterprise API Gateway (v2.2.2)
Python 3.13.1+ | Unified Governance Engine
Strictly Production | Olympus Mont Systems LLC  2026
"""

import asyncio
import os
import io
import json
import base64
import secrets
from datetime import datetime, timezone, timedelta
from typing import Annotated, Any, Final, Optional, Dict, List
from time import perf_counter_ns

from fastapi import FastAPI, Depends, Request, Header, status, Form
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, ConfigDict
from fastapi.staticfiles import StaticFiles
from fastapi import HTTPException
from pathlib import Path

# CGC CORE - Unified Governance System
from app.Core.tenant.multi_tenant import tenant_manager
from app.modules.compliance.compliance_engine import ComplianceEngine
from app.Core.db.database import get_database
from app.Core.auth.auth_system import AuthSystem
from app.Core.config import config
from app.Core.logging import logging_config

# Core Governance Modules
from app.modules.prefilter.PreFilter import PreFilter, Agent, EnforcementContext
from app.modules.scm.scmmodule import SCM
from app.modules.ecm.ecmmodule import ECM
from app.modules.pfm.pfmmodule import PFM
from app.modules.pan.panmodule import PAN
from app.modules.sda.sdamodule import SDA
from app.modules.tco.tcomodule import TCO
from app.modules.loop.cgc_loop import LOOP
from app.modules.pod.pod_interceptor_v2 import PoDInterceptor

# Forensic verify router (PoD chain integrity + per-decision proof).
from api.v1.endpoints.verify import router as verify_router

# Application monitoring router (LedgiProof + LedgiProof Tax Pro client error reports).
from api.v1.endpoints.monitor import router as monitor_router, ALLOWED_APP_SOURCES

# Type Aliases (Python 3.12+)
type AuditHash = str
type SentinelResponse = Dict[str, Any]

import logging
logger = logging.getLogger("cgc.main")

class CGCCoreEngine(FastAPI):
    """Production FastAPI extension with pre-heated connection pools + PreFilter."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.db = get_database()
        self.auth = AuthSystem()

        # ====================================================================
        # CGC GOVERNANCE MODULES - Unified System
        # ====================================================================

        # First Layer: PreFilter
        self.prefilter = PreFilter()

        # Security & Cryptographic Module
        self.scm = SCM()

        # Core Governance Modules
        self.ecm = ECM()
        self.pfm = PFM()
        self.pan = PAN()
        self.sda = SDA()
        self.tco = TCO()

        # Orchestration & Compliance
        self.cgc_loop = LOOP()
        self.compliance_engine = ComplianceEngine(self.scm, self.tco) if self.scm and self.tco else None

        # Proof-of-Decision: pre-delivery cryptographic non-repudiation.
        # Instantiation itself never touches the DB (persistence is lazy,
        # per-call), so this can't block startup -- guarded anyway per the
        # cgc_jla-outage lesson: nothing new added to __init__ goes in bare.
        try:
            self.pod = PoDInterceptor(signing_key_id="cgc-pod-v1")
        except Exception as e:
            logger.warning(f"[PoD] Interceptor init failed (non-fatal, decisions proceed unsealed): {e}")
            self.pod = None


app = CGCCoreEngine(
    title="CGC CORE - Enterprise Governance Gateway",
    version="2.2.2",
    root_path="/api/v1",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Mount the forensic verify router → /verify/{decision_id} and /verify/chain/integrity
app.include_router(verify_router, prefix="/verify", tags=["Forensic Audit"])

security = HTTPBearer()

# CGC AUTH (PRODUCTION READY)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_info = app.auth.verify_token(credentials.credentials)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user_info

async def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user

# Mount the application-monitoring router → /monitor/error, /monitor/errors, ...
# Same Bearer-token auth as every other authenticated endpoint, enforced here
# at the router level so monitor.py itself carries no auth logic.
app.include_router(
    monitor_router, prefix="/monitor", tags=["Monitoring"],
    dependencies=[Depends(get_current_user)]
)

# PreFilter Helper
async def run_cgc_prefilter(
    org_id: str,
    user_email: str,
    action: str,
    data_domains: List[str],
    user: Dict[str, Any]
) -> Any:
    """Ejecutar CGC-PreFilter."""

    # AuthSystem.verify_token() only ever returns {"email", "role"} (a single
    # string, confirmed in auth_system.py) -- .get("roles", ...) here was
    # checking a key that never exists, always silently falling back.
    user_roles = [user.get("role", "user")]

    # PreFilter.evaluate() requires a registered Agent (id/roles/scopes/
    # owners/capabilities) to check RBAC/scopes against -- confirmed via
    # full repo search that no agent registry exists anywhere (no DB table,
    # no lookup class, no auth-token field); Agent is otherwise only ever
    # constructed once, as demo data in PreFilter.py's __main__ block. This
    # endpoint has no agent_id in its request shape either. Synthesizing a
    # permissive per-request Agent that mirrors the caller's own already-
    # authenticated role is the only thing there's real data for -- it
    # makes agent_exists/user_rbac/scopes_exist trivially satisfied (agent
    # roles == user roles, requested_scopes is empty) without inventing new
    # access-control policy. A real agent registry, if this product ever
    # needs distinct per-agent permissions, is a separate feature to build.
    now_iso = datetime.now(timezone.utc).isoformat()
    agent = Agent(
        id=f"agent-{org_id}",
        name=f"{org_id} default agent",
        status="PRODUCTION",
        roles=user_roles,
        scopes=[],
        owners=[],
        capabilities=[],
        created_at=now_iso,
        updated_at=now_iso,
    )

    context = EnforcementContext(
        user_id=user.get("id", user_email),
        user_roles=user_roles,
        action=action,
        data_domains=data_domains,
        requested_scopes=[],
        correlation_id=f"corr_{secrets.token_hex(8)}"
    )

    # PREFILTER (ultra-fast <10ms)
    result = app.prefilter.evaluate(agent, context)

    # Save in DB for TCO
    app.db.save_prefilter_result(result.correlation_id, result.to_dict())

    return result

# =========================
# ENTERPRISE SENTINEL MONITORING
# =========================
@app.get("/status/nodes", tags=["Governance"])
async def get_sentinel_health(user=Depends(get_current_user)) -> JSONResponse:
    """Health check de todos los módulos de gobernanza."""
    results: Dict[str, SentinelResponse] = {}
    
    # PreFilter (First Layer)
    results["prefilter"] = app.prefilter.get_metrics()
    
    # Core Governance Modules
    if app.ecm:
        results["ecm"] = {"status": "active", "module": "EthicalCalibrationModule"}
    if app.pfm:
        results["pfm"] = {"status": "active", "module": "PredictiveFeedbackMechanism"}
    if app.pan:
        results["pan"] = {"status": "active", "module": "PerceptionAnalysisNode"}
    if app.sda:
        results["sda"] = {"status": "active", "module": "SmartDataAdvisor"}
    if app.tco:
        results["tco"] = {"status": "active", "module": "TraceabilityOversight"}
    if app.scm:
        results["scm"] = app.scm.get_metrics() if hasattr(app.scm, 'get_metrics') else {"status": "active"}
    
    # Compliance Engine
    if app.compliance_engine:
        results["compliance_engine"] = {"status": "active", "module": "ComplianceEngine"}

    return JSONResponse(
        content={"nodes": results, "integrity": "VERIFIED", "governance_system": "UNIFIED"},
        status_code=status.HTTP_200_OK
    )

# =========================
# CGC AUTH + ADMIN
# =========================
class SignUp(BaseModel):
    email: EmailStr
    password: str
    name: str = ""
    role: str = "user"
    model_config = ConfigDict(from_attributes=True)

class SignIn(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/signup", tags=["Auth"])
async def signup(data: SignUp):
    app.auth.create_user(data.email, data.password, data.name, data.role)
    return {"message": "User created successfully"}

@app.post("/auth/signin", tags=["Auth"])
async def signin(data: SignIn):
    token = app.auth.create_session_token(data.email, data.password)
    user_info = app.auth.verify_token(token)
    return {"access_token": token, "token_type": "bearer", "user": user_info}

@app.get("/admin/users", tags=["Admin"])
async def list_users(user=Depends(require_admin)):
    return app.auth.list_users()

# =========================
# BILLING + TENANT
# =========================
@app.post("/billing/upgrade", tags=["Billing"])
async def upgrade_plan(org_id: str = Form(...), plan: str = Form(...), user=Depends(get_current_user)):
    result = tenant_manager.upgrade_plan(org_id, plan)
    return result

@app.get("/billing/usage/{org_id}", tags=["Billing"])
async def get_usage(org_id: str, user=Depends(get_current_user)):
    tenant = tenant_manager.get_tenant(org_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant

# =========================
# PERFORMANCE TRACING
# =========================
@app.middleware("http")
async def trace_execution(request: Request, call_next: Any) -> Any:
    start_ns = perf_counter_ns()
    response = await call_next(request)
    duration_ns = perf_counter_ns() - start_ns
    response.headers["X-CGC-Process-Time-NS"] = str(duration_ns)
    response.headers["X-CGC-Version"] = "2.2.2"
    response.headers["X-CGC-PreFilter"] = "ENABLED"
    return response

# =========================
# HEALTH + GOVERNANCE
# =========================
@app.get("/health", tags=["System"])
async def health() -> Dict[str, Any]:
    """Liveness probe for Railway (railway.toml healthcheckPath = "/health").
    No auth, no DB dependency — just confirms the process is up and serving,
    which is all a deploy healthcheck should require."""
    return {"status": "ok", "version": "2.2.2"}

# Read once at import time -- a static bundled asset, not a runtime write,
# so this is safe on Vercel's read-only filesystem.
_DASHBOARD_HTML = (Path(__file__).parent / "static" / "dashboard.html").read_text(encoding="utf-8")

@app.get("/dashboard", tags=["System"], response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """CGC Core Monitoring Systems -- a self-contained static page (no
    server-side auth on the shell itself). It prompts for a Bearer token
    client-side and uses it to call the already-authenticated /monitor/*
    and /status/nodes JSON endpoints directly from the browser. Temporary
    home for this (v1) -- a dedicated page/app is the planned next step."""
    return HTMLResponse(content=_DASHBOARD_HTML)

@app.get("/", tags=["System"])
async def root() -> Dict[str, Any]:
    """Root endpoint con información del sistema unificado."""
    return {
        "engine": "CGC CORE v2.2.2 + UNIFIED GOVERNANCE",
        "compliance": "EU_AI_ACT_2025_COMPLIANT",
        "architecture": {
            "first_layer": "PreFilter",
            "security": "SCM",
            "core_modules": ["PAN", "ECM", "PFM", "SDA"],
            "audit": "TCO",
            "compliance": "ComplianceEngine"
        },
        "prefilter": app.prefilter.get_metrics(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# =========================
# GOVERNANCE ENDPOINTS
# =========================

@app.post("/governance/decision", tags=["Governance"])
async def execute_governance_decision(
    org_id: str = Form(...),
    action: str = Form(...),
    input_data: str = Form(...),
    user_email: str = Form(...),
    data_domains: str = Form(...),
    app_source: str = Form("unknown"),
    user=Depends(get_current_user)
) -> Dict[str, Any]:
    """Endpoint unificado para ejecutar decisiones de gobernanza."""
    start_time = perf_counter_ns()

    # Optional with a default (not Form(...)) so any existing caller not
    # yet sending it keeps working unbroken. Same naming convention as
    # /monitor/error's app_source, reused here rather than invented fresh.
    if app_source not in ALLOWED_APP_SOURCES:
        app_source = "unknown"

    try:
        input_dict = json.loads(input_data)
        domains_list = json.loads(data_domains)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

    # Proof-of-Decision: capture the input hash BEFORE the decision is made,
    # so the eventual proof can't be fabricated after the fact. Sealed once
    # the outcome (ALLOW or blocked) is known, further down.
    decision_id = f"dec_{secrets.token_hex(8)}"
    intercept_id = None
    if app.pod:
        try:
            intercept_id = app.pod.begin_intercept(
                decision_id=decision_id,
                tenant_id=org_id,
                model_identifier="cgc-governance/full-cycle/v2.2.2",
                input_payload={"action": action, "input_data": input_dict, "data_domains": domains_list}
            )
        except Exception as e:
            logger.warning(f"[PoD] begin_intercept failed (non-fatal): {e}")

    prefilter_result = await run_cgc_prefilter(
        org_id=org_id,
        user_email=user_email,
        action=action,
        data_domains=domains_list,
        user=user
    )

    if prefilter_result.outcome != "ALLOW":
        response = {
            "approved": False,
            "stage": "prefilter",
            "outcome": prefilter_result.outcome,
            "reason": prefilter_result.reason,
            "correlation_id": prefilter_result.correlation_id,
            "decision_id": decision_id
        }
    else:
        # Full governance cycle: ECM/PFM/PAN/SDA scoring + aggregation,
        # ComplianceEngine (EU AI Act), TCO audit log -- app.cgc_loop
        # already implements all of this (execute_governance_cycle) but
        # was never called from here; the endpoint used to stop after
        # PreFilter alone. Sync call, no await -- same pattern as
        # app.prefilter.evaluate() above.
        loop_result = app.cgc_loop.execute_governance_cycle(
            decision_id=decision_id,
            module_source=user_email,
            org_id=org_id,
            action=action,
            input_data=input_dict,
            prefilter_result=prefilter_result,
            context=None,
            app_source=app_source,
        )
        total_latency = (perf_counter_ns() - start_time) / 1_000_000
        response = {
            "approved": loop_result.get("approved", False),
            "outcome": loop_result.get("outcome"),
            "reason": loop_result.get("reason"),
            "correlation_id": prefilter_result.correlation_id,
            "prefilter": prefilter_result.to_dict(),
            "decision": loop_result,
            "total_latency_ms": round(total_latency, 2),
            "decision_id": decision_id
        }

    if app.pod and intercept_id:
        try:
            await app.pod.seal_intercept(
                intercept_id=intercept_id,
                output_payload=response,
                governance_outcome=response.get("outcome", prefilter_result.outcome),
            )
        except Exception as e:
            logger.warning(f"[PoD] seal_intercept failed (non-fatal): {e}")

    return response


@app.get("/governance/reports/{app_source}", tags=["Governance"])
async def get_governance_report(
    app_source: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    user=Depends(get_current_user)
) -> Response:
    """
    On-demand per-app governance report (decision summary + full audit
    chain) as an inline-viewable PDF, sourced from TCO's Postgres-backed
    audit trail (cgc_tco.audit_trail).
    """
    if app_source not in ALLOWED_APP_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unknown app_source: {app_source}")

    if not to_date:
        to_date = datetime.now(timezone.utc).date().isoformat()
    if not from_date:
        from_date = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()

    pdf_bytes = app.tco.generate_app_report_pdf(app_source, from_date, to_date)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="cgc_report_{app_source}_{from_date}_to_{to_date}.pdf"'}
    )


@app.get("/governance/modules/{module_name}/metrics", tags=["Governance"])
async def get_module_metrics(
    module_name: str,
    user=Depends(get_current_user)
) -> Dict[str, Any]:
    """Obtener métricas de un módulo específico de gobernanza."""
    module_map = {
        "prefilter": app.prefilter,
        "ecm": app.ecm,
        "pfm": app.pfm,
        "pan": app.pan,
        "sda": app.sda,
        "tco": app.tco,
        "scm": app.scm
    }
    
    module = module_map.get(module_name.lower())
    if not module:
        raise HTTPException(status_code=404, detail=f"Module {module_name} not found")
    
    if hasattr(module, 'get_metrics'):
        return module.get_metrics()
    else:
        return {"status": "active", "module": module_name}

@app.post("/audit/seal", tags=["Governance"])
async def seal_governance_decision(
    payload: Dict[str, Any],
    user=Depends(get_current_user)
) -> Dict[str, AuditHash]:
    """Sellar decisión de gobernanza usando SCM."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    if app.scm and hasattr(app.scm, 'sign_data'):
        tenant_id = payload.get("org_id", "default")
        signature_result = app.scm.sign_data(
            json.dumps(payload, sort_keys=True),
            tenant_id,
            context={"operation": "audit_seal", "user": user.get("email")}
        )
        audit_id = signature_result.get("signature_id", os.urandom(16).hex())
    else:
        audit_id: AuditHash = os.urandom(16).hex()
    
    logger.info(f"Audit sealed: {audit_id} by {user.get('email')}")
    return {
        "audit_id": audit_id,
        "status": "SEALED_IMMUTABLE",
        "timestamp": timestamp,
        "signed": app.scm is not None
    }

# =========================
# PRODUCTION STARTUP
# =========================
@app.on_event("startup")
async def startup_event():
    logger.info("CGC CORE v2.2.2 + PRE-FILTER + Unified Governance LIVE")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("CGC CORE shutting down gracefully")

if os.path.exists("./dist"):
    app.mount("/", StaticFiles(directory="./dist", html=True), name="ui")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8080, 
        loop="uvloop", 
        http="httptools",
        log_level="info"
    )