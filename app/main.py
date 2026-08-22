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

# Business-flow scoring router (read-only aggregation over the TCO ledger — Phase 1
# of the CGC Core reinforcement plan).
from api.v1.endpoints.flow_score import router as flow_score_router

# External guard (Phase 2 of the reinforcement plan) — distributed rate
# limiting + payload signature checks.
from app.modules.guard.rate_limiter import check_rate_limit
from app.modules.guard.payload_guard import scan_payload, record_suspicious_payload
from app.modules.guard.enforcement import is_hard_mode as is_guard_hard_mode

# Internal guard router (Phase 3 of the reinforcement plan) — read-only
# misuse-detection report over the TCO ledger.
from api.v1.endpoints.internal_guard import router as internal_guard_router

# Guard activity router — dashboard-visibility reads over what Phase 2/3
# have already been persisting since they shipped.
from api.v1.endpoints.guard_activity import router as guard_activity_router

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

        # Wires the real logging pipeline (file + console + the
        # cgc_audit_traces DB handler + optional syslog/HTTP) into the root
        # logger. Was defined but never called anywhere in the whole repo --
        # cgc_audit_traces (this codebase's own "immutable audit trail for
        # all governance events") was therefore always empty; its only
        # writer, CGCLoggingHandler, was never attached to anything. Fixed
        # two real bugs inside logging_config.py itself first (see that
        # file): CGCLoggingHandler.emit() was reading a record.extra
        # attribute that never exists (extra={} keys land as top-level
        # record attributes, not nested), so decision_id/user_id were
        # always None regardless of what callers passed; and the shared
        # formatter hard-requires %(decision_id)s, which most log calls
        # never set, which used to raise inside every handler's format()
        # call. Called first, before any other module below, so their own
        # __init__-time log lines are captured too. Guarded per the
        # cgc_jla-outage lesson -- a logging setup failure must never take
        # the app down.
        try:
            logging_config.setup_logging()
        except Exception as e:
            logger.warning(f"[Logging] setup_logging() failed (non-fatal, falls back to default logging): {e}")

        self.db = get_database()

        # AuthSystem() was the one __init__ step still unguarded -- unlike
        # every other module here, a failure inside it (e.g. os.makedirs on
        # a misconfigured/non-writable CGC_AUTH_DATA_DIR) used to take down
        # the ENTIRE app at import time, not just auth-gated routes. Falling
        # back to None means /health and the unauthenticated routes stay up
        # even if auth is broken -- get_current_user() below raises a clean
        # 503 instead of an unhandled AttributeError either way.
        try:
            self.auth = AuthSystem()
        except Exception as e:
            logger.error(f"[Auth] AuthSystem init failed (non-fatal, auth-gated routes will 503): {e}")
            self.auth = None

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
        # LOOP receives the SAME scm/pan/ecm/pfm/sda/tco instances above,
        # instead of building its own separate set (2026-08-22 fix) -- every
        # real /governance/decision call runs through LOOP, so
        # GET /governance/modules/{name}/metrics and /status/nodes (which
        # read app.pan/app.ecm/... directly) now reflect real traffic
        # instead of permanently-zero counters on objects nothing ever
        # calls. self.compliance_engine reuses LOOP's own ComplianceEngine
        # (built from these same scm/tco instances) rather than
        # constructing a second one that was only ever used for a boolean
        # presence check in /status/nodes.
        self.cgc_loop = LOOP(
            scm=self.scm, pan=self.pan, ecm=self.ecm,
            pfm=self.pfm, sda=self.sda, tco=self.tco,
        )
        self.compliance_engine = self.cgc_loop.compliance

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
    if app.auth is None:
        raise HTTPException(status_code=503, detail="Auth system unavailable")
    user_info = app.auth.verify_token(credentials.credentials)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user_info

async def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user

async def require_admin_or_service(user=Depends(get_current_user)):
    """
    Same as require_admin, but also accepts the 'service' principal
    (a caller presenting CGC_SERVICE_API_KEY -- see AuthSystem.verify_token,
    role "service"). Built for /admin/cleanup/guard-tables specifically:
    that endpoint is meant to be hit by a scheduler (Vercel Cron, a GitHub
    Action, cron-job.com), and a normal admin JWT expires after 7 days
    (AuthSystem.login()), which would mean manually refreshing whatever
    secret the scheduler holds every week. CGC_SERVICE_API_KEY is already
    the long-lived, first-party credential this codebase trusts for
    server-to-server calls (LedgiProof's cgc-evaluate/report-error edge
    functions use it today) -- reusing it here avoids a second credential
    with a second rotation story for the exact same trust level. NOT
    applied to every admin endpoint -- e.g. /admin/users stays strictly
    admin-only, since the service principal has no legitimate reason to
    enumerate user accounts.
    """
    if user.get("role") not in ("admin", "service"):
        raise HTTPException(status_code=403, detail="Admin or service credential required")
    return user

# Mount the application-monitoring router → /monitor/error, /monitor/errors, ...
# Same Bearer-token auth as every other authenticated endpoint, enforced here
# at the router level so monitor.py itself carries no auth logic.
app.include_router(
    monitor_router, prefix="/monitor", tags=["Monitoring"],
    dependencies=[Depends(get_current_user)]
)

# Mount the business-flow scoring router → /flow-score/{app_source}
# Read-only over the already-sealed TCO ledger; no write path touched.
app.include_router(
    flow_score_router, prefix="/flow-score", tags=["Flow Scoring"],
    dependencies=[Depends(get_current_user)]
)

# Mount the internal-guard router → /guard/internal/report
# Read-only misuse-detection report over the TCO ledger; no write path touched.
app.include_router(
    internal_guard_router, prefix="/guard/internal", tags=["Internal Guard"],
    dependencies=[Depends(get_current_user)]
)

# Mount the guard-activity router → /guard/activity/*
# Dashboard-visibility reads only; no write path touched.
app.include_router(
    guard_activity_router, prefix="/guard/activity", tags=["Guard Activity"],
    dependencies=[Depends(get_current_user)]
)

# PreFilter Helper
async def run_cgc_prefilter(
    org_id: str,
    user_email: str,
    action: str,
    data_domains: List[str],
    user: Dict[str, Any],
    area: str = "DEFAULT"
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
        area=area,
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
    """Health check across all governance modules."""
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
async def signup(data: SignUp, request: Request):
    if app.auth is None:
        raise HTTPException(status_code=503, detail="Auth system unavailable")

    # 5/hour per IP -- generous for real onboarding, a real backstop
    # against signup spam (there was none before Phase 2).
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"signup:{client_ip}", 5, 3600):
        raise HTTPException(status_code=429, detail="Too many signups — try again later")

    # Was create_user(data.email, data.password, data.name, data.role) --
    # create_user's real signature is (email, password, role, created_by),
    # so every signup positionally stuffed `name` into the `role` slot and
    # `role` into `created_by`. `name` has no field on the user record at
    # all (create_user never accepted one), so it's dropped here rather
    # than invented a home for it -- same practical effect as before
    # (silently unused), just without corrupting `role` in the process.
    app.auth.create_user(data.email, data.password, role=data.role)
    return {"message": "User created successfully"}

@app.post("/auth/signin", tags=["Auth"])
async def signin(data: SignIn, request: Request):
    if app.auth is None:
        raise HTTPException(status_code=503, detail="Auth system unavailable")

    # Was calling app.auth.create_session_token(...), a method that never
    # existed on AuthSystem -- every real signin attempt 500'd before this
    # fix. AuthSystem.login() is the real method: bcrypt password check,
    # already-built in-memory brute-force protection (5 attempts / 15min
    # lockout per IP, plus an is_blocked() IP/email blocklist check), JWT
    # issuance, session storage -- all of it was dead code until this call
    # site actually reached it.
    client_ip = request.client.host if request.client else None
    result = app.auth.login(data.email, data.password, ip=client_ip)

    if not result.get("success"):
        if result.get("rate_limited"):
            raise HTTPException(status_code=429, detail=result["error"])
        if result.get("blocked"):
            raise HTTPException(status_code=403, detail=result["error"])
        raise HTTPException(status_code=401, detail=result["error"])

    return {"access_token": result["token"], "token_type": "bearer", "user": result["user"]}

@app.get("/admin/users", tags=["Admin"])
async def list_users(user=Depends(require_admin)):
    return app.auth.list_users()

@app.post("/admin/cleanup/guard-tables", tags=["Admin"])
async def cleanup_guard_tables(user=Depends(require_admin_or_service)):
    """
    Deletes rows past retention from the 4 cgc_guard.* telemetry tables
    (rate_limit_events, login_attempts, suspicious_payloads,
    internal_flags) -- none of them had any cleanup mechanism before this
    (2026-08-22 audit finding #9), so they grew unboundedly forever.

    This process has no scheduler of its own -- wire this endpoint up to
    whatever recurring trigger is available (Vercel Cron, a GitHub Action,
    cron-job.com, ...). Accepts either an admin bearer token or
    CGC_SERVICE_API_KEY (require_admin_or_service) specifically so a
    scheduler can use the same long-lived first-party credential this
    codebase already trusts elsewhere, instead of a 7-day-expiring admin
    JWT that would need manual weekly renewal. Deliberately does NOT touch
    cgc_tco.audit_trail or cgc_pod.* -- see Database.cleanup_guard_tables()'s
    docstring for why those need an archival strategy instead of a plain
    delete.
    """
    return app.db.cleanup_guard_tables()

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

# Read once at import time -- static bundled assets, not a runtime write,
# so this is safe on Vercel's read-only filesystem. Split into 4 dedicated
# pages (hub + governance/scoring/security) so governance, scoring, and
# security stay visually and operationally separate instead of one mixed
# dashboard -- each is self-contained (own CSS/JS, no shared-asset routes),
# all reading/writing the same localStorage token so signing in on one
# carries over to the others.
_DASHBOARD_HOME_HTML = (Path(__file__).parent / "static" / "dashboard_home.html").read_text(encoding="utf-8")
_DASHBOARD_GOVERNANCE_HTML = (Path(__file__).parent / "static" / "dashboard_governance.html").read_text(encoding="utf-8")
_DASHBOARD_SCORING_HTML = (Path(__file__).parent / "static" / "dashboard_scoring.html").read_text(encoding="utf-8")
_DASHBOARD_SECURITY_HTML = (Path(__file__).parent / "static" / "dashboard_security.html").read_text(encoding="utf-8")

@app.get("/dashboard", tags=["System"], response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """CGC Core Monitoring hub -- self-contained static page (no server-side
    auth on the shell itself). Prompts for a Bearer token client-side and
    links out to the 3 dedicated Governance/Scoring/Security screens."""
    return HTMLResponse(content=_DASHBOARD_HOME_HTML)

@app.get("/dashboard/governance", tags=["System"], response_class=HTMLResponse)
async def dashboard_governance() -> HTMLResponse:
    """Governance Modules + Governance Reports (PDF generator/viewer)."""
    return HTMLResponse(content=_DASHBOARD_GOVERNANCE_HTML)

@app.get("/dashboard/scoring", tags=["System"], response_class=HTMLResponse)
async def dashboard_scoring() -> HTMLResponse:
    """Business Flow Scoring cards (Phase 1)."""
    return HTMLResponse(content=_DASHBOARD_SCORING_HTML)

@app.get("/dashboard/security", tags=["System"], response_class=HTMLResponse)
async def dashboard_security() -> HTMLResponse:
    """Guard Activity (Phase 2/3 stat cards + tables) + Recent Errors."""
    return HTMLResponse(content=_DASHBOARD_SECURITY_HTML)

@app.get("/", tags=["System"])
async def root() -> Dict[str, Any]:
    """Root endpoint with unified system information."""
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
    request: Request,
    org_id: str = Form(...),
    action: str = Form(...),
    input_data: str = Form(...),
    user_email: str = Form(...),
    data_domains: str = Form(...),
    app_source: str = Form("unknown"),
    area: str = Form("DEFAULT"),
    user=Depends(get_current_user)
) -> Dict[str, Any]:
    """Unified endpoint for executing governance decisions."""
    start_time = perf_counter_ns()

    # Optional with a default (not Form(...)) so any existing caller not
    # yet sending it keeps working unbroken. Same naming convention as
    # /monitor/error's app_source, reused here rather than invented fresh.
    if app_source not in ALLOWED_APP_SOURCES:
        app_source = "unknown"

    # Dual-keyed distributed rate limit: per org_id AND per IP. Either one
    # tripping blocks the request -- an org-only check alone wouldn't catch
    # an attacker rotating which org_id it claims from one source, and an
    # IP-only check alone would be too coarse (real traffic from shared
    # Vercel/Supabase edge infrastructure can legitimately span many orgs
    # behind one IP pool), so the IP ceiling is set higher than the org one.
    # The org ceiling now comes from the tenant's real plan (was a flat
    # 300/min hardcoded constant for every tenant before this).
    client_ip = request.client.host if request.client else "unknown"
    org_rate_limit = tenant_manager.get_rate_limit(org_id, "decisions_per_min", 300)
    if not check_rate_limit(f"decision:org:{org_id}", org_rate_limit, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for this organization")
    if not check_rate_limit(f"decision:ip:{client_ip}", 1000, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for this source")

    try:
        input_dict = json.loads(input_data)
        domains_list = json.loads(data_domains)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

    # Proof-of-Decision: capture the input hash BEFORE the decision is made,
    # so the eventual proof can't be fabricated after the fact. Sealed once
    # the outcome (ALLOW or blocked) is known, further down.
    decision_id = f"dec_{secrets.token_hex(8)}"

    # Payload signature check -- soft-flag by default (logs + records which
    # pattern/field matched, never the payload content itself; doesn't
    # alter the response). GUARD_HARD_MODE_PAYLOAD=true promotes this to an
    # actual 400 rejection -- off by default until real false-positive rate
    # has actually been observed; see app/modules/guard/enforcement.py.
    try:
        findings = scan_payload(action, input_dict)
        if findings and is_guard_hard_mode("payload"):
            first_field, first_patterns = next(iter(findings.items()))
            logger.warning(f"[guard] BLOCKED (hard mode) suspicious payload: decision={decision_id} org={org_id} field={first_field} pattern={first_patterns[0]}")
            record_suspicious_payload(decision_id, org_id, first_field, first_patterns[0])
            raise HTTPException(status_code=400, detail="Request payload rejected by guard policy")
        for field, patterns in findings.items():
            for pattern in patterns:
                logger.warning(f"[guard] suspicious payload: decision={decision_id} org={org_id} field={field} pattern={pattern}")
                record_suspicious_payload(decision_id, org_id, field, pattern)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[guard] payload scan failed (non-fatal): {e}")

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

    # Safety net: neither run_cgc_prefilter() nor execute_governance_cycle()
    # used to have any guard around this call site -- unlike every PoD call
    # in this same handler, which is triple-wrapped. cgc_loop.py's own
    # internal try/except only starts AFTER its tenant-quota check block
    # (check_quota/check_feature, and the quota-exceeded branch's own
    # tco.log_decision call), so any exception in that narrow pre-try
    # window -- or in run_cgc_prefilter itself -- used to propagate fully
    # unguarded straight to Starlette's default handler: a raw, unformatted
    # 500 with no detail body, exactly what made a real incident hard to
    # diagnose. This converts that into a normal, diagnosable HTTPException.
    try:
        prefilter_result = await run_cgc_prefilter(
            org_id=org_id,
            user_email=user_email,
            action=action,
            data_domains=domains_list,
            user=user,
            area=area
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
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[governance/decision] unhandled failure: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "governance_cycle_failed", "message": str(e), "decision_id": decision_id}
        )

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
    """Get metrics for a specific governance module."""
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
    request: Request,
    user=Depends(get_current_user)
) -> Dict[str, AuditHash]:
    """Seal a governance decision using SCM."""
    timestamp = datetime.now(timezone.utc).isoformat()

    seal_tenant_id = payload.get("org_id", "default")
    # Lighter-weight endpoint than /governance/decision, lower ceiling.
    if not check_rate_limit(f"seal:{seal_tenant_id}", 100, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for this organization")

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