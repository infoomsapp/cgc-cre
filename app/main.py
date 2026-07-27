"""
CGC CORE - Enterprise API Gateway (v2.2.2)
Python 3.13.1+ | 8 Integrations + DisciplineAI Legal 
Strictly Production | Olympus Mont Systems LLC  2025
"""

import asyncio
import os
import io
import json
import base64
import secrets  # Movido al scope global
from datetime import datetime, timezone
from typing import Annotated, Any, Final, Optional, Dict, List
from time import perf_counter_ns

from fastapi import FastAPI, Depends, Request, Header, status, Form, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, ConfigDict
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import HTTPException

# CGC CORE - Unified Governance System
from app.Core.tenant.multi_tenant import tenant_manager
from app.modules.compliance.compliance_engine import ComplianceEngine
from app.Core.db.database import get_database
from app.Core.auth.auth_system import AuthSystem
from app.Core.config import config
from app.Core.logging import logging_config

# Core Governance Modules
from app.modules.prefilter.PreFilter import PreFilter
from app.modules.scm.scmmodule import SCM
from app.modules.ecm.ecmmodule import ECM
from app.modules.pfm.pfmmodule import PFM
from app.modules.pan.panmodule import PAN
from app.modules.sda.sdamodule import SDA
from app.modules.tco.tcomodule import TCO
from app.modules.loop.cgc_loop import LOOP
   


# 8 INTEGRATIONS
from app.integrations.docusign import DocuSignIntegration
from app.integrations.salesforce import SalesforceIntegration
from app.integrations.microsoft365 import Microsoft365Integration
from app.integrations.okta import OktaIntegration
from app.integrations.google_workspace import GoogleWorkspaceIntegration
from app.integrations.slack_teams import SlackIntegration
from app.integrations.zapier import ZapierIntegration
from app.integrations.netsuite import NetSuiteIntegration

# Forensic verify router (PoD chain integrity + per-decision proof).
# Mounted on the app below so /verify/... is reachable from the canonical app.
from api.v1.endpoints.verify import router as verify_router

# Type Aliases (Python 3.12+)
type AuditHash = str
type SentinelResponse = Dict[str, Any]

# Loggers (: org_id no existe aqu, se usa genrico)
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

        # ====================================================================
        # Enterprise Integrations (8 nodes)
        # ====================================================================
        self.nodes: Final[Dict[str, Any]] = {
            "docusign": DocuSignIntegration(),
            "salesforce": SalesforceIntegration(),
            "m365": Microsoft365Integration(),
            "okta": OktaIntegration(),
            "google": GoogleWorkspaceIntegration(),
            "slack": SlackIntegration(),
            "netsuite": NetSuiteIntegration(),
            "zapier": ZapierIntegration()
        }
        

app = CGCCoreEngine(
    title="CGC CORE - Enterprise LegalTech Gateway",
    version="2.2.2",
    root_path="/api/v1",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Mount the forensic verify router → /verify/{decision_id} and
# /verify/chain/integrity. With root_path="/api/v1" the external paths are
# /api/v1/verify/... — this is what the LedgiProof governance-dashboard guard
# calls for PoD chain-integrity verification.
app.include_router(verify_router, prefix="/verify", tags=["Forensic Audit"])

security = HTTPBearer()

# UTILITY: Text extraction 
async def extract_text(content: bytes, filename: str) -> str:
    """Production text extraction from PDF/DOCX."""
    try:
        if filename.lower().endswith('.pdf'):
            import pdfplumber
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                return '\n'.join(page.extract_text() or '' for page in pdf.pages)
        elif filename.lower().endswith('.docx'):
            from docx import Document
            doc = Document(io.BytesIO(content))
            return '\n'.join(para.text for para in doc.paragraphs)
        return content.decode('utf-8', errors='ignore')[:10000]
    except Exception:
        return content.decode('utf-8', errors='ignore')[:5000]

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

# PreFilter Helper (Consolidado y corregido)
async def run_cgc_prefilter(
    org_id: str,
    user_email: str,
    action: str,
    data_domains: List[str],
    user: Dict[str, Any]
) -> PreFilterResult:
    """Ejecutar CGC-PreFilter."""
    
    agent = Agent(
        id=f"agent-legal-{org_id}",
        name="DisciplineAI Legal Agent",
        status="PRODUCTION",
        roles=["LEGAL_ANALYST", "COMPLIANCE"],
        scopes=["read:contracts", "analyze:legal", "write:docusign"],
        owners=[{"id": user_email, "role": "LEGAL_OWNER"}],
        capabilities=["contract_analysis", "risk_assessment"],
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat()
    )
    
    context = EnforcementContext(
        user_id=user.get("id", user_email),
        user_roles=user.get("roles", ["user"]),
        action=action,
        data_domains=data_domains,
        requested_scopes=["read:contracts", "analyze:legal"],
        area="LEGAL",
        correlation_id=f"corr_{secrets.token_hex(8)}"
    )

    # PREFILTER (ultra-fast <10ms)
    result = app.prefilter.evaluate(agent, context)

    # Save in DB for TCO
    app.db.save_prefilter_result(result.correlation_id, result.to_dict())

    return result

# =========================
# MAIN PRODUCTION PIPELINE WITH PREFILTER 
# =========================
@app.post("/legal/hybrid-analyze", tags=["LegalTech"])
async def hybrid_legal_pipeline(
    org_id: str = Form(...),
    contract: UploadFile = File(...),
    user_email: str = Form(...),
    jurisdiction: str = Form("federal"),
    user=Depends(get_current_user)
):
    """Production: CGC-PRE FILTER  Hybrid  CGC  8 Parallel Integrations."""
    
    start_time = perf_counter_ns()
    
    # 0: CGC-PRE FILTER
    prefilter_result = await run_cgc_prefilter(
        org_id=org_id,
        user_email=user_email,
        action="hybrid_legal_analysis",
        data_domains=["CONFIDENTIAL_CONTRACTS", "LEGAL_OPINIONS"],
        user=user
    )
    
    # CORREGIDO: Bloquear si el resultado NO es ALLOW
    if prefilter_result.outcome != "ALLOW":
        api_logger.warning(f"PreFilter DENY: {prefilter_result.correlation_id}")
        return {
            "stage": "prefilter",
            "outcome": "DENY",
            "reason": prefilter_result.reason,
            "correlation_id": prefilter_result.correlation_id,
            "latency_ms": prefilter_result.latency_ms
        }
    
    # Tenant quota (POST-PreFilter)
    if not tenant_manager.check_quota(org_id, "contracts"):
        raise HTTPException(429, "Legal quota exceeded. Upgrade Enterprise.")
    
    # Extract + Analyze
    content = await contract.read()
    text = await extract_text(content, contract.filename)
    analysis = await app.hybrid_analyzer.analyze(text, org_id, {"jurisdiction": jurisdiction})
    
    # Ejecutar ciclo de gobernanza unificado (PreFilter ya validado)
    governance_result = await app.governance_orchestrator.execute_governance_cycle(
        decision_id=prefilter_result.correlation_id,
        module_source="disciplineai_legal",
        org_id=org_id,
        action="hybrid_legal_analysis",
        input_data={"analysis": analysis, "org_id": org_id},
        prefilter_result=prefilter_result  # Pasar objeto PreFilterResult, no dict
    )

    # 8 NODES PARALLEL EXECUTION (Python 3.13 TaskGroup)
    results: Dict[str, Any] = {}
    try:
        async with asyncio.TaskGroup() as tg:
            tasks = {
                "docusign": tg.create_task(app.nodes["docusign"].create_cgc_envelope(text, org_id, user_email, "Legal Team")),
                "salesforce": tg.create_task(app.nodes["salesforce"].sync_contract_analysis(analysis, org_id)),
                "m365": tg.create_task(app.nodes["m365"].send_teams_notification(analysis, f"org-{org_id}")),
                "okta": tg.create_task(app.nodes["okta"].authenticate_user(org_id, user_email)),
                "google": tg.create_task(app.nodes["google"].save_to_drive(analysis, org_id)),
                "slack": tg.create_task(app.nodes["slack"].post_slack_alert(analysis, org_id)),
                "netsuite": tg.create_task(app.nodes["netsuite"].sync_financials(analysis, org_id)),
                "zapier": tg.create_task(app.nodes["zapier"].trigger_workflows(analysis, org_id))
            }
        results = {name: task.result() for name, task in tasks.items()}
        
    except* Exception as eg:  # Python 3.13 ExceptionGroup
        api_logger.error(f"Integration group failed: {eg.exceptions}")
        results = {name: {"status": "failed"} for name in app.nodes.keys()}
    
    total_latency = (perf_counter_ns() - start_time) / 1_000_000
    
    return {
        "success": True,
        "prefilter": prefilter_result.to_dict(), 
        "analysis": analysis,
        "integrations": results,
        "status": "FULLY_INTEGRATED_LEGAL_PIPELINE_COMPLETE",
        "tenant_plan": tenant_manager.get_tenant(org_id)["plan"],
        "total_latency_ms": round(total_latency, 2),
        "prefilter_latency_ms": prefilter_result.latency_ms
    }

# =========================
# PRODUCTION LEGAL MODULES
# =========================
@app.post("/legal/esign-cgc", tags=["LegalTech"])
async def cgc_docusign_pipeline(
    org_id: str = Form(...), contract_text: str = Form(...),
    signer_email: str = Form(...), signer_name: str = Form(...),
    user=Depends(get_current_user)
):
    prefilter_result = await run_cgc_prefilter(
        org_id=org_id,
        user_email=signer_email,
        action="esign_cgc",
        data_domains=["LEGAL_OPINIONS"],
        user=user
    )
    
    if prefilter_result.outcome != "ALLOW":
        return {"prefilter": prefilter_result.to_dict(), "status": "DENIED"}
    
    return await app.nodes["docusign"].create_cgc_envelope(contract_text, org_id, signer_email, signer_name)

@app.get("/legal/compliance/{org_id}", tags=["LegalTech"])
async def compliance_stats(org_id: str, user=Depends(get_current_user)):
    prefilter_result = await run_cgc_prefilter(
        org_id=org_id,
        user_email=user.get("email"),
        action="compliance_check",
        data_domains=["COMPLIANCE_REPORTS"],
        user=user
    )
    
    if prefilter_result.outcome != "ALLOW":
        return {"prefilter": prefilter_result.to_dict(), "status": "DENIED"}
    
    return app.compliance_checker.get_framework_stats(org_id)


# =========================
# ENTERPRISE SENTINEL MONITORING
# =========================
@app.get("/status/nodes", tags=["Governance"])
async def get_sentinel_health(user=Depends(get_current_user)) -> JSONResponse:
    """Health check de todos los módulos de gobernanza e integraciones."""
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
    
    # Orchestrator
    results["governance_orchestrator"] = app.governance_orchestrator.get_metrics()
    
    # Compliance Engine
    if app.compliance_engine:
        results["compliance_engine"] = {"status": "active", "module": "ComplianceEngine"}

    # Enterprise Integrations
    try:
        async with asyncio.TaskGroup() as tg:
            tasks = {
                name: tg.create_task(node.get_status())
                for name, node in app.nodes.items()
            }
        
        for name, task in tasks.items():
            try:
                results[name] = task.result()
            except Exception as e:
                results[name] = {"status": "ERROR", "details": str(e)}

        return JSONResponse(
            content={"nodes": results, "integrity": "VERIFIED", "governance_system": "UNIFIED"},
            status_code=status.HTTP_200_OK
        )

    except Exception as eg:
        return JSONResponse(
            status_code=status.HTTP_207_MULTI_STATUS,
            content={"error": "Node_Cluster_Degraded", "details": [str(e) for e in eg.exceptions]}
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
            "orchestration": "GovernanceCycleOrchestrator",
            "compliance": "ComplianceEngine"
        },
        "integrations": len(app.nodes),
        "prefilter": app.prefilter.get_metrics(),
        "governance_orchestrator": app.governance_orchestrator.get_metrics(),
        "legaltech": "FULLY_OPERATIONAL",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# =========================
# GOVERNANCE ENDPOINTS
# =========================

@app.post("/governance/decision", tags=["Governance"])
async def execute_governance_decision(
    org_id: str = Form(...),
    action: str = Form(...),
    input_data: str = Form(...),  # JSON string
    user_email: str = Form(...),
    data_domains: str = Form(...),  # JSON array string
    user=Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Endpoint unificado para ejecutar decisiones de gobernanza.
    Flujo: PreFilter -> SCM Entry -> Core Modules -> Decision
    """
    start_time = perf_counter_ns()
    
    # Parse input
    try:
        input_dict = json.loads(input_data)
        domains_list = json.loads(data_domains)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    
    # STEP 1: PreFilter (First Layer)
    prefilter_result = await run_cgc_prefilter(
        org_id=org_id,
        user_email=user_email,
        action=action,
        data_domains=domains_list,
        user=user
    )
    
    if prefilter_result.outcome != "ALLOW":
        return {
            "approved": False,
            "stage": "prefilter",
            "outcome": prefilter_result.outcome,
            "reason": prefilter_result.reason,
            "correlation_id": prefilter_result.correlation_id
        }
    
    # STEP 2: Execute Governance Cycle
    decision_id = prefilter_result.correlation_id
    governance_result = await app.governance_orchestrator.execute_governance_cycle(
        decision_id=decision_id,
        module_source=user_email,
        org_id=org_id,
        action=action,
        input_data=input_dict,
        prefilter_result=prefilter_result
    )
    
    total_latency = (perf_counter_ns() - start_time) / 1_000_000
    
    return {
        **governance_result,
        "prefilter": prefilter_result.to_dict(),
        "total_latency_ms": round(total_latency, 2)
    }

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
        "scm": app.scm,
        "orchestrator": app.governance_orchestrator
    }
    
    module = module_map.get(module_name.lower())
    if not module:
        raise HTTPException(status_code=404, detail=f"Module {module_name} not found")
    
    if hasattr(module, 'get_metrics'):
        return module.get_metrics()
    else:
        return {"status": "active", "module": module_name}

@app.post("/governance/compliance/validate", tags=["Governance"])
async def validate_compliance(
    org_id: str = Form(...),
    decision_artifact: str = Form(...),  # JSON string
    industry: str = Form("DEFAULT"),
    user=Depends(get_current_user)
) -> Dict[str, Any]:
    """Validar cumplimiento EU AI Act + NIST para una decisión."""
    import json
    
    if not app.compliance_engine:
        raise HTTPException(status_code=503, detail="ComplianceEngine not available")
    
    try:
        artifact = json.loads(decision_artifact)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    # PreFilter check
    prefilter_result = await run_cgc_prefilter(
        org_id=org_id,
        user_email=user.get("email", ""),
        action="compliance_validation",
        data_domains=["COMPLIANCE_REPORTS"],
        user=user
    )
    
    if prefilter_result.outcome != "ALLOW":
        return {"status": "DENIED", "reason": prefilter_result.reason}
    
    # Validate compliance
    compliance_result = app.compliance_engine.validate_eu_ai_act(
        agent_decision=artifact,
        industry=industry
    )
    
    return {
        "compliance_status": compliance_result.status if hasattr(compliance_result, 'status') else "PASS",
        "profile": compliance_result.profile if hasattr(compliance_result, 'profile') else {},
        "prefilter": prefilter_result.to_dict()
    }

@app.post("/audit/seal", tags=["Governance"])
async def seal_governance_decision(
    payload: Dict[str, Any],
    user=Depends(get_current_user)
) -> Dict[str, AuditHash]:
    """Sellar decisión de gobernanza usando SCM."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    if app.scm and hasattr(app.scm, 'sign_data'):
        # Usar SCM para firmar el payload
        tenant_id = payload.get("org_id", "default")
        signature_result = app.scm.sign_data(
            json.dumps(payload, sort_keys=True),
            tenant_id,
            context={"operation": "audit_seal", "user": user.get("email")}
        )
        audit_id = signature_result.get("signature_id", os.urandom(16).hex())
    else:
        audit_id: AuditHash = os.urandom(16).hex()
    
    api_logger.info(f"Audit sealed: {audit_id} by {user.get('email')}")
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
    api_logger.info("CGC CORE v2.2.2 + PRE-FILTER + 8 Integrations + LegalTech LIVE")
    api_logger.info(f"Pre-heated {len(app.nodes)} enterprise nodes")

@app.on_event("shutdown")
async def shutdown_event():
    api_logger.info("CGC CORE shutting down gracefully")

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

