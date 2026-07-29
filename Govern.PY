"""
CGC Core — Govern Endpoint

POST /api/v1/govern
    Submit a decision payload through the full CGC governance cycle.
    Returns outcome + PoD proof + verify URL.

Olympus Mont Systems LLC © 2026
"""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends
from app.api.v1.deps.db import require_tenant
from app.api.v1.schemas import GovernRequest, GovernResponse

logger = logging.getLogger("cgc.govern")
router = APIRouter()


@router.post(
    "",
    response_model=GovernResponse,
    summary="Someter decition to governance cycle",
    description="""
Ejecuta el ciclo completo de governance CGC Core sobre el payload enviado:

1. **PreFilter** — validación ultra-rápida, detección de dominios sensibles
2. **PAN** — extracción de features y contexto
3. **ECM** — calibración ética con matriz cargada desde Supabase
4. **PFM** — predicción de riesgo con modelo cargado desde Supabase
5. **SDA** — recomendaciones con best practices desde Supabase
6. **SCM** — firma RSA-PSS del artefacto
7. **PoD** — sellado en cadena inmutable (pre-delivery)
8. **Compliance** — validación EU AI Act + NIST RMF

Retorna el resultado y una URL para verificación forense posterior.
    """,
)
async def govern(
    request: GovernRequest,
    tenant_id: str = Depends(require_tenant),
):
    """
    Main governance endpoint.
    Runs the full CGC Loop cycle and returns the governance decision
    with a PoD proof and a verify URL for future forensic lookups.
    """
    start = time.monotonic()

    try:
        # Import LOOP here to avoid circular imports at module level
        from app.cgc_loop_v2 import LOOP

        loop = LOOP()

        # Build a minimal PreFilter result for the loop
        # In production this would run the full PreFilter module
        prefilter_result = {
            "areaIdentified": request.input_data.get("area", "DEFAULT"),
            "sensitiveDomainsCount": request.input_data.get("sensitive_domains_count", 0),
            "sensitiveDomainsDetected": request.input_data.get("sensitive_domains", []),
            "complianceOwnerPresent": request.input_data.get("compliance_owner_present", False),
            "short_circuit": False,
        }

        # Add model_slug to input_data for PoD interceptor
        input_data = dict(request.input_data)
        input_data["model_slug"] = request.model_slug

        result = loop.execute_governance_cycle(
            decision_id=request.decision_id,
            module_source=request.module_source,
            org_id=tenant_id,
            action=request.action,
            input_data=input_data,
            prefilter_result=prefilter_result,
            context=request.context,
        )

        processing_ms = round((time.monotonic() - start) * 1000, 2)

        # Build verify URL
        base_url = "http://localhost:8000"  # override with env var in production
        verify_url = f"{base_url}/api/v1/verify/{request.decision_id}"

        return GovernResponse(
            decision_id=request.decision_id,
            approved=result.get("approved", False),
            outcome=result.get("outcome", "ERROR"),
            reason=result.get("reason", ""),
            aggregated_score=result.get("decision_artifact", {}).get("aggregated_score"),
            area=result.get("area", prefilter_result["areaIdentified"]),
            sensitivity_level=result.get("sensitivity_level", "MEDIUM"),
            eu_ai_act_compliant=result.get("eu_ai_act_compliant"),
            pod=result.get("decision_artifact", {}).get("pod"),
            processing_time_ms=processing_ms,
            verify_url=verify_url,
        )

    except Exception as e:
        logger.error(f"[Govern] Error processing {request.decision_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "governance_cycle_failed",
                "decision_id": request.decision_id,
                "message": str(e)
            }
        )