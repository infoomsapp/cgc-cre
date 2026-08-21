"""
GET /guard/internal/report?tenant_id=&module_source=&window_days=&baseline_days=

Phase 3 of the CGC Core reinforcement plan: internal guard, a read-only
report over cgc_tco.audit_trail (no new capture point, no write path
touched). See app/modules/guard/internal_guard.py for the 3 detectors and
their explicitly accepted limitations.

Auth: same Bearer-token scheme as the rest of the API, applied at the
router-mount level in main.py (dependencies=[Depends(get_current_user)]),
so this file has no auth logic of its own - same pattern as monitor.py/flow_score.py.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Query

from app.modules.guard.internal_guard import (
    detect_baseline_deviation,
    detect_escalation_chains,
    detect_cross_tenant_reach,
    record_internal_flag,
)

router = APIRouter()


@router.get("/report", summary="Internal-guard report: escalation chains, and (if module_source given) baseline deviation + cross-tenant reach")
async def get_internal_guard_report(
    tenant_id: str = Query(...),
    module_source: Optional[str] = Query(None),
    window_days: int = Query(1, ge=1, le=30),
    baseline_days: int = Query(30, ge=7, le=180),
) -> Dict[str, Any]:
    findings: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "module_source": module_source,
        "escalation_chains": [],
        "baseline_deviation": None,
        "cross_tenant_reach": None,
    }

    escalation_chains = detect_escalation_chains(tenant_id, window_hours=window_days * 24)
    findings["escalation_chains"] = escalation_chains
    for chain in escalation_chains:
        record_internal_flag("escalation_chain", tenant_id, chain.get("module_source"), chain)

    if module_source:
        deviation = detect_baseline_deviation(tenant_id, module_source, window_days=window_days, baseline_days=baseline_days)
        findings["baseline_deviation"] = deviation
        if deviation:
            record_internal_flag("baseline_deviation", tenant_id, module_source, deviation)

        reach = detect_cross_tenant_reach(module_source, window_days=baseline_days)
        findings["cross_tenant_reach"] = reach
        if reach:
            record_internal_flag("cross_tenant_reach", tenant_id, module_source, reach)

    return findings
