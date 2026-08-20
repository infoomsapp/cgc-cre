"""
GET /flow-score/{app_source}   - business-flow score for one connected app

Phase 1 of the CGC Core reinforcement plan: a read-only aggregation over
cgc_tco.audit_trail (no new capture point, no write path touched). See
app/modules/flow_scoring/flow_scoring.py for the full scoring design and its
explicitly scoped limitations.

Auth: same Bearer-token scheme as the rest of the API, applied at the
router-mount level in main.py (dependencies=[Depends(get_current_user)]),
so this file has no auth logic of its own - same pattern as monitor.py.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query

from app.modules.flow_scoring.flow_scoring import FlowScoring
from api.v1.endpoints.monitor import ALLOWED_APP_SOURCES

router = APIRouter()


@router.get("/{app_source}", summary="Business-flow score for one connected app")
async def get_flow_score(
    app_source: str,
    window_days: int = Query(7, ge=1, le=90),
    baseline_days: int = Query(30, ge=7, le=180),
    tenant_id: Optional[str] = Query(None, description="Narrow to one organization within app_source"),
) -> Dict[str, Any]:
    if app_source not in ALLOWED_APP_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unknown app_source: {app_source}")

    # Instantiated per-request, same as monitor.py's get_database() calls -
    # no module-level singleton, no extra import-time side effect on main.py's
    # import chain.
    flow_scoring = FlowScoring()
    return flow_scoring.compute_flow_score(
        app_source, window_days=window_days, baseline_days=baseline_days, tenant_id=tenant_id
    )
