"""
GET /calibration/{module}/{area}              -- current calibration row (read)
PUT /calibration/{module}/{area}               -- update a calibration row (admin, write)
GET /calibration/changelog                     -- versioned history of every change

Versioned changelog for the four scoring modules' governance calibration
(ECM/PFM/SDA/PAN, backed by cgc_jla.* -- see app/Core/db/cgc_db_loader.py
and Database._CALIBRATION_MODULES). Until this existed, nothing in this
codebase ever updated a cgc_jla row outside its one-time seed, and there
was no record of who changed a value, when, or why -- exactly the kind
of "versioned rules changelog" this project already requires of
LedgiProof Tax Pro's own tax engines (rules.ts + changelog.ts per year),
now applied to CGC Core's own scoring rules.

Auth: same Bearer-token scheme as the rest of the API, base layer applied
at the router-mount level in main.py (dependencies=[Depends(get_current_user)]).
The write endpoint (PUT) additionally requires role=="admin", re-derived
here via request.app.auth.verify_token() rather than importing
require_admin from app.main (which would be a circular import -- same
pattern already used in monitor.py/flow_score.py/launch_readiness.py).
Every successful write is unconditionally logged to
cgc_calibration_changelog in the same request -- there is deliberately
no code path that updates a calibration row without also writing its
changelog entry.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.calibration")

router = APIRouter()

_VALID_MODULES = ("ecm", "pfm", "sda", "pan")


def _require_admin_principal(request: Request) -> Dict[str, Any]:
    """Re-derives the caller's role from the already-verified Bearer token
    (the router-mount dependency in main.py only confirms the token is
    valid, it doesn't expose the role to this handler). Not importing
    require_admin from app.main -- that would be circular, since main.py
    imports this router at module load time."""
    auth_header = request.headers.get("authorization", "")
    token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
    principal = request.app.auth.verify_token(token) if (token and request.app.auth) else None
    if not principal:
        raise HTTPException(status_code=401, detail="Invalid token")
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return principal


class CalibrationUpdateIn(BaseModel):
    fields: Dict[str, Any] = Field(..., min_length=1)
    action_type: Optional[str] = None
    reason: str = Field(..., min_length=8, max_length=2000)
    source_name: Optional[str] = Field(None, max_length=255)
    source_url: Optional[str] = Field(None, max_length=1000)


@router.get("/changelog/list", summary="Versioned history of calibration changes")
async def list_changelog(
    module: Optional[str] = None, governance_area: Optional[str] = None, limit: int = 100,
) -> Dict[str, Any]:
    if module is not None and module not in _VALID_MODULES:
        raise HTTPException(status_code=400, detail=f"module must be one of {_VALID_MODULES}")
    limit = max(1, min(limit, 500))
    db = get_database()
    entries = db.get_calibration_changelog(module, governance_area, limit)
    return {"entries": entries}


# NOTE: the two parametrized routes below (/{module}/{area}) MUST stay
# registered after /changelog/list -- FastAPI/Starlette match routes in
# registration order, and /{module}/{area} would otherwise swallow
# GET /calibration/changelog/list as module="changelog", area="list".


@router.get("/{module}/{area}", summary="Current calibration row for a module+area")
async def get_calibration(module: str, area: str, action_type: Optional[str] = None) -> Dict[str, Any]:
    if module not in _VALID_MODULES:
        raise HTTPException(status_code=400, detail=f"module must be one of {_VALID_MODULES}")
    db = get_database()
    row = db.get_calibration_row(module, area, action_type)
    if row is None:
        raise HTTPException(status_code=404, detail="No calibration row for that module/area/action_type")
    return {"module": module, "governance_area": area, "row": row}


@router.put("/{module}/{area}", summary="Update a calibration row (admin only, always changelogged)")
async def update_calibration(module: str, area: str, payload: CalibrationUpdateIn, request: Request) -> Dict[str, Any]:
    if module not in _VALID_MODULES:
        raise HTTPException(status_code=400, detail=f"module must be one of {_VALID_MODULES}")

    principal = _require_admin_principal(request)

    db = get_database()
    previous_row = db.get_calibration_row(module, area, payload.action_type)
    if previous_row is None:
        raise HTTPException(
            status_code=404,
            detail="No existing calibration row for that module/area/action_type -- "
                   "this endpoint only updates rows that already exist.",
        )

    updated_row = db.update_calibration_row(module, area, payload.fields, payload.action_type)
    if updated_row is None:
        raise HTTPException(
            status_code=400,
            detail="None of the supplied fields are editable for this module, or the update matched no row.",
        )

    # The changelog entry only records the fields that were actually part
    # of this update (not the whole row before/after), so the diff stays
    # readable even for modules with large JSONB columns.
    changed_keys = [k for k in payload.fields if k in updated_row]
    previous_value = {k: previous_row.get(k) for k in changed_keys}
    new_value = {k: updated_row.get(k) for k in changed_keys}

    changelog_entry = db.record_calibration_change({
        "module": module,
        "governance_area": area,
        "action_type": payload.action_type,
        "previous_value": previous_value,
        "new_value": new_value,
        "reason": payload.reason,
        "source_name": payload.source_name,
        "source_url": payload.source_url,
        "changed_by": principal.get("email", "unknown"),
    })

    # Calibration is cached in-process by CGCDBLoader (app/Core/db/
    # cgc_db_loader.py) -- without invalidating it, this Vercel instance
    # would keep serving the pre-update values until its next cold start.
    try:
        from app.Core.db.cgc_db_loader import get_db_loader
        get_db_loader().reload_all()
    except Exception as e:
        logger.warning(f"[calibration] cache reload after update failed (non-fatal): {e}")

    return {"row": updated_row, "changelog_entry": changelog_entry}
