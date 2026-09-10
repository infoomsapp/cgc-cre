"""
GET    /launch-readiness/{app_source}/summary            -- aggregate view
GET    /launch-readiness/{app_source}/checklist           -- list manual items
POST   /launch-readiness/{app_source}/checklist           -- create/update a manual item
DELETE /launch-readiness/{app_source}/checklist/{item_id} -- remove a manual item
POST   /launch-readiness/{app_source}/refresh              -- re-pull automated signals

Launch-readiness tracking for Play Store / App Store submission, scoped
per app_source. Three signal sources roll into one view:
  1. A manual checklist (admin-edited rows) for the things no API can
     verify -- Play Console / Apple Developer account state, Stripe
     live-mode confirmation, etc.
  2. A "repo" signal -- a launch_readiness.json manifest committed to
     each app's repo root, fetched from raw.githubusercontent.com on
     refresh (both ControlMiles repos are public, no token needed).
  3. A "supabase" signal -- the project's own security/performance
     advisors, pulled directly from Supabase's Management API on
     refresh (needs SUPABASE_MANAGEMENT_PAT -- a Management API personal
     access token, NOT the project's anon/service-role key).

Auth: same Bearer-token scheme as the rest of the API, applied at the
router-mount level in main.py (dependencies=[Depends(get_current_user)]),
same as monitor.py -- this file carries no auth logic of its own. Write
routes (checklist create/delete, refresh) are not further admin-gated,
matching monitor.py's own resolve/delete endpoints (an authenticated
caller managing this app's own data, not a platform-wide/billing action);
refresh is rate-limited tighter than reads since it costs real outbound
calls.
"""

import os
import logging
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from app.Core.db.database import get_database
from app.modules.guard.rate_limiter import check_rate_limit
from api.v1.endpoints.monitor import ALLOWED_APP_SOURCES

logger = logging.getLogger("cgc.launch_readiness")

router = APIRouter()

_RATE_LIMIT = 30
_RATE_WINDOW = 60
_REFRESH_RATE_LIMIT = 5
_REFRESH_RATE_WINDOW = 300
_HTTP_TIMEOUT_SECONDS = 10

_VALID_STATUSES = {"done", "pending", "blocked"}

# Per-app_source config for the automated pulls -- only controlmiles is
# wired for now. ALLOWED_APP_SOURCES already covers the other apps; this
# map is what actually gates whether /refresh has anything real to fetch
# for a given app_source (falls back to a clear "not configured" result
# rather than a broken request).
_REPO_MANIFEST_URLS: Dict[str, str] = {
    "controlmiles": "https://raw.githubusercontent.com/CEOOMS01/ControlMiles-app/main/launch_readiness.json",
}
_SUPABASE_PROJECT_REFS: Dict[str, str] = {
    "controlmiles": "zuujwmcftycmdaxesdya",
}


def _require_valid_app_source(app_source: str) -> None:
    if app_source not in ALLOWED_APP_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unknown app_source: {app_source}")


class ChecklistItemIn(BaseModel):
    model_config = ConfigDict(str_max_length=2000)

    id: Optional[int] = None
    category: str
    item: str
    status: str = "pending"
    note: Optional[str] = None


@router.get("/{app_source}/summary", summary="Aggregate launch-readiness view")
async def get_summary(app_source: str) -> Dict[str, Any]:
    _require_valid_app_source(app_source)
    db = get_database()
    items = db.list_checklist_items(app_source)
    snapshots = db.get_latest_snapshots(app_source)

    counts = {"done": 0, "pending": 0, "blocked": 0}
    for it in items:
        status = it.get("status", "pending")
        counts[status] = counts.get(status, 0) + 1

    return {
        "app_source": app_source,
        "checklist_counts": counts,
        "checklist_total": len(items),
        "snapshots": snapshots,
    }


@router.get("/{app_source}/checklist", summary="List manual checklist items")
async def list_checklist(app_source: str) -> Dict[str, Any]:
    _require_valid_app_source(app_source)
    db = get_database()
    return {"items": db.list_checklist_items(app_source)}


@router.post("/{app_source}/checklist", summary="Create or update a manual checklist item")
async def upsert_checklist_item(
    app_source: str, payload: ChecklistItemIn, request: Request
) -> Dict[str, Any]:
    _require_valid_app_source(app_source)

    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"launch_readiness:write:{client_ip}", _RATE_LIMIT, _RATE_WINDOW):
        raise HTTPException(status_code=429, detail="Too many requests -- slow down")

    if payload.status not in _VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_VALID_STATUSES)}")

    updated_by = None
    auth_header = request.headers.get("authorization", "")
    token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
    principal = request.app.auth.verify_token(token) if (token and request.app.auth) else None
    if principal:
        updated_by = principal.get("email")

    db = get_database()
    row = db.save_checklist_item({
        "id": payload.id,
        "app_source": app_source,
        "category": payload.category,
        "item": payload.item,
        "status": payload.status,
        "note": payload.note,
        "updated_by": updated_by,
    })
    if not row:
        raise HTTPException(status_code=404, detail="Item not found (or belongs to a different app_source)")
    return row


@router.delete("/{app_source}/checklist/{item_id}", summary="Delete a manual checklist item")
async def delete_checklist_item(app_source: str, item_id: int) -> Dict[str, Any]:
    _require_valid_app_source(app_source)
    db = get_database()
    ok = db.delete_checklist_item(item_id, app_source)
    if not ok:
        raise HTTPException(status_code=404, detail="No checklist item with that id for this app_source")
    return {"deleted": True, "id": item_id}


@router.post("/{app_source}/refresh", summary="Re-pull automated signals (repo manifest + Supabase advisors)")
async def refresh_signals(app_source: str, request: Request) -> Dict[str, Any]:
    _require_valid_app_source(app_source)

    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"launch_readiness:refresh:{client_ip}", _REFRESH_RATE_LIMIT, _REFRESH_RATE_WINDOW):
        raise HTTPException(status_code=429, detail="Too many refresh requests -- try again later")

    db = get_database()
    results: Dict[str, Any] = {}

    repo_url = _REPO_MANIFEST_URLS.get(app_source)
    if repo_url:
        results["repo"] = await _fetch_repo_manifest(app_source, repo_url, db)
    else:
        results["repo"] = {"configured": False, "reason": "no repo manifest URL configured for this app_source"}

    project_ref = _SUPABASE_PROJECT_REFS.get(app_source)
    if project_ref:
        results["supabase"] = await _fetch_supabase_advisors(app_source, project_ref, db)
    else:
        results["supabase"] = {"configured": False, "reason": "no Supabase project configured for this app_source"}

    return {"app_source": app_source, "refreshed": results}


async def _fetch_repo_manifest(app_source: str, url: str, db) -> Dict[str, Any]:
    try:
        timeout = aiohttp.ClientTimeout(total=_HTTP_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return {"configured": True, "ok": False, "reason": f"GitHub returned {resp.status}"}
                manifest = await resp.json(content_type=None)
    except Exception as e:
        logger.warning(f"[launch_readiness] repo manifest fetch failed for {app_source}: {e}")
        return {"configured": True, "ok": False, "reason": str(e)}

    saved = db.save_snapshot(app_source, "repo", manifest)
    return {"configured": True, "ok": True, "fetched_at": saved.get("fetched_at"), "payload": manifest}


async def _fetch_supabase_advisors(app_source: str, project_ref: str, db) -> Dict[str, Any]:
    pat = os.getenv("SUPABASE_MANAGEMENT_PAT")
    if not pat:
        return {"configured": False, "reason": "SUPABASE_MANAGEMENT_PAT not set"}

    headers = {"Authorization": f"Bearer {pat}"}
    payload: Dict[str, Any] = {}
    try:
        timeout = aiohttp.ClientTimeout(total=_HTTP_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for kind in ("security", "performance"):
                async with session.get(
                    f"https://api.supabase.com/v1/projects/{project_ref}/advisors/{kind}"
                ) as resp:
                    if resp.status != 200:
                        payload[kind] = {"ok": False, "status": resp.status}
                        continue
                    data = await resp.json(content_type=None)
                    lints = data.get("lints", []) if isinstance(data, dict) else []
                    by_level: Dict[str, int] = {}
                    for lint in lints:
                        level = lint.get("level", "unknown")
                        by_level[level] = by_level.get(level, 0) + 1
                    payload[kind] = {"ok": True, "total": len(lints), "by_level": by_level}
    except Exception as e:
        logger.warning(f"[launch_readiness] Supabase advisors fetch failed for {app_source}: {e}")
        return {"configured": True, "ok": False, "reason": str(e)}

    saved = db.save_snapshot(app_source, "supabase", payload)
    return {"configured": True, "ok": True, "fetched_at": saved.get("fetched_at"), "payload": payload}
