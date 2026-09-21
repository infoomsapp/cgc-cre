"""
POST /analytics/pageview   -- public beacon, called from the visitor's own
                               browser on the tracked site (controlmiles.com
                               today, ledgiproof.com next)
GET  /analytics/summary    -- active visitors / top paths / today's total,
                               admin-only
GET  /analytics/stream     -- SSE live feed of new pageviews, admin-only

2026-09-21, explicit user request: "cgc core me muestre las visitas a mi
pagina en tiempo real." Deliberately its own router, not folded into
monitor.py -- that file's whole scope is client-CRASH telemetry (frontend
JS errors), a different concern with a different caller (an app's own
report-error edge function, never a plain browser fetch) and a different
trust model (bearer-token app_source, not a public unauthenticated beacon).

No cookies, no third-party tracking pixel, no persistent visitor
identifier: session_id is generated fresh by the browser beacon per tab
session (sessionStorage, not localStorage) and never tied to an account or
email -- consistent with the privacy policy's existing "we do not
currently use third-party advertising networks" line, which this must not
quietly violate.

Auth is per-route, not router-level (unlike monitor.py's uniform
dependencies=[Depends(get_current_user)] at the include_router() call in
main.py): POST /pageview is called directly from an anonymous visitor's
browser, which structurally cannot hold a bearer token/secret, so it must
stay open (rate-limited instead). GET /summary and /stream are for the
dashboard only and DO require an admin/service principal -- checked
manually via request.app.auth, same pattern launch_readiness.py's own
_require_valid_app_source already uses for the same "this router needs
per-route, not uniform, auth" reason.
"""

import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.Core.db.database import get_database
from app.modules.guard.rate_limiter import check_rate_limit

logger = logging.getLogger("cgc.analytics")

router = APIRouter()

ALLOWED_SITES = {"controlmiles.com"}  # add "ledgiproof.com" once that site wires the beacon in

# Same shape/reasoning as monitor.py's own POST /error limiter: one
# visitor's browser could legitimately fire a handful of these per minute
# (SPA route changes), a script hammering the endpoint should not.
_RATE_LIMIT = 60
_RATE_WINDOW = 60


class PageviewIn(BaseModel):
    model_config = ConfigDict(str_max_length=2000)

    site: str
    path: str
    session_id: str = Field(min_length=8, max_length=64)
    referrer: Optional[str] = None


def _require_admin_or_service(request: Request) -> None:
    auth_header = request.headers.get("authorization", "")
    token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
    principal = request.app.auth.verify_token(token) if (token and request.app.auth) else None
    if not principal or principal.get("role") not in ("admin", "service"):
        raise HTTPException(status_code=401, detail="Admin or service credentials required")


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/pageview", summary="Record a pageview (public beacon)")
async def record_pageview(payload: PageviewIn, request: Request) -> Dict[str, Any]:
    if payload.site not in ALLOWED_SITES:
        raise HTTPException(status_code=400, detail=f"Unknown site: {payload.site}")

    client_ip = _client_ip(request)
    if not check_rate_limit(f"analytics:pageview:{client_ip}", _RATE_LIMIT, _RATE_WINDOW):
        raise HTTPException(status_code=429, detail="Too many requests -- slow down")

    # Vercel's own edge already resolves this on every request that reaches
    # a Vercel-hosted function -- no GeoIP database/service to run or pay
    # for, and it's present regardless of which site is calling in, as
    # long as CGC Core itself stays on Vercel.
    country = request.headers.get("x-vercel-ip-country")

    db = get_database()
    row = db.record_pageview(
        site=payload.site,
        path=payload.path[:500],
        session_id=payload.session_id,
        referrer=(payload.referrer or None),
        country=country,
        user_agent=request.headers.get("user-agent", "")[:300],
    )
    return {"recorded": True, **row}


@router.get("/summary", summary="Aggregate visitor stats for a site")
async def analytics_summary(
    request: Request,
    site: str = Query(...),
    active_window_minutes: int = Query(5, ge=1, le=60),
    top_paths_hours: int = Query(24, ge=1, le=168),
) -> Dict[str, Any]:
    _require_admin_or_service(request)
    if site not in ALLOWED_SITES:
        raise HTTPException(status_code=400, detail=f"Unknown site: {site}")
    db = get_database()
    return db.get_analytics_summary(site, active_window_minutes=active_window_minutes, top_paths_hours=top_paths_hours)


# =========================================================
# LIVE STREAM (SSE) -- same honest design as monitor.py's own
# /errors/stream: server-side polling on a tight ~1.5s cadence, pushed
# down one open connection, self-closing every ~25s so it never depends
# on assuming a particular Vercel function-duration limit. See that
# file's own comment for the full explanation; not repeated here.
# =========================================================
_STREAM_POLL_SECONDS = 1.5
_STREAM_MAX_SECONDS = 25
_STREAM_KEEPALIVE_EVERY = 15


async def _pageview_stream_generator(site: str):
    db = get_database()
    cursor = datetime.now(timezone.utc)
    started = asyncio.get_event_loop().time()
    last_keepalive = started

    yield ": connected\n\n"

    while True:
        now = asyncio.get_event_loop().time()
        if now - started >= _STREAM_MAX_SECONDS:
            yield ": closing (max stream duration reached, client will reconnect)\n\n"
            return

        try:
            new_views = db.get_pageviews_since(site, cursor, limit=50)
        except Exception as exc:
            logger.warning(f"[analytics] stream poll failed (non-fatal, will retry): {exc}")
            new_views = []

        if new_views:
            for view in new_views:
                payload = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in view.items()}
                yield f"data: {json.dumps(payload)}\n\n"
            newest = new_views[-1].get("viewed_at")
            if newest:
                cursor = newest if isinstance(newest, datetime) else datetime.fromisoformat(str(newest))
            last_keepalive = now
        elif now - last_keepalive >= _STREAM_KEEPALIVE_EVERY:
            yield ": keep-alive\n\n"
            last_keepalive = now

        await asyncio.sleep(_STREAM_POLL_SECONDS)


@router.get("/stream", summary="Server-Sent Events stream of new pageviews")
async def stream_pageviews(request: Request, site: str = Query(...)) -> StreamingResponse:
    _require_admin_or_service(request)
    if site not in ALLOWED_SITES:
        raise HTTPException(status_code=400, detail=f"Unknown site: {site}")
    return StreamingResponse(
        _pageview_stream_generator(site),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
