"""
POST /monitor/error                     — ingest a client error report (LedgiProof / LTP)
GET  /monitor/errors                    — list recent reports
GET  /monitor/errors/stats              — aggregated stats
POST /monitor/errors/{fingerprint}/resolve — mark a report resolved

This is plain application-crash telemetry (frontend JS errors / unhandled
rejections forwarded via each app's `report-error` edge function), not a
governed decision — kept separate from the /governance/* pipeline.

Auth: same Bearer-token scheme as the rest of the API, applied at the
router-mount level in main.py (dependencies=[Depends(get_current_user)]),
so this file has no auth logic of its own.
"""

import os
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.Core.db.database import get_database
from app.modules.guard.rate_limiter import check_rate_limit

logger = logging.getLogger("cgc.monitor")

router = APIRouter()

ALLOWED_APP_SOURCES = {"ledgiproof", "ledgiproof-tax-pro", "controlmiles"}
ALLOWED_SEVERITIES  = {"info", "warning", "error", "critical"}

# Rate limiting — POST /error was confirmed unbounded during a live pentest
# (15 concurrent requests, each a distinct fingerprint, all 200'd -- every
# caller shares one bearer token, so nothing before this stopped a leaked
# key, or a buggy client in a retry loop, from growing the table forever).
# 2026-08-23: migrated from an in-memory per-instance deque (the one
# remaining holdout of that bug class -- everything else in this codebase
# already moved to this same Postgres-backed limiter) to
# app.modules.guard.rate_limiter.check_rate_limit, real across every
# Vercel instance, not just the one warm process that happened to serve
# the request. Same 20-per-60s ceiling as before.
_RATE_LIMIT  = 20     # requests
_RATE_WINDOW = 60     # seconds


class ErrorReportIn(BaseModel):
    model_config = ConfigDict(str_max_length=4000)

    app_source:  str
    environment: str = "production"
    severity:    str = "error"
    message:     str
    stack:       Optional[str] = None
    url:         Optional[str] = None
    user_agent:  Optional[str] = None
    context:     Optional[Dict[str, Any]] = None


def _bound_app_source(request: Request) -> Optional[str]:
    """2026-09-14: every route in this file used to check app_source
    against ONLY the static ALLOWED_APP_SOURCES allowlist -- meaning a
    real self-signup tenant's per-tenant API key (app_source bound
    cryptographically at issuance, see AuthSystem.generate_api_key) got
    a 400 from every one of them, same gap already closed on
    /governance/reports and /governance/timeseries. Returns the
    request's bound app_source if its token is a per-tenant key (already
    verified by the router-level get_current_user dependency -- this
    just reads the principal back out, same pattern used elsewhere in
    this file for Slack-alert attribution), or None for an unbound
    caller (the legacy shared CGC_SERVICE_API_KEY, or an admin session),
    which keeps today's allowlist-checked behavior."""
    auth_header = request.headers.get("authorization", "")
    token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
    principal = request.app.auth.verify_token(token) if (token and request.app.auth) else None
    return (principal or {}).get("app_source")


@router.post("/error", summary="Ingest a client error report")
async def report_error(payload: ErrorReportIn, request: Request) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"monitor:{client_ip}", _RATE_LIMIT, _RATE_WINDOW):
        raise HTTPException(status_code=429, detail="Too many error reports — slow down")

    # A per-tenant key's bound app_source is already cryptographically
    # verified at issuance -- trusted outright, no allowlist check. Only
    # an UNBOUND caller (the legacy shared CGC_SERVICE_API_KEY, or an
    # admin session) falls back to the static allowlist, since only then
    # is app_source coming from an untrusted, caller-declared payload field.
    bound_app_source = _bound_app_source(request)
    app_source = bound_app_source or payload.app_source
    if not bound_app_source and app_source not in ALLOWED_APP_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unknown app_source: {app_source}")
    severity = payload.severity if payload.severity in ALLOWED_SEVERITIES else "error"

    db = get_database()
    result = db.save_error_report({
        "app_source":  app_source,
        "environment": payload.environment,
        "severity":    severity,
        "message":     payload.message[:2000],
        "stack":       (payload.stack or "")[:4000],
        "url":         payload.url,
        "user_agent":  payload.user_agent,
        "context":     payload.context or {},
    })

    # Alert on genuinely new errors or anything critical — never let a Slack
    # failure turn a successful ingest into a 500.
    if result.get("first_seen") or severity == "critical":
        try:
            await _alert_slack(payload, result)
        except Exception as exc:
            logger.warning(f"[monitor] Slack alert failed (non-fatal): {exc}")

    return {"accepted": True, **result}


@router.get("/errors", summary="List recent error reports")
async def list_errors(
    request: Request,
    app_source: Optional[str] = Query(None),
    resolved:   Optional[bool] = Query(None),
    since_days: Optional[int] = Query(None, ge=1, le=365),
    limit:      int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    # 2026-09-14: a per-tenant key's bound app_source now OVERRIDES the
    # query param instead of being ignored -- previously any authenticated
    # caller could pass a different app_source and read another tenant's
    # error reports (this endpoint had no scoping at all, unlike every
    # ownership-checked /tenants/my-apps/* route). An unbound caller
    # (legacy shared key / admin) keeps today's unrestricted behavior.
    bound_app_source = _bound_app_source(request)
    db = get_database()
    reports = db.get_error_reports(
        app_source=bound_app_source or app_source, resolved=resolved, since_days=since_days, limit=limit
    )
    return {"total": len(reports), "reports": reports}


@router.get("/errors/stats", summary="Aggregated error stats")
async def error_stats(request: Request, days: int = Query(7, ge=1, le=90)) -> Dict[str, Any]:
    # Same per-tenant scoping as list_errors above -- was global across
    # every app_source for any authenticated caller before this.
    bound_app_source = _bound_app_source(request)
    db = get_database()
    return db.get_error_stats(days=days, app_source=bound_app_source)


@router.post("/errors/{fingerprint}/resolve", summary="Mark an error report resolved")
async def resolve_error(fingerprint: str, request: Request) -> Dict[str, Any]:
    db = get_database()
    bound_app_source = _bound_app_source(request)
    if bound_app_source:
        # A per-tenant key may only resolve its OWN app_source's reports --
        # was reachable for any fingerprint by any authenticated caller
        # before this, same class of gap as list_errors above.
        existing = db.get_error_report(fingerprint)
        if existing and existing.get("app_source") != bound_app_source:
            raise HTTPException(status_code=403, detail="You don't own this error report")
    ok = db.resolve_error_report(fingerprint)
    if not ok:
        raise HTTPException(status_code=404, detail="No error report with that fingerprint")
    return {"resolved": True, "fingerprint": fingerprint}


@router.delete("/errors/{fingerprint}", summary="Permanently delete an error report")
async def delete_error(fingerprint: str, request: Request) -> Dict[str, Any]:
    db = get_database()
    bound_app_source = _bound_app_source(request)
    if bound_app_source:
        existing = db.get_error_report(fingerprint)
        if existing and existing.get("app_source") != bound_app_source:
            raise HTTPException(status_code=403, detail="You don't own this error report")
    ok = db.delete_error_report(fingerprint)
    if not ok:
        raise HTTPException(status_code=404, detail="No error report with that fingerprint")
    return {"deleted": True, "fingerprint": fingerprint}


class BulkDeleteIn(BaseModel):
    fingerprints: List[str] = Field(..., min_length=1, max_length=500)


@router.post("/errors/bulk-delete", summary="Permanently delete multiple error reports in one call")
async def bulk_delete_errors(payload: BulkDeleteIn, request: Request) -> Dict[str, Any]:
    db = get_database()
    bound_app_source = _bound_app_source(request)
    fingerprints = payload.fingerprints
    if bound_app_source:
        # Same per-tenant ownership check as the single-delete route above,
        # applied per fingerprint -- silently drops any fingerprint that
        # isn't this caller's own rather than 403ing the whole batch, since
        # a bulk op mixing owned and not-owned items should still make
        # progress on the ones it legitimately can.
        fingerprints = [
            fp for fp in fingerprints
            if (existing := db.get_error_report(fp)) is None or existing.get("app_source") == bound_app_source
        ]
    deleted = db.delete_error_reports(fingerprints)
    return {"deleted": deleted, "requested": len(payload.fingerprints)}


# ─────────────────────────────────────────────────────────────────────────
#  Slack alerting — best-effort, no-ops cleanly if not configured.
# ─────────────────────────────────────────────────────────────────────────

async def _alert_slack(payload: ErrorReportIn, result: Dict[str, Any]) -> None:
    channel = os.getenv("SLACK_MONITOR_CHANNEL")
    if not os.getenv("SLACK_BOT_TOKEN") or not channel:
        return  # monitoring alerts not configured for this environment

    from app.integrations.slack.slack_teams import SlackIntegration

    label = "NEW" if result.get("first_seen") else "RECURRING (critical)"
    text = (
        f":rotating_light: *{label} error* — `{payload.app_source}` ({payload.environment})\n"
        f"> {payload.message[:300]}\n"
        f"seen {result.get('count')}x · fingerprint `{result.get('fingerprint')}`"
        + (f"\n<{payload.url}|{payload.url}>" if payload.url else "")
    )

    slack = SlackIntegration()
    await slack.send_message(channel=channel, text=text)
