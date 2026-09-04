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


@router.post("/error", summary="Ingest a client error report")
async def report_error(payload: ErrorReportIn, request: Request) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"monitor:{client_ip}", _RATE_LIMIT, _RATE_WINDOW):
        raise HTTPException(status_code=429, detail="Too many error reports — slow down")

    # Gap 1 (per-tenant API keys): the router-level dependency
    # (dependencies=[Depends(get_current_user)] in main.py) already
    # verified this request's Bearer token before this handler ever runs --
    # re-resolving it here (request.app.auth, not importing get_current_user,
    # which would be a circular import against main.py) only reads the
    # already-validated principal back out, to bind app_source to it. A
    # per-tenant key overrides whatever payload.app_source claims; the
    # legacy shared key (no bound app_source) keeps today's behavior --
    # trust the payload, checked against the static allowlist below.
    auth_header = request.headers.get("authorization", "")
    token = auth_header[7:] if auth_header.lower().startswith("bearer ") else auth_header
    principal = request.app.auth.verify_token(token) if (token and request.app.auth) else None
    bound_app_source = (principal or {}).get("app_source")

    app_source = bound_app_source or payload.app_source
    if app_source not in ALLOWED_APP_SOURCES:
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
    app_source: Optional[str] = Query(None),
    resolved:   Optional[bool] = Query(None),
    since_days: Optional[int] = Query(None, ge=1, le=365),
    limit:      int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    db = get_database()
    reports = db.get_error_reports(
        app_source=app_source, resolved=resolved, since_days=since_days, limit=limit
    )
    return {"total": len(reports), "reports": reports}


@router.get("/errors/stats", summary="Aggregated error stats")
async def error_stats(days: int = Query(7, ge=1, le=90)) -> Dict[str, Any]:
    db = get_database()
    return db.get_error_stats(days=days)


@router.post("/errors/{fingerprint}/resolve", summary="Mark an error report resolved")
async def resolve_error(fingerprint: str) -> Dict[str, Any]:
    db = get_database()
    ok = db.resolve_error_report(fingerprint)
    if not ok:
        raise HTTPException(status_code=404, detail="No error report with that fingerprint")
    return {"resolved": True, "fingerprint": fingerprint}


@router.delete("/errors/{fingerprint}", summary="Permanently delete an error report")
async def delete_error(fingerprint: str) -> Dict[str, Any]:
    db = get_database()
    ok = db.delete_error_report(fingerprint)
    if not ok:
        raise HTTPException(status_code=404, detail="No error report with that fingerprint")
    return {"deleted": True, "fingerprint": fingerprint}


class BulkDeleteIn(BaseModel):
    fingerprints: List[str] = Field(..., min_length=1, max_length=500)


@router.post("/errors/bulk-delete", summary="Permanently delete multiple error reports in one call")
async def bulk_delete_errors(payload: BulkDeleteIn) -> Dict[str, Any]:
    db = get_database()
    deleted = db.delete_error_reports(payload.fingerprints)
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
