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

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.monitor")

router = APIRouter()

ALLOWED_APP_SOURCES = {"ledgiproof", "ledgiproof-tax-pro"}
ALLOWED_SEVERITIES  = {"info", "warning", "error", "critical"}


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
async def report_error(payload: ErrorReportIn) -> Dict[str, Any]:
    if payload.app_source not in ALLOWED_APP_SOURCES:
        raise HTTPException(status_code=400, detail=f"Unknown app_source: {payload.app_source}")
    severity = payload.severity if payload.severity in ALLOWED_SEVERITIES else "error"

    db = get_database()
    result = db.save_error_report({
        "app_source":  payload.app_source,
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
