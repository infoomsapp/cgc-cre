"""
Phase 3 of the reinforcement plan: internal guard -- misuse detection by
someone already authenticated. Purely read-side over cgc_tco.audit_trail,
same risk profile as flow_scoring.py (no write-path changes) -- it can
never corrupt a decision it didn't influence.

Known, accepted limitation (see project plan/memory): TCO's `module_source`
("actor") is the caller-supplied user_email, and LedgiProof's real
integration sends the same fixed value for every call today
('service@ledgiproof'), not a per-end-user identity. So today there is
exactly one "actor" for all of LedgiProof's traffic --
detect_baseline_deviation and detect_cross_tenant_reach will be mostly
inert/noisy against it. Built anyway, per explicit user decision, ready to
activate meaningfully the day an upstream caller sends real per-user
identifiers. detect_escalation_chains is tenant-scoped, not actor-dependent,
and is real value today regardless.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.internal")

ESCALATION_GAP_MINUTES = 10
CROSS_TENANT_THRESHOLD = 1  # more than this many distinct tenants -> flag


def detect_baseline_deviation(
    tenant_id: str,
    module_source: str,
    window_days: int = 1,
    baseline_days: int = 30,
) -> Optional[Dict[str, Any]]:
    """
    Compares this (tenant_id, module_source) actor's recent action-type mix,
    hour-of-day pattern, and volume against its own preceding baseline.
    Returns a finding dict if anything looks new/off, else None.
    """
    db = get_database()
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=window_days)
    baseline_start = window_start - timedelta(days=baseline_days)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return None
            cur = conn.cursor()

            cur.execute(
                "SELECT action, created_at FROM cgc_tco.audit_trail "
                "WHERE tenant_id = %s AND module_source = %s AND created_at >= %s AND created_at < %s "
                "ORDER BY created_at DESC LIMIT 2000",
                (tenant_id, module_source, window_start, now)
            )
            current_rows = cur.fetchall()

            cur.execute(
                "SELECT action, created_at FROM cgc_tco.audit_trail "
                "WHERE tenant_id = %s AND module_source = %s AND created_at >= %s AND created_at < %s "
                "ORDER BY created_at DESC LIMIT 5000",
                (tenant_id, module_source, baseline_start, window_start)
            )
            baseline_rows = cur.fetchall()
    except Exception as e:
        logger.warning(f"[guard] baseline deviation check failed for {tenant_id}/{module_source} (non-fatal): {e}")
        return None

    if not baseline_rows:
        return None  # nothing to compare against yet

    current_actions = {r["action"] for r in current_rows if r["action"]}
    baseline_actions = {r["action"] for r in baseline_rows if r["action"]}
    new_actions = sorted(current_actions - baseline_actions)

    current_hours = {r["created_at"].hour for r in current_rows if r["created_at"]}
    baseline_hours = {r["created_at"].hour for r in baseline_rows if r["created_at"]}
    off_hours = sorted(current_hours - baseline_hours)

    baseline_daily_avg = len(baseline_rows) / baseline_days
    volume_ratio = (len(current_rows) / window_days) / baseline_daily_avg if baseline_daily_avg > 0 else None

    if not new_actions and not off_hours and (volume_ratio is None or volume_ratio < 3.0):
        return None

    return {
        "tenant_id": tenant_id,
        "module_source": module_source,
        "new_actions": new_actions,
        "off_hours": off_hours,
        "volume_ratio": round(volume_ratio, 2) if volume_ratio is not None else None,
        "current_count": len(current_rows),
        "baseline_daily_avg": round(baseline_daily_avg, 2),
    }


def detect_escalation_chains(
    tenant_id: str,
    window_hours: int = 24,
    gap_minutes: int = ESCALATION_GAP_MINUTES,
) -> List[Dict[str, Any]]:
    """
    Flags a REJECT followed within `gap_minutes` by an APPROVE for the same
    (module_source, action) pair -- the shape of someone probing for the
    edge of a policy. input_data itself isn't stored (only its hash), so
    exact "slightly altered input" comparison isn't possible; same actor +
    same action + reject-then-approve-fast is the closest honest proxy.
    """
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    findings: List[Dict[str, Any]] = []

    try:
        with db.get_connection() as conn:
            if conn is None:
                return []
            cur = conn.cursor()
            cur.execute(
                "SELECT module_source, action, outcome, created_at FROM cgc_tco.audit_trail "
                "WHERE tenant_id = %s AND created_at >= %s "
                "ORDER BY module_source, action, created_at ASC LIMIT 5000",
                (tenant_id, since)
            )
            rows = cur.fetchall()
    except Exception as e:
        logger.warning(f"[guard] escalation chain check failed for {tenant_id} (non-fatal): {e}")
        return []

    gap = timedelta(minutes=gap_minutes)
    prev: Optional[Dict[str, Any]] = None
    for row in rows:
        key = (row["module_source"], row["action"])
        prev_key = (prev["module_source"], prev["action"]) if prev else None

        if (
            prev is not None
            and key == prev_key
            and prev["outcome"] == "REJECT"
            and row["outcome"] == "APPROVE"
            and (row["created_at"] - prev["created_at"]) <= gap
        ):
            findings.append({
                "tenant_id": tenant_id,
                "module_source": row["module_source"],
                "action": row["action"],
                "rejected_at": prev["created_at"].isoformat(),
                "approved_at": row["created_at"].isoformat(),
                "gap_seconds": (row["created_at"] - prev["created_at"]).total_seconds(),
            })

        prev = row

    return findings


def detect_cross_tenant_reach(module_source: str, window_days: int = 7) -> Optional[Dict[str, Any]]:
    """
    Flags an actor whose actions touch more than one tenant_id -- should
    essentially never happen for a real individual actor. Will fire
    continuously for a shared service account (e.g. LedgiProof's
    'service@ledgiproof' today) -- expected, not a bug, per the accepted
    tradeoff of building this ready-to-activate rather than waiting.
    """
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(days=window_days)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return None
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(DISTINCT tenant_id) AS c, array_agg(DISTINCT tenant_id) AS tenants "
                "FROM cgc_tco.audit_trail "
                "WHERE module_source = %s AND tenant_id IS NOT NULL AND created_at >= %s",
                (module_source, since)
            )
            row = cur.fetchone()
    except Exception as e:
        logger.warning(f"[guard] cross-tenant reach check failed for {module_source} (non-fatal): {e}")
        return None

    if not row or (row["c"] or 0) <= CROSS_TENANT_THRESHOLD:
        return None

    return {
        "module_source": module_source,
        "distinct_tenants": row["c"],
        "tenants": row["tenants"],
        "window_days": window_days,
    }


def get_recent_internal_flags(limit: int = 50, flag_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Dashboard/visibility read -- most recent persisted findings, newest first."""
    db = get_database()
    try:
        with db.get_connection() as conn:
            if conn is None:
                return []
            cur = conn.cursor()
            if flag_type:
                cur.execute(
                    "SELECT flag_type, tenant_id, module_source, details, created_at "
                    "FROM cgc_guard.internal_flags WHERE flag_type = %s ORDER BY created_at DESC LIMIT %s",
                    (flag_type, limit)
                )
            else:
                cur.execute(
                    "SELECT flag_type, tenant_id, module_source, details, created_at "
                    "FROM cgc_guard.internal_flags ORDER BY created_at DESC LIMIT %s",
                    (limit,)
                )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"[guard] failed to read internal flags (non-fatal): {e}")
        return []


def record_internal_flag(flag_type: str, tenant_id: Optional[str], module_source: Optional[str], details: Dict[str, Any]) -> None:
    import json as _json
    db = get_database()
    try:
        with db.get_connection() as conn:
            if conn is None:
                return
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO cgc_guard.internal_flags (flag_type, tenant_id, module_source, details) "
                "VALUES (%s, %s, %s, %s)",
                (flag_type, tenant_id, module_source, _json.dumps(details))
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"[guard] failed to record internal flag (non-fatal): {e}")
