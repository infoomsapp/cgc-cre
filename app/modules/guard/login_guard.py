"""
Login-attempt guard over cgc_guard.login_attempts -- backs AuthSystem.login()'s
brute-force lockout (now distributed, was in-memory) and adds a real
credential-stuffing pattern detector on top of the same table.

Soft-flag only: detect_credential_stuffing() never blocks anything by
itself -- it logs a warning so the pattern is visible (dashboard/log
search), while check_login_lockout() is the actual gate, same 5-attempts/
15-minute threshold AuthSystem already used before this, just durable now.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.login")

LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 900  # 15 minutes -- same numbers AuthSystem already used

STUFFING_DISTINCT_EMAIL_THRESHOLD = 3
STUFFING_WINDOW_SECONDS = 300  # 5 minutes


def record_login_attempt(ip: Optional[str], email: str, success: bool) -> None:
    if not ip:
        return
    db = get_database()
    try:
        with db.get_connection() as conn:
            if conn is None:
                return
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO cgc_guard.login_attempts (ip, email, success) VALUES (%s, %s, %s)",
                (ip, email, success)
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"[guard] failed to record login attempt (non-fatal): {e}")


def check_login_lockout(ip: Optional[str]) -> bool:
    """Returns True if this IP is allowed to attempt login, False if locked out."""
    if not ip:
        return True
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(seconds=LOCKOUT_WINDOW_SECONDS)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return True
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) AS c FROM cgc_guard.login_attempts "
                "WHERE ip = %s AND success = FALSE AND created_at >= %s",
                (ip, since)
            )
            row = cur.fetchone()
            failed_count = row["c"] if row else 0
            return failed_count < LOCKOUT_MAX_ATTEMPTS
    except Exception as e:
        logger.warning(f"[guard] lockout check failed for ip={ip}, allowing: {e}")
        return True


def get_login_activity_stats(hours: int = 24) -> Dict[str, Any]:
    """
    Dashboard/visibility read -- aggregate login activity over the trailing
    window: totals, failure rate, and which IPs are currently over the
    credential-stuffing distinct-email threshold (a live view of the same
    check detect_credential_stuffing runs per-attempt).
    """
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return {"total": 0, "failed": 0, "succeeded": 0, "flagged_ips": []}
            cur = conn.cursor()

            cur.execute(
                "SELECT COUNT(*) AS total, "
                "COUNT(*) FILTER (WHERE success = TRUE) AS succeeded, "
                "COUNT(*) FILTER (WHERE success = FALSE) AS failed "
                "FROM cgc_guard.login_attempts WHERE created_at >= %s",
                (since,)
            )
            totals = cur.fetchone()

            cur.execute(
                "SELECT ip, COUNT(DISTINCT email) AS distinct_emails, COUNT(*) AS attempts "
                "FROM cgc_guard.login_attempts "
                "WHERE created_at >= %s AND ip IS NOT NULL "
                "GROUP BY ip HAVING COUNT(DISTINCT email) >= %s "
                "ORDER BY distinct_emails DESC LIMIT 20",
                (since, STUFFING_DISTINCT_EMAIL_THRESHOLD)
            )
            flagged = [dict(r) for r in cur.fetchall()]

            return {
                "total": totals["total"] if totals else 0,
                "succeeded": totals["succeeded"] if totals else 0,
                "failed": totals["failed"] if totals else 0,
                "flagged_ips": flagged,
                "window_hours": hours,
            }
    except Exception as e:
        logger.warning(f"[guard] failed to read login activity stats (non-fatal): {e}")
        return {"total": 0, "failed": 0, "succeeded": 0, "flagged_ips": []}


def detect_credential_stuffing(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Soft-flag signal: many DISTINCT emails attempted from one IP in a short
    window is the credential-stuffing shape (as opposed to one user
    fat-fingering their own password repeatedly, which is same-email).
    Returns flag details if the pattern fires, else None. Never blocks --
    call check_login_lockout() separately for the actual gate.
    """
    if not ip:
        return None
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(seconds=STUFFING_WINDOW_SECONDS)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return None
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(DISTINCT email) AS c FROM cgc_guard.login_attempts "
                "WHERE ip = %s AND created_at >= %s",
                (ip, since)
            )
            row = cur.fetchone()
            distinct_emails = row["c"] if row else 0

            if distinct_emails >= STUFFING_DISTINCT_EMAIL_THRESHOLD:
                flag = {
                    "ip": ip,
                    "distinct_emails": distinct_emails,
                    "window_seconds": STUFFING_WINDOW_SECONDS,
                }
                logger.warning(f"[guard] credential-stuffing pattern detected: {flag}")
                return flag
            return None
    except Exception as e:
        logger.warning(f"[guard] credential-stuffing check failed for ip={ip} (non-fatal): {e}")
        return None
