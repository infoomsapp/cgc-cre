"""
Circuit breaker over cgc_guard.circuit_breaker_state -- item #2 of the
AI-agent action-governance plan (item #1 was PreFilter's
action_within_capabilities check, see PreFilter.py CHECK 4B).

That check denies a single out-of-bounds request. It does nothing about
the *next* one: an agent whose calls keep tripping PreFilter (blocked
domain, action outside capabilities, scope mismatch, unknown agent, ...)
gets the exact same per-request treatment as a first-time offender --
evaluated fresh, denied, and free to try again immediately. A
compromised or misconfigured caller hammering the boundary can keep
probing indefinitely at whatever rate the plain rate limiter allows.

This adds the actual circuit-breaker semantics: repeated PreFilter
short-circuit denials from the same (org_id, user_email) pair within a
trailing window trip the breaker OPEN, which then denies every request
from that pair immediately -- before PreFilter runs any check at all --
until a cooldown elapses. One HALF_OPEN trial request is then let through;
success (PreFilter ALLOW) closes the breaker, failure re-opens it with a
fresh cooldown. Standard closed/open/half-open shape, not a novel design.

Keyed on (org_id, user_email) rather than agent_id because that's the
only real, stable identity available at the actual production call site
today (see main.py's run_cgc_prefilter -- Agent is synthesized fresh per
request with no backing registry). Once a real agent registry exists,
this can be re-keyed to agent_id without changing the trip/cooldown
mechanics below.

Fails open on any DB error, same as rate_limiter.py and every other
cgc_guard.* check: a broken breaker should never itself cause an outage,
and the underlying PreFilter checks (CHECK 1-4B) still run and still
enforce policy per-request even if this repeated-offender layer is down.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.circuit_breaker")

VIOLATION_THRESHOLD = int(os.getenv("CGC_CIRCUIT_BREAKER_THRESHOLD", "5"))
VIOLATION_WINDOW_SECONDS = int(os.getenv("CGC_CIRCUIT_BREAKER_WINDOW_SECONDS", "600"))
COOLDOWN_SECONDS = int(os.getenv("CGC_CIRCUIT_BREAKER_COOLDOWN_SECONDS", "900"))


def _actor_key(org_id: str, user_email: str) -> str:
    return f"{org_id}:{user_email}"


def check_breaker(org_id: str, user_email: str) -> Optional[Dict[str, Any]]:
    """
    Returns None if the request may proceed to PreFilter (breaker CLOSED,
    or OPEN-but-cooldown-elapsed -- flips to HALF_OPEN and lets this one
    request through as the trial). Returns a block dict (reason,
    cooldown_until) if the breaker is OPEN and still cooling down.
    """
    db = get_database()
    if not db.use_postgres:
        return None

    key = _actor_key(org_id, user_email)
    now = datetime.now(timezone.utc)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return None
            cur = conn.cursor()
            cur.execute(
                "SELECT state, cooldown_until, violation_count FROM cgc_guard.circuit_breaker_state "
                "WHERE actor_key = %s",
                (key,)
            )
            row = cur.fetchone()

            if not row or row["state"] != "OPEN":
                return None

            if row["cooldown_until"] and now < row["cooldown_until"]:
                return {
                    "reason": f"Circuit breaker open for {user_email}@{org_id} after "
                              f"{row['violation_count']} policy violations -- cooling down until "
                              f"{row['cooldown_until'].isoformat()}",
                    "cooldown_until": row["cooldown_until"].isoformat(),
                }

            # Cooldown elapsed: allow exactly one trial request through.
            cur.execute(
                "UPDATE cgc_guard.circuit_breaker_state SET state = 'HALF_OPEN', updated_at = NOW() "
                "WHERE actor_key = %s",
                (key,)
            )
            conn.commit()
            return None
    except Exception as e:
        logger.warning(f"[guard] circuit breaker check failed for {key} (non-fatal, allowing): {e}")
        return None


def record_violation(org_id: str, user_email: str) -> None:
    """Call after a PreFilter short-circuit DENY for (org_id, user_email)."""
    db = get_database()
    if not db.use_postgres:
        return

    key = _actor_key(org_id, user_email)
    now = datetime.now(timezone.utc)
    window_cutoff = now - timedelta(seconds=VIOLATION_WINDOW_SECONDS)
    cooldown_until = now + timedelta(seconds=COOLDOWN_SECONDS)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return
            cur = conn.cursor()
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (key,))

            cur.execute(
                "SELECT state, window_start, violation_count FROM cgc_guard.circuit_breaker_state "
                "WHERE actor_key = %s",
                (key,)
            )
            row = cur.fetchone()

            if not row:
                cur.execute(
                    "INSERT INTO cgc_guard.circuit_breaker_state "
                    "(actor_key, org_id, user_email, violation_count, window_start, state, updated_at) "
                    "VALUES (%s, %s, %s, 1, %s, 'CLOSED', NOW())",
                    (key, org_id, user_email, now)
                )
                conn.commit()
                return

            # A HALF_OPEN trial that itself fails re-opens immediately,
            # regardless of the threshold -- the trial is the whole test.
            if row["state"] == "HALF_OPEN":
                cur.execute(
                    "UPDATE cgc_guard.circuit_breaker_state SET "
                    "state = 'OPEN', opened_at = NOW(), cooldown_until = %s, updated_at = NOW() "
                    "WHERE actor_key = %s",
                    (cooldown_until, key)
                )
                conn.commit()
                logger.warning(f"[guard] circuit breaker RE-OPENED for {key} (half-open trial failed)")
                return

            window_expired = row["window_start"] is None or row["window_start"] < window_cutoff
            new_count = 1 if window_expired else row["violation_count"] + 1
            new_window_start = now if window_expired else row["window_start"]

            if new_count >= VIOLATION_THRESHOLD:
                cur.execute(
                    "UPDATE cgc_guard.circuit_breaker_state SET "
                    "violation_count = %s, window_start = %s, state = 'OPEN', "
                    "opened_at = NOW(), cooldown_until = %s, updated_at = NOW() "
                    "WHERE actor_key = %s",
                    (new_count, new_window_start, cooldown_until, key)
                )
                logger.warning(
                    f"[guard] circuit breaker TRIPPED OPEN for {key}: "
                    f"{new_count} violations in {VIOLATION_WINDOW_SECONDS}s"
                )
            else:
                cur.execute(
                    "UPDATE cgc_guard.circuit_breaker_state SET "
                    "violation_count = %s, window_start = %s, updated_at = NOW() "
                    "WHERE actor_key = %s",
                    (new_count, new_window_start, key)
                )
            conn.commit()
    except Exception as e:
        logger.warning(f"[guard] circuit breaker violation record failed for {key} (non-fatal): {e}")


def record_success(org_id: str, user_email: str) -> None:
    """Call after a PreFilter ALLOW for (org_id, user_email) -- closes the
    breaker if it was CLOSED already (no-op) or HALF_OPEN (trial passed)."""
    db = get_database()
    if not db.use_postgres:
        return

    key = _actor_key(org_id, user_email)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return
            cur = conn.cursor()
            cur.execute(
                "UPDATE cgc_guard.circuit_breaker_state SET "
                "state = 'CLOSED', violation_count = 0, window_start = NULL, "
                "opened_at = NULL, cooldown_until = NULL, updated_at = NOW() "
                "WHERE actor_key = %s AND state != 'CLOSED'",
                (key,)
            )
            if cur.rowcount > 0:
                conn.commit()
                logger.info(f"[guard] circuit breaker CLOSED for {key} (trial succeeded)")
    except Exception as e:
        logger.warning(f"[guard] circuit breaker success record failed for {key} (non-fatal): {e}")


def list_open_breakers(limit: int = 50) -> list:
    """Dashboard/visibility read -- currently OPEN or HALF_OPEN breakers."""
    db = get_database()
    if not db.use_postgres:
        return []

    try:
        with db.get_connection() as conn:
            if conn is None:
                return []
            cur = conn.cursor()
            cur.execute(
                "SELECT actor_key, org_id, user_email, violation_count, state, "
                "opened_at, cooldown_until, updated_at FROM cgc_guard.circuit_breaker_state "
                "WHERE state != 'CLOSED' ORDER BY opened_at DESC NULLS LAST LIMIT %s",
                (limit,)
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.warning(f"[guard] circuit breaker list failed (non-fatal): {e}")
        return []


def reset_breaker(org_id: str, user_email: str) -> bool:
    """Admin manual clear -- forces a tripped breaker back to CLOSED."""
    db = get_database()
    if not db.use_postgres:
        return False

    key = _actor_key(org_id, user_email)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return False
            cur = conn.cursor()
            cur.execute(
                "UPDATE cgc_guard.circuit_breaker_state SET "
                "state = 'CLOSED', violation_count = 0, window_start = NULL, "
                "opened_at = NULL, cooldown_until = NULL, updated_at = NOW() "
                "WHERE actor_key = %s",
                (key,)
            )
            conn.commit()
            return cur.rowcount > 0
    except Exception as e:
        logger.warning(f"[guard] circuit breaker manual reset failed for {key}: {e}")
        return False
