"""
Distributed (Postgres-backed) rate limiting over cgc_guard.rate_limit_events.

Replaces the in-memory, single-Vercel-instance limiters that existed before
this (monitor.py's IP-keyed deque, AuthSystem's own login_attempts dict) --
neither survives a cold start or is shared across instances. This one does,
since it reads/writes the same real Postgres every other module already uses.

Fails open on any DB error -- a broken rate limiter shouldn't take down the
feature it's guarding, same principle already used for LedgiProof's own
version of this exact pattern.
"""

import logging
from datetime import datetime, timedelta, timezone

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.rate_limiter")


def check_rate_limit(key: str, max_count: int, window_seconds: int) -> bool:
    """
    Returns True if the call is allowed (and records it), False if `key`
    has hit `max_count` events within the trailing `window_seconds`.

    The count-then-insert below is guarded by a per-key
    pg_advisory_xact_lock -- same shape already proven for PoD's block
    sequencing and TCO's audit-chain sequencing (both found, live, to have
    the exact same race under genuine concurrency: N simultaneous callers
    all read the same count before any of their inserts land, letting more
    than max_count through in one window). Locks only serialize callers
    sharing the same key (e.g. the same org_id or IP hammering
    /governance/decision at once) -- different keys stay fully parallel.
    """
    db = get_database()
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

    try:
        with db.get_connection() as conn:
            if conn is None:
                return True
            cur = conn.cursor()
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (key,))

            cur.execute(
                "SELECT COUNT(*) AS c FROM cgc_guard.rate_limit_events WHERE key = %s AND created_at >= %s",
                (key, since)
            )
            row = cur.fetchone()
            count = row["c"] if row else 0

            if count >= max_count:
                return False

            cur.execute("INSERT INTO cgc_guard.rate_limit_events (key) VALUES (%s)", (key,))
            conn.commit()
            return True
    except Exception as e:
        logger.warning(f"[guard] rate limit check failed for key={key}, allowing: {e}")
        return True
