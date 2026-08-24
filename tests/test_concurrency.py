"""
Real concurrency tests against Postgres -- this project's actual history
of bugs (PoD block sequencing, TCO audit-chain sequencing, tenant quota
reservation, the rate limiter) is entirely this one shape: N simultaneous
callers all read the same "current count" before any of their writes
land, letting more than the limit through. Every one of those was found
live, in production, not by a test -- these exist so the next one isn't.

Uses real threads against a real connection pool (not asyncio mocking)
because the bug class is a genuine database-level race, not a Python
concurrency-primitive one.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest


def test_rate_limiter_never_admits_more_than_max(db):
    from app.modules.guard.rate_limiter import check_rate_limit

    key = f"pytest-ratelimit-{uuid.uuid4().hex[:8]}"
    max_count = 3
    # Kept comfortably under Database's admin pool cap (ThreadedConnectionPool
    # maxconn=20) -- psycopg2's pool raises immediately on exhaustion rather
    # than queuing, so testing the advisory-lock race needs enough concurrent
    # callers to contend for it without also contending for pool slots.
    concurrency = 8

    def call(_):
        return check_rate_limit(key, max_count, window_seconds=60)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(call, range(concurrency)))

    admitted = sum(1 for r in results if r)
    assert admitted == max_count, (
        f"expected exactly {max_count} of {concurrency} concurrent calls to be admitted, "
        f"got {admitted} -- the advisory-lock guard against this exact TOCTOU race regressed"
    )

    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("delete from cgc_guard.rate_limit_events where key = %s", (key,))
        conn.commit()


def test_reserve_quota_never_over_admits(db, monkeypatch):
    from app.Core.tenant.multi_tenant import TenantManager

    # reserve_quota's limit is plan-derived, not a parameter -- FREE's real
    # "decisions" quota (1,000/month) is correct for production but far too
    # large to usefully race in a unit test (the DB connection pool itself
    # caps at 20). Patch it down to something a real race would blow past
    # in one small concurrent burst; restored automatically after the test.
    monkeypatch.setitem(TenantManager.PLAN_QUOTAS["FREE"], "decisions", 3)

    tm = TenantManager()
    org_id = f"pytest-quota-{uuid.uuid4().hex[:8]}"
    tm.upgrade_plan(org_id, "FREE")
    limit = 3
    # See test_rate_limiter_never_admits_more_than_max's comment -- kept
    # under the app pool's cap (get_scoped_connection's ThreadedConnectionPool
    # maxconn=10) so a real race is what's tested, not pool exhaustion.
    concurrency = 8

    def call(_):
        return tm.reserve_quota(org_id, "decisions")

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(call, range(concurrency)))

    admitted = sum(1 for r in results if r)
    assert admitted == limit, (
        f"expected exactly {limit} of {concurrency} concurrent reservations to succeed, "
        f"got {admitted} -- reserve_quota's advisory-lock atomicity regressed"
    )

    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("delete from cgc_guard.tenant_usage where org_id = %s", (org_id,))
        cur.execute("delete from cgc_guard.tenant_plans where org_id = %s", (org_id,))
        conn.commit()
