"""
Real cross-tenant isolation tests against cgc_app -- the exact manual
verification done live on 2026-08-23 before cutting production over to
RLS, now codified so it's re-checked on every change instead of once.

Connects AS cgc_app (not the admin `postgres`/DATABASE_URL role, which
has rolbypassrls=true and would make every one of these tests pass
trivially and meaninglessly) to prove the RLS policies actually restrict
what a real tenant-scoped connection can see.
"""

import uuid

import psycopg2
import psycopg2.extras
import pytest


def _set_tenant(cur, tenant_id):
    cur.execute("select set_config('cgc.current_tenant_id', %s, false)", (tenant_id,))


@pytest.fixture
def app_conn(rls_ready, cgc_app_dsn):
    conn = psycopg2.connect(cgc_app_dsn, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=10)
    yield conn
    conn.close()


def test_cgc_app_role_does_not_bypass_rls(db, rls_ready):
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("select rolbypassrls from pg_roles where rolname = 'cgc_app'")
        assert cur.fetchone()["rolbypassrls"] is False


def test_inference_intercepts_tenant_isolation(app_conn):
    cur = app_conn.cursor()
    tenant_a, tenant_b = f"test-a-{uuid.uuid4().hex[:8]}", f"test-b-{uuid.uuid4().hex[:8]}"
    decision_a, decision_b = f"dec-a-{uuid.uuid4().hex[:8]}", f"dec-b-{uuid.uuid4().hex[:8]}"

    insert_sql = """
        insert into cgc_pod.inference_intercepts
            (intercept_id, decision_id, tenant_id, input_payload_hash, model_identifier,
             output_payload_hash, intercepted_at, triplet_hash, triplet_signature,
             signing_key_id, pii_detected, pii_fields_count)
        values (%s, %s, %s, 'h', 'test-model', 'h', now(), 'h', 's', 'test-key', false, 0)
    """
    _set_tenant(cur, tenant_a)
    cur.execute(insert_sql, (str(uuid.uuid4()), decision_a, tenant_a))
    _set_tenant(cur, tenant_b)
    cur.execute(insert_sql, (str(uuid.uuid4()), decision_b, tenant_b))
    app_conn.commit()

    _set_tenant(cur, tenant_a)
    cur.execute("select decision_id from cgc_pod.inference_intercepts where decision_id in (%s, %s)", (decision_a, decision_b))
    seen_as_a = {r["decision_id"] for r in cur.fetchall()}
    app_conn.commit()

    _set_tenant(cur, tenant_b)
    cur.execute("select decision_id from cgc_pod.inference_intercepts where decision_id in (%s, %s)", (decision_a, decision_b))
    seen_as_b = {r["decision_id"] for r in cur.fetchall()}
    app_conn.commit()

    assert seen_as_a == {decision_a}
    assert seen_as_b == {decision_b}


def test_pod_ledger_uuid5_policy_end_to_end(app_conn):
    """The specific policy that broke in production once already (see
    test_pod_uuid5.py for the pure-Python half of this same check)."""
    cur = app_conn.cursor()
    raw_tenant = f"test-ledger-{uuid.uuid4().hex[:8]}"
    ledger_tenant_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, raw_tenant))
    decision_id = str(uuid.uuid4())
    unique_hash = f"pytest-{uuid.uuid4().hex}"  # block_hash has a UNIQUE constraint

    _set_tenant(cur, raw_tenant)
    cur.execute(
        """
        insert into cgc_pod.pod_ledger
            (block_uuid, tenant_id, intercept_id, decision_id, block_number,
             previous_block_hash, block_hash, triplet_hash, governance_outcome,
             chain_height, sealed_at, sealed_by, tamper_detected)
        values (%s, %s, %s, %s, 999999999, 'p', %s, 't', 'APPROVE', 999999999, now(), 'pytest', false)
        """,
        (str(uuid.uuid4()), ledger_tenant_uuid, str(uuid.uuid4()), decision_id, unique_hash),
    )
    app_conn.commit()

    _set_tenant(cur, raw_tenant)
    cur.execute("select decision_id from cgc_pod.pod_ledger where decision_id = %s", (decision_id,))
    row = cur.fetchone()
    app_conn.commit()

    assert row is not None, "pod_ledger insert/select failed under cgc_app -- uuid5 policy mismatch"
    assert str(row["decision_id"]) == decision_id


def test_tenant_usage_isolation(app_conn, db):
    cur = app_conn.cursor()
    org_a, org_b = f"test-org-a-{uuid.uuid4().hex[:8]}", f"test-org-b-{uuid.uuid4().hex[:8]}"

    _set_tenant(cur, org_a)
    cur.execute(
        "insert into cgc_guard.tenant_usage (org_id, resource, period, count) values (%s, 'decisions', '2099-01', 5)",
        (org_a,),
    )
    app_conn.commit()

    _set_tenant(cur, org_b)
    cur.execute("select count from cgc_guard.tenant_usage where org_id = %s", (org_a,))
    assert cur.fetchone() is None, "tenant B could see tenant A's usage row"
    app_conn.commit()

    _set_tenant(cur, org_a)
    cur.execute("select count from cgc_guard.tenant_usage where org_id = %s", (org_a,))
    assert cur.fetchone()["count"] == 5
    app_conn.commit()

    # cgc_app deliberately has no DELETE grant (least-privilege by design --
    # this is proof it holds, not a bug) -- cleanup goes through the admin
    # connection instead.
    with db.get_connection() as admin_conn:
        admin_cur = admin_conn.cursor()
        admin_cur.execute("delete from cgc_guard.tenant_usage where org_id = %s", (org_a,))
