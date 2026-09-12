"""
Self-service outbound webhooks (Database.save_webhook/get_webhook/
delete_webhook/record_webhook_delivery, cgc_tenant_webhooks). Needs a
real Postgres -- see conftest.py's `db` fixture.
"""


def test_save_webhook_then_get_returns_it(db):
    row = db.save_webhook("test-app-webhooks", "https://example.test/hook", "whsec_abc123", created_by="pytest@local")
    assert row["url"] == "https://example.test/hook"
    assert row["active"] is True

    fetched = db.get_webhook("test-app-webhooks")
    assert fetched["url"] == "https://example.test/hook"
    assert fetched["secret"] == "whsec_abc123"

    db.delete_webhook("test-app-webhooks")


def test_save_webhook_upserts_on_conflict(db):
    db.save_webhook("test-app-webhooks-2", "https://old.test/hook", "whsec_old", created_by="pytest@local")
    db.save_webhook("test-app-webhooks-2", "https://new.test/hook", "whsec_new", created_by="pytest@local")

    row = db.get_webhook("test-app-webhooks-2")
    assert row["url"] == "https://new.test/hook"
    assert row["secret"] == "whsec_new"

    db.delete_webhook("test-app-webhooks-2")


def test_get_webhook_returns_none_when_unconfigured(db):
    assert db.get_webhook("no-such-app-webhooks") is None


def test_delete_webhook_returns_false_when_nothing_to_delete(db):
    assert db.delete_webhook("no-such-app-webhooks") is False


def test_record_webhook_delivery_updates_status(db):
    db.save_webhook("test-app-webhooks-3", "https://example.test/hook", "whsec_x", created_by="pytest@local")
    db.record_webhook_delivery("test-app-webhooks-3", "http_200")

    row = db.get_webhook("test-app-webhooks-3")
    assert row["last_delivery_status"] == "http_200"
    assert row["last_delivery_at"] is not None

    db.delete_webhook("test-app-webhooks-3")


def test_app_source_usage_counter_is_isolated_from_org_id_quota(db):
    """Regression: get_app_source_usage/record_app_source_decision (added
    2026-09-12 for the self-service usage panel) must never touch the
    org_id-keyed quota rows check_quota/reserve_quota rely on -- these are
    a distinct 'app_source:'-prefixed namespace in the same table."""
    from app.Core.tenant.multi_tenant import TenantManager
    tm = TenantManager()

    before = tm.get_app_source_usage("test-app-usage-isolation", plan="FREE")
    tm.record_app_source_decision("test-app-usage-isolation")
    after = tm.get_app_source_usage("test-app-usage-isolation", plan="FREE")

    assert after["decisions_used"] == before["decisions_used"] + 1
    assert after["decisions_quota"] == tm.PLAN_QUOTAS["FREE"]["decisions"]

    # A real org_id quota check for the SAME literal string must be
    # completely unaffected by the app_source counter above.
    org_usage_before = tm._get_usage("test-app-usage-isolation", "decisions")
    assert org_usage_before == 0
