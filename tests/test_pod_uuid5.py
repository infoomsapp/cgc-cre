"""
Pure unit tests, no DB required -- pod_ledger's RLS policy (see
Database._create_rls_policies()) reproduces this exact derivation in SQL
(extensions.uuid_generate_v5('6ba7b810-9dad-11d1-80b4-00c04fd430c8'::uuid, ...)),
because pod_ledger.tenant_id is stored as this UUID, not the raw tenant_id
string. A live cross-tenant test caught this mismatch once already
(2026-08-23, "function does not exist" then "permission denied for schema
extensions") -- these tests exist so the next change to either side is
caught before a live deploy, not after.
"""

import uuid

from app.modules.pod.pod_repository import _ledger_uid

# The literal constant embedded in _create_rls_policies()'s pod_ledger
# policy SQL. If uuid.NAMESPACE_DNS's value ever changed (it can't --
# it's fixed by RFC 4122 -- but if this constant were ever copy-paste
# edited wrong), this is what would silently break the policy.
POLICY_NAMESPACE_DNS_LITERAL = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


def test_namespace_dns_matches_the_hardcoded_policy_literal():
    assert str(uuid.NAMESPACE_DNS) == POLICY_NAMESPACE_DNS_LITERAL


def test_ledger_uid_matches_python_uuid5_directly():
    raw = "some-arbitrary-tenant-id-string"
    assert _ledger_uid(raw) == str(uuid.uuid5(uuid.NAMESPACE_DNS, raw))


def test_ledger_uid_is_deterministic():
    assert _ledger_uid("tenant-x") == _ledger_uid("tenant-x")


def test_ledger_uid_differs_by_input():
    assert _ledger_uid("tenant-a") != _ledger_uid("tenant-b")
