"""
Enterprise SAML connections (Database.save_saml_connection/
get_saml_connection/list_saml_connections, cgc_saml_connections). Needs
a real Postgres -- see conftest.py's `db` fixture. The actual
cryptographic assertion verification (python3-saml/xmlsec against a real
IdP-signed response) can't be unit-tested here without a real IdP or a
hand-crafted assertion that would only prove my own test fixture
correct, not the real flow -- that's exercised live via TestClient
against the production DB instead (see the session's own verification
notes), not in this file.
"""

_FAKE_CERT = "-----BEGIN CERTIFICATE-----\nMIIBxxxxFAKEFAKEFAKEFAKEFAKE\n-----END CERTIFICATE-----"


def test_save_saml_connection_then_get_returns_it(db):
    row = db.save_saml_connection(
        "test-domain-1.example", "https://idp.example/entity",
        "https://idp.example/sso", _FAKE_CERT, created_by="pytest@local",
    )
    assert row["domain"] == "test-domain-1.example"
    assert row["active"] is True

    fetched = db.get_saml_connection("test-domain-1.example")
    assert fetched["idp_sso_url"] == "https://idp.example/sso"


def test_save_saml_connection_upserts_on_conflict(db):
    db.save_saml_connection(
        "test-domain-2.example", "https://old-idp.example/entity",
        "https://old-idp.example/sso", _FAKE_CERT, created_by="pytest@local",
    )
    db.save_saml_connection(
        "test-domain-2.example", "https://new-idp.example/entity",
        "https://new-idp.example/sso", _FAKE_CERT, created_by="pytest@local",
    )
    row = db.get_saml_connection("test-domain-2.example")
    assert row["idp_entity_id"] == "https://new-idp.example/entity"
    assert row["idp_sso_url"] == "https://new-idp.example/sso"


def test_get_saml_connection_returns_none_when_unconfigured(db):
    assert db.get_saml_connection("no-such-domain.example") is None


def test_list_saml_connections_includes_created_rows(db):
    db.save_saml_connection(
        "test-domain-3.example", "https://idp3.example/entity",
        "https://idp3.example/sso", _FAKE_CERT, created_by="pytest@local",
    )
    domains = [c["domain"] for c in db.list_saml_connections()]
    assert "test-domain-3.example" in domains
