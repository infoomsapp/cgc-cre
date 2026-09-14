"""Unit tests for CGCCoreClient -- mocks the HTTP layer, no live server or
database needed. Verifies request shaping (headers, form vs. JSON
encoding, query params) and error mapping, not server behavior."""

import json

import pytest
import responses

from cgc_core_sdk import CGCCoreAPIError, CGCCoreAuthError, CGCCoreClient

BASE = "https://cgc-cre.example.test"


@pytest.fixture
def client():
    return CGCCoreClient(base_url=BASE, token="tok_abc123")


@responses.activate
def test_signin_stores_token():
    responses.add(
        responses.POST,
        f"{BASE}/auth/signin",
        json={"access_token": "jwt-xyz", "token_type": "bearer", "user": {"email": "a@b.com"}},
        status=200,
    )
    c = CGCCoreClient(base_url=BASE)
    result = c.signin("a@b.com", "pw")
    assert c.token == "jwt-xyz"
    assert result["user"]["email"] == "a@b.com"


@responses.activate
def test_submit_decision_sends_form_encoded_json_strings(client):
    def match_body(request):
        body = dict(pair.split("=") for pair in request.body.split("&"))
        import urllib.parse
        body = {k: urllib.parse.unquote_plus(v) for k, v in body.items()}
        assert json.loads(body["input_data"]) == {"amount": 100}
        assert json.loads(body["data_domains"]) == ["financial"]
        assert body["org_id"] == "acme"
        return (200, {}, json.dumps({"decision": "ALLOW", "decision_id": "dec_1"}))

    responses.add_callback(
        responses.POST, f"{BASE}/governance/decision", callback=match_body,
        content_type="application/json",
    )
    result = client.submit_decision(
        org_id="acme", action="review", input_data={"amount": 100},
        user_email="u@acme.com", data_domains=["financial"], app_source="acme-app",
    )
    assert result["decision"] == "ALLOW"


@responses.activate
def test_auth_header_sent(client):
    def check_auth(request):
        assert request.headers["Authorization"] == "Bearer tok_abc123"
        return (200, {}, json.dumps({"apps": []}))

    responses.add_callback(responses.GET, f"{BASE}/tenants/my-apps", callback=check_auth)
    client.list_my_apps()


@responses.activate
def test_401_raises_auth_error(client):
    responses.add(responses.GET, f"{BASE}/tenants/my-apps", json={"detail": "Invalid token"}, status=401)
    with pytest.raises(CGCCoreAuthError) as exc_info:
        client.list_my_apps()
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"


@responses.activate
def test_400_raises_generic_api_error_not_auth_error(client):
    responses.add(
        responses.PUT,
        f"{BASE}/tenants/my-apps/acme/weighting/DEFAULT/LOW",
        json={"detail": "ecm_weight must be between 0.0 and 1.0"},
        status=400,
    )
    with pytest.raises(CGCCoreAPIError) as exc_info:
        client.set_weighting(
            "acme", "DEFAULT", "LOW",
            ecm_weight=1.5, pfm_weight=0.2, pan_weight=0.2, sda_weight=0.1,
            approval_threshold=0.5,
        )
    assert not isinstance(exc_info.value, CGCCoreAuthError)
    assert exc_info.value.status_code == 400


@responses.activate
def test_health_needs_no_token():
    responses.add(responses.GET, f"{BASE}/health", json={"status": "ok"}, status=200)
    c = CGCCoreClient(base_url=BASE)  # no token
    assert c.health() == {"status": "ok"}


@responses.activate
def test_list_errors_query_params(client):
    def check_params(request):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(request.url).query)
        assert qs["app_source"] == ["acme"]
        assert qs["resolved"] == ["False"]
        assert qs["limit"] == ["50"]
        return (200, {}, json.dumps({"total": 0, "reports": []}))

    responses.add_callback(responses.GET, f"{BASE}/monitor/errors", callback=check_params)
    client.list_errors(app_source="acme", resolved=False, limit=50)
