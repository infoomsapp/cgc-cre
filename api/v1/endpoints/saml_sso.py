"""
GET  /auth/saml/lookup?email=...        -- {"available": bool, "domain": ...}
GET  /auth/saml/{domain}/login          -- redirects to that customer's IdP
POST /auth/saml/{domain}/acs            -- Assertion Consumer Service
GET  /saml/metadata                     -- this SP's metadata XML

Enterprise SAML SSO -- fundamentally different from Google OIDC
(oauth_google.py): Google uses ONE app-wide Client ID that works for any
Google account. SAML has no equivalent -- each enterprise customer's
Okta/Azure AD/OneLogin tenant is its OWN Identity Provider with its own
Entity ID, SSO URL, and signing certificate. One row per email domain in
cgc_saml_connections (Database.save_saml_connection/get_saml_connection),
admin-provisioned via POST /admin/saml-connections in main.py -- NOT a
self-service customer form for this pass. Getting a customer's raw IdP
metadata wrong (malformed cert, wrong URL) silently locks their whole
company out of login, and onboarding a real enterprise SAML connection is
realistically a white-glove, hands-on conversation anyway.

Uses python3-saml (OneLogin's official, maintained library) for every
cryptographic operation -- signature verification against the IdP's
certificate happens inside process_response()/is_authenticated(), never
re-implemented here. Mounted in main.py with NO auth dependency for the
first 3 routes (these ARE the login entry points, same posture as
/auth/signup, /auth/signin, and oauth_google.py).

Security notes (read before touching this file):
- is_authenticated() AND get_errors() must both be checked after
  process_response() -- a response can fail validation in ways that
  don't set is_authenticated() to False on their own. Never trust a
  response python3-saml hasn't explicitly validated.
- The email extracted from the assertion (NameID, or an attribute if the
  IdP maps email that way) is trusted ONLY because process_response()
  cryptographically verified the assertion came from that domain's
  registered IdP certificate -- never accept an email that arrived any
  other way through this flow.
- SP-initiated only (the user starts at CGC Core, not by clicking a tile
  inside their Okta dashboard) -- IdP-initiated SSO is a different,
  riskier flow (no client-side state to correlate the response against)
  and is deliberately not supported.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.saml_sso")

router = APIRouter()

# This SP's own identity -- fixed, not per-customer. Each customer's IdP
# connection (cgc_saml_connections row) is configured to trust THIS
# entity_id/ACS URL, same way any SAML SP has one identity regardless of
# how many IdPs it federates with. This router is mounted at /auth/saml
# in main.py -- metadata lives at /auth/saml/metadata, not a separate
# /saml/metadata prefix, to avoid a second router mount for one route.
_SP_ENTITY_ID = "https://cgc-cre.vercel.app/auth/saml/metadata"
_SP_ACS_URL = "https://cgc-cre.vercel.app/auth/saml/{domain}/acs"


def _domain_from_email(email: str) -> Optional[str]:
    if "@" not in email:
        return None
    return email.rsplit("@", 1)[-1].strip().lower()


def _saml_settings(domain: str, connection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sp": {
            "entityId": _SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": _SP_ACS_URL.format(domain=domain),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": connection["idp_entity_id"],
            "singleSignOnService": {
                "url": connection["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": connection["idp_x509_cert"],
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
        },
    }


async def _build_saml_request_data(request: Request) -> Dict[str, Any]:
    """python3-saml expects a Django/Flask-shaped request dict, not a
    FastAPI Request object -- this adapts the two, same purpose as
    web-framework integration snippets python3-saml ships for other
    frameworks."""
    form = {}
    if request.method == "POST":
        form_data = await request.form()
        form = dict(form_data)
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": form,
    }


@router.get("/lookup")
async def saml_lookup(email: str) -> Dict[str, Any]:
    domain = _domain_from_email(email)
    if not domain:
        return {"available": False}
    db = get_database()
    connection = db.get_saml_connection(domain)
    return {"available": connection is not None, "domain": domain if connection else None}


@router.get("/{domain}/login")
async def saml_login(domain: str, request: Request) -> RedirectResponse:
    # 2026-09-14: any_status, not the active-only lookup -- a draft
    # (self-service, not yet activated) connection must still be
    # reachable through this same route so its owner can test-login
    # against their real IdP before activating (see saml_acs's draft-mode
    # branch below). /auth/saml/lookup, used to decide whether to SHOW
    # ordinary end users an "SSO" button, is unaffected -- it still only
    # reports active connections as available.
    db = get_database()
    connection = db.get_saml_connection_any_status(domain)
    if not connection:
        raise HTTPException(status_code=404, detail=f"No SSO connection configured for domain '{domain}'")

    req_data = await _build_saml_request_data(request)
    auth = OneLogin_Saml2_Auth(req_data, old_settings=_saml_settings(domain, connection))
    return RedirectResponse(url=auth.login(), status_code=302)


@router.post("/{domain}/acs")
async def saml_acs(domain: str, request: Request) -> RedirectResponse:
    db = get_database()
    connection = db.get_saml_connection_any_status(domain)
    if not connection:
        raise HTTPException(status_code=404, detail=f"No SSO connection configured for domain '{domain}'")

    req_data = await _build_saml_request_data(request)
    auth = OneLogin_Saml2_Auth(req_data, old_settings=_saml_settings(domain, connection))
    auth.process_response()

    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or "; ".join(errors) or "Unknown SAML validation failure"
        logger.warning(f"[saml_sso] assertion rejected for domain={domain}: {reason}")
        raise HTTPException(status_code=401, detail="SAML assertion failed validation")

    email = auth.get_nameid()
    if not email or "@" not in email:
        # Some IdPs put email in an attribute statement instead of NameID.
        attrs = auth.get_attributes()
        email = next((v[0] for k, v in attrs.items() if "email" in k.lower() and v), None)
    if not email:
        raise HTTPException(status_code=502, detail="SAML assertion did not include an email")

    # The assertion is cryptographically verified as coming from THIS
    # domain's registered IdP -- but the email claim itself could still
    # name a different domain (an IdP misconfiguration, not malice) if
    # the customer's IdP is set up to assert other domains too. Reject
    # rather than silently trust a mismatch.
    if _domain_from_email(email) != domain:
        logger.warning(f"[saml_sso] assertion email domain mismatch: expected {domain}, got {email}")
        raise HTTPException(status_code=403, detail="Assertion email does not match the requested domain")

    # 2026-09-14 -- self-service draft-mode test login. A connection that
    # isn't active() yet can't issue a real session (activating it is a
    # separate, explicit step -- see POST /tenants/saml-connections/
    # {domain}/activate in main.py) -- but a successful, cryptographically
    # verified round-trip THIS far already proves the IdP metadata this
    # customer pasted in actually works, which is exactly what
    # activate_saml_connection() requires before it'll flip active=TRUE.
    # No session is issued here on purpose: this endpoint has no auth
    # dependency (it's the real ACS URL, hit by the IdP's redirect, not by
    # a logged-in browser tab), so it can't know WHICH of this domain's
    # accounts is the one that should see "test succeeded" -- it only
    # marks the connection itself as verified and sends the browser back
    # to a page that account can then check via GET /tenants/saml-connections.
    if not connection.get("active"):
        db.mark_saml_connection_test_verified(domain)
        logger.info(f"[saml_sso] draft connection test-verified: domain={domain}")
        return RedirectResponse(url="/dashboard/account?saml_test=success", status_code=302)

    client_ip = request.client.host if request.client else None
    result = request.app.auth.login_federated(email, ip=client_ip)
    if not result.get("success"):
        status_code = 403 if result.get("blocked") else 401
        raise HTTPException(status_code=status_code, detail=result.get("error", "Sign-in failed"))

    return RedirectResponse(url=f"/dashboard/account#token={result['token']}", status_code=302)


@router.get("/metadata", include_in_schema=False)
async def saml_metadata() -> Response:
    """
    This SP's own metadata XML -- what a customer's IT admin pastes into
    their Okta/Azure AD app configuration when setting up their side of
    the connection. Not domain-specific (the SP identity is fixed); the
    ACS URL template here is generic since the real per-domain ACS URL
    is only known once a specific connection exists.
    """
    settings_dict = {
        "sp": {
            "entityId": _SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": _SP_ACS_URL.format(domain="{your-domain}"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": "placeholder",
            "singleSignOnService": {"url": "https://placeholder.example.com", "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
            "x509cert": "",
        },
        # Must match the real per-connection settings in _saml_settings()
        # above -- otherwise a customer's IT admin reading this metadata
        # sees a WEAKER requirement than what login/acs actually enforces.
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
        },
    }
    saml_settings = OneLogin_Saml2_Settings(settings_dict, sp_validation_only=True)
    metadata_xml = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata_xml)
    if errors:
        raise HTTPException(status_code=500, detail=f"Invalid SP metadata: {errors}")
    return Response(content=metadata_xml, media_type="application/xml")
