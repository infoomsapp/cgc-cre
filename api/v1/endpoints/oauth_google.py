"""
GET /auth/google/status    -- {"configured": bool}, lets the dashboard hide
                               the button before Google Cloud setup is done
GET /auth/google/login     -- redirects to Google's OAuth consent screen
GET /auth/google/callback  -- exchanges the code, verifies the ID token,
                               issues a real CGC Core session, redirects
                               back to the dashboard with the token

"Continue with Google" login for /dashboard/account -- one identity
provider (Google OIDC), not SAML, not CGC Core acting as an OAuth
provider for anyone else. Mounted in main.py with NO auth dependency --
these ARE the login entry points, same as /auth/signup and /auth/signin.

Security notes (read before touching this file):
- The `state` cookie is the CSRF protection for the whole flow -- the
  callback MUST reject any request whose `state` query param doesn't
  match it. Never skip this check "to make testing easier".
- The ID token is verified via google.oauth2.id_token.verify_oauth2_token
  -- this checks signature (against Google's real, rotating JWKS),
  issuer, audience, and expiry all at once. Never parse/trust the JWT's
  claims without this call actually succeeding first.
- email_verified must be true in the verified claims before treating the
  email as authoritative -- Google allows unverified emails on some
  account types.
- The session token is returned to the browser in the URL FRAGMENT
  (`#token=...`), never a query parameter -- a fragment is never sent to
  the server by the browser on subsequent requests and never appears in
  server access logs, unlike a query string.
"""

import os
import secrets
import logging
from typing import Any, Dict
from urllib.parse import urlencode

import aiohttp
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_auth_requests

logger = logging.getLogger("cgc.oauth_google")

router = APIRouter()

_STATE_COOKIE = "cgc_oauth_state"
_STATE_MAX_AGE_SECONDS = 600  # 10 minutes -- plenty for a real consent flow, short enough to limit replay
_GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


def _config() -> Dict[str, str]:
    return {
        "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
        "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
        "redirect_uri": os.getenv("GOOGLE_OAUTH_REDIRECT_URI", ""),
    }


def _is_configured(cfg: Dict[str, str]) -> bool:
    return bool(cfg["client_id"] and cfg["client_secret"] and cfg["redirect_uri"])


@router.get("/status")
async def google_oauth_status() -> Dict[str, Any]:
    return {"configured": _is_configured(_config())}


@router.get("/login")
async def google_oauth_login() -> RedirectResponse:
    cfg = _config()
    if not _is_configured(cfg):
        raise HTTPException(status_code=503, detail="Google sign-in is not configured on this server")

    state = secrets.token_urlsafe(24)
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    resp = RedirectResponse(url=f"{_GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}", status_code=307)
    resp.set_cookie(
        _STATE_COOKIE, state,
        max_age=_STATE_MAX_AGE_SECONDS, httponly=True, secure=True, samesite="lax",
    )
    return resp


@router.get("/callback")
async def google_oauth_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    cfg = _config()
    if not _is_configured(cfg):
        raise HTTPException(status_code=503, detail="Google sign-in is not configured on this server")

    cookie_state = request.cookies.get(_STATE_COOKIE)
    if not code or not state or not cookie_state or not secrets.compare_digest(state, cookie_state):
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state -- please try signing in again")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                _GOOGLE_TOKEN_ENDPOINT,
                data={
                    "code": code,
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "redirect_uri": cfg["redirect_uri"],
                    "grant_type": "authorization_code",
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.warning(f"[oauth_google] token exchange failed: {resp.status} {body[:300]}")
                    raise HTTPException(status_code=502, detail="Google token exchange failed")
                token_response = await resp.json()
    except aiohttp.ClientError as e:
        logger.warning(f"[oauth_google] token exchange request failed: {e}")
        raise HTTPException(status_code=502, detail="Could not reach Google")

    raw_id_token = token_response.get("id_token")
    if not raw_id_token:
        raise HTTPException(status_code=502, detail="Google did not return an ID token")

    try:
        claims = google_id_token.verify_oauth2_token(
            raw_id_token, google_auth_requests.Request(), audience=cfg["client_id"]
        )
    except ValueError as e:
        logger.warning(f"[oauth_google] ID token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid Google ID token")

    if not claims.get("email_verified"):
        raise HTTPException(status_code=403, detail="Google account email is not verified")
    email = claims.get("email")
    if not email:
        raise HTTPException(status_code=502, detail="Google token did not include an email claim")

    client_ip = request.client.host if request.client else None
    result = request.app.auth.login_federated(email, ip=client_ip)
    if not result.get("success"):
        detail = result.get("error", "Sign-in failed")
        status_code = 403 if result.get("blocked") else 401
        raise HTTPException(status_code=status_code, detail=detail)

    resp = RedirectResponse(url=f"/dashboard/account#token={result['token']}", status_code=302)
    resp.delete_cookie(_STATE_COOKIE)
    return resp
