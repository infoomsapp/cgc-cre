"""
Python client for CGC Core (https://github.com/infoomsapp/cgc-cre).

Covers the self-service integration surface documented in
docs/INTEGRATION_GUIDE.md: account signup/login, claiming an app_source
and getting an API key, submitting governance decisions, reading back
reports/timeseries, application-error monitoring, launch-readiness
tracking, webhook configuration, and per-tenant scoring-weight overrides.

Every authenticated endpoint on this API takes the same single credential
-- an `Authorization: Bearer <token>` header, where <token> is either a
signin JWT (30-day expiry) or a long-lived API key issued via self-signup
or key regeneration (see AuthSystem.verify_token, which accepts both).
This client stores whichever one you give it and sends it the same way on
every request; there is no separate "API key mode" vs "session mode".

Not covered here: platform-admin-only endpoints (/admin/users,
/admin/cleanup/*, /admin/keys/rotation-check, SAML connection management,
billing checkout/portal links) -- those aren't things an integrating
tenant calls themselves, and pulling them in would blur this SDK's actual
audience. Add them later if a real caller needs them.
"""

from __future__ import annotations

import json as _json
from typing import Any, Dict, List, Optional

import requests

from .exceptions import CGCCoreAPIError, CGCCoreAuthError

DEFAULT_BASE_URL = "https://cgc-cre.vercel.app"
DEFAULT_TIMEOUT = 30


class CGCCoreClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._session = session or requests.Session()

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        raw_response: bool = False,
    ):
        url = f"{self.base_url}{path}"
        resp = self._session.request(
            method,
            url,
            json=json_body,
            data=form_data,
            params=params,
            headers=self._headers(),
            timeout=self.timeout,
        )

        if not resp.ok:
            detail: Any
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            error_cls = CGCCoreAuthError if resp.status_code in (401, 403) else CGCCoreAPIError
            raise error_cls(resp.status_code, detail, resp.text)

        if raw_response:
            return resp
        if not resp.content:
            return None
        return resp.json()

    # ------------------------------------------------------------------
    # auth
    # ------------------------------------------------------------------

    def signup(self, email: str, password: str) -> Dict[str, Any]:
        """Create a plain user account (does not sign you in -- call
        signin() after, or use login() to do both)."""
        return self._request("POST", "/auth/signup", json_body={"email": email, "password": password})

    def signin(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate and store the returned JWT on this client for
        subsequent calls. Returns the full {access_token, token_type,
        user} response."""
        result = self._request("POST", "/auth/signin", json_body={"email": email, "password": password})
        self.token = result["access_token"]
        return result

    def login(self, email: str, password: str) -> Dict[str, Any]:
        """signup() then signin() in one call, ignoring a 409 if the
        account already exists -- the common case for a script that just
        wants to end up authenticated."""
        try:
            self.signup(email, password)
        except CGCCoreAPIError as e:
            if e.status_code != 409:
                raise
        return self.signin(email, password)

    def set_token(self, token: str) -> None:
        """Use an existing JWT or API key directly, skipping signin()."""
        self.token = token

    # ------------------------------------------------------------------
    # tenant onboarding / API keys (requires a signed-in user token)
    # ------------------------------------------------------------------

    def claim_app_source(self, app_source: str) -> Dict[str, Any]:
        """Claim a new app_source and receive its first API key. Requires
        an authenticated user token (from signin()/login()), NOT an
        existing API key. The returned key is shown in full only this
        once -- store it now."""
        return self._request("POST", "/tenants/self-signup", json_body={"app_source": app_source})

    def list_my_apps(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/tenants/my-apps")["apps"]

    def regenerate_key(self, app_source: str) -> Dict[str, Any]:
        """Revokes every active key you hold for app_source and issues a
        fresh one."""
        return self._request("POST", f"/tenants/my-apps/{app_source}/keys/regenerate")

    def revoke_key(self, app_source: str, key_id: str) -> Dict[str, Any]:
        return self._request("POST", f"/tenants/my-apps/{app_source}/keys/{key_id}/revoke")

    # ------------------------------------------------------------------
    # governance -- the core product
    # ------------------------------------------------------------------

    def submit_decision(
        self,
        *,
        org_id: str,
        action: str,
        input_data: Dict[str, Any],
        user_email: str,
        data_domains: List[str],
        app_source: str = "unknown",
        area: str = "DEFAULT",
    ) -> Dict[str, Any]:
        """Run one input through the governance pipeline. POST /governance/
        decision is form-encoded (not JSON) on the server side -- input_data
        and data_domains are sent as JSON-encoded strings inside form
        fields; this method does that encoding for you."""
        form = {
            "org_id": org_id,
            "action": action,
            "input_data": _json.dumps(input_data),
            "user_email": user_email,
            "data_domains": _json.dumps(data_domains),
            "app_source": app_source,
            "area": area,
        }
        return self._request("POST", "/governance/decision", form_data=form)

    def get_report_pdf(
        self, app_source: str, from_date: Optional[str] = None, to_date: Optional[str] = None
    ) -> bytes:
        """Returns the raw PDF bytes for a per-app governance report.
        from_date/to_date are ISO date strings (YYYY-MM-DD); defaults to
        the trailing 30 days. Works for any app_source you own (claimed via
        claim_app_source()) or a first-party one."""
        params = {k: v for k, v in {"from_date": from_date, "to_date": to_date}.items() if v}
        resp = self._request("GET", f"/governance/reports/{app_source}", params=params, raw_response=True)
        return resp.content

    def get_timeseries(self, app_source: str, hours: int = 24) -> Dict[str, Any]:
        return self._request("GET", f"/governance/timeseries/{app_source}", params={"hours": hours})

    def get_scoring_methodology(self) -> Dict[str, Any]:
        return self._request("GET", "/governance/scoring-methodology")

    # ------------------------------------------------------------------
    # application error monitoring (crash/exception telemetry)
    # ------------------------------------------------------------------

    def report_error(
        self,
        *,
        app_source: str,
        message: str,
        environment: str = "production",
        severity: str = "error",
        stack: Optional[str] = None,
        url: Optional[str] = None,
        user_agent: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        body = {
            "app_source": app_source,
            "environment": environment,
            "severity": severity,
            "message": message,
            "stack": stack,
            "url": url,
            "user_agent": user_agent,
            "context": context,
        }
        return self._request("POST", "/monitor/error", json_body=body)

    def list_errors(
        self,
        app_source: Optional[str] = None,
        resolved: Optional[bool] = None,
        since_days: Optional[int] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        params = {
            k: v
            for k, v in {
                "app_source": app_source,
                "resolved": resolved,
                "since_days": since_days,
                "limit": limit,
            }.items()
            if v is not None
        }
        return self._request("GET", "/monitor/errors", params=params)

    def error_stats(self, days: int = 7) -> Dict[str, Any]:
        return self._request("GET", "/monitor/errors/stats", params={"days": days})

    def resolve_error(self, fingerprint: str) -> Dict[str, Any]:
        return self._request("POST", f"/monitor/errors/{fingerprint}/resolve")

    def delete_error(self, fingerprint: str) -> Dict[str, Any]:
        return self._request("DELETE", f"/monitor/errors/{fingerprint}")

    def bulk_delete_errors(self, fingerprints: List[str]) -> Dict[str, Any]:
        return self._request("POST", "/monitor/errors/bulk-delete", json_body={"fingerprints": fingerprints})

    # ------------------------------------------------------------------
    # launch readiness (store submission tracking, incl. process errors)
    # ------------------------------------------------------------------

    def get_launch_summary(self, app_source: str) -> Dict[str, Any]:
        return self._request("GET", f"/launch-readiness/{app_source}/summary")

    def list_checklist(self, app_source: str) -> List[Dict[str, Any]]:
        return self._request("GET", f"/launch-readiness/{app_source}/checklist")["items"]

    def upsert_checklist_item(
        self,
        app_source: str,
        *,
        category: str,
        item: str,
        status: str = "pending",
        note: Optional[str] = None,
        item_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        body = {"id": item_id, "category": category, "item": item, "status": status, "note": note}
        return self._request("POST", f"/launch-readiness/{app_source}/checklist", json_body=body)

    def delete_checklist_item(self, app_source: str, item_id: int) -> Dict[str, Any]:
        return self._request("DELETE", f"/launch-readiness/{app_source}/checklist/{item_id}")

    def report_launch_error(
        self,
        app_source: str,
        *,
        source: str,
        message: str,
        severity: str = "error",
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a launch/submission-process error (a store rejection, a
        signing failure, a failed CI build) -- distinct from report_error(),
        which is runtime app telemetry, not the launch process itself."""
        body = {"source": source, "severity": severity, "message": message, "detail": detail}
        return self._request("POST", f"/launch-readiness/{app_source}/errors", json_body=body)

    def list_launch_errors(self, app_source: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"status": status} if status else None
        return self._request("GET", f"/launch-readiness/{app_source}/errors", params=params)["errors"]

    def resolve_launch_error(self, app_source: str, error_id: int) -> Dict[str, Any]:
        return self._request("POST", f"/launch-readiness/{app_source}/errors/{error_id}/resolve")

    def refresh_launch_readiness(self, app_source: str) -> Dict[str, Any]:
        return self._request("POST", f"/launch-readiness/{app_source}/refresh")

    # ------------------------------------------------------------------
    # webhooks
    # ------------------------------------------------------------------

    def get_webhook(self, app_source: str) -> Dict[str, Any]:
        return self._request("GET", f"/tenants/my-apps/{app_source}/webhook")

    def set_webhook(self, app_source: str, url: str) -> Dict[str, Any]:
        """Returns the signing secret in full -- shown only this once,
        store it. CGC Core signs every delivery with HMAC-SHA256 over the
        JSON body as `X-CGC-Signature: sha256=<hex>`."""
        return self._request("POST", f"/tenants/my-apps/{app_source}/webhook", json_body={"url": url})

    def delete_webhook(self, app_source: str) -> Dict[str, Any]:
        return self._request("DELETE", f"/tenants/my-apps/{app_source}/webhook")

    # ------------------------------------------------------------------
    # per-tenant scoring-weight overrides
    # ------------------------------------------------------------------

    def get_weighting(self, app_source: str) -> List[Dict[str, Any]]:
        return self._request("GET", f"/tenants/my-apps/{app_source}/weighting")["overrides"]

    def set_weighting(
        self,
        app_source: str,
        area: str,
        sensitivity_level: str,
        *,
        ecm_weight: float,
        pfm_weight: float,
        pan_weight: float,
        sda_weight: float,
        approval_threshold: float,
        critical_framework_enforcement: bool = False,
        require_human_review: bool = False,
    ) -> Dict[str, Any]:
        """ecm/pfm/pan/sda weights must each be in [0, 1] and sum to ~1.0
        (server-enforced within 0.02 tolerance)."""
        body = {
            "ecm_weight": ecm_weight,
            "pfm_weight": pfm_weight,
            "pan_weight": pan_weight,
            "sda_weight": sda_weight,
            "approval_threshold": approval_threshold,
            "critical_framework_enforcement": critical_framework_enforcement,
            "require_human_review": require_human_review,
        }
        return self._request(
            "PUT", f"/tenants/my-apps/{app_source}/weighting/{area}/{sensitivity_level}", json_body=body
        )

    def delete_weighting(self, app_source: str, area: str, sensitivity_level: str) -> Dict[str, Any]:
        return self._request("DELETE", f"/tenants/my-apps/{app_source}/weighting/{area}/{sensitivity_level}")

    # ------------------------------------------------------------------
    # misc
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Unauthenticated -- works without a token."""
        return self._request("GET", "/health")
