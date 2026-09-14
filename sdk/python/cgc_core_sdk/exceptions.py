"""Exceptions raised by the CGC Core SDK."""

from typing import Any, Optional


class CGCCoreError(Exception):
    """Base class for every exception this SDK raises."""


class CGCCoreAPIError(CGCCoreError):
    """The API responded with a 4xx/5xx status.

    Mirrors the {"detail": "..."} shape every CGC Core endpoint uses for
    error responses (FastAPI's default HTTPException body).
    """

    def __init__(self, status_code: int, detail: Any, response_body: Optional[str] = None):
        self.status_code = status_code
        self.detail = detail
        self.response_body = response_body
        super().__init__(f"CGC Core API error {status_code}: {detail}")


class CGCCoreAuthError(CGCCoreAPIError):
    """401/403 from the API -- missing, expired, or insufficiently-scoped
    credential. Kept distinct from CGCCoreAPIError so callers can catch it
    separately (e.g. to trigger a re-login) without string-matching status
    codes themselves."""
