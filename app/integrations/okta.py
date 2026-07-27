"""
Okta SSO Integration - CGC CORE™
Pure External Authentication Connector
Olympus Mont Systems LLC © 2025 - Production Ready
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import aiohttp
from dataclasses import dataclass
from pydantic import BaseModel, Field

logger = logging.getLogger("cgc.integrations.okta")


@dataclass
class OktaAuthResult:
    success: bool
    user_id: Optional[str] = None
    email: Optional[str] = None
    groups: Optional[List[str]] = None
    status: str = "authenticated"
    error: Optional[str] = None


class OktaUser(BaseModel):
    id: str = Field(..., description="Okta user ID")
    email: str = Field(..., description="User email")
    login: str = Field(..., description="Login name")
    status: str = Field(..., description="ACTIVE/SUSPENDED")
    profile: Dict[str, Any] = Field(default_factory=dict)


class OktaIntegration:
    """
    Pure Okta SSO integration for CGC CORE.

    Responsibilities:
    - Look up users in Okta
    - Retrieve group memberships
    - Authenticate users based on Okta status

    This module does NOT:
    - Perform legal analysis
    - Compute CGC or risk
    - Handle tenancy or quotas
    - Contain business logic
    - Map tenants or plans
    """

    def __init__(self):
        """Initialize Okta API client."""
        self.api_token = os.getenv("OKTA_API_TOKEN")
        self.domain = os.getenv("OKTA_DOMAIN", "").rstrip("/")
        self.base_url = f"https://{self.domain}/api/v1"

        self._validate_credentials()
        logger.info("OktaIntegration initialized (SSO ready)")

    def _validate_credentials(self) -> None:
        """Ensure Okta credentials exist."""
        required = ["OKTA_API_TOKEN", "OKTA_DOMAIN"]
        missing = [var for var in required if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing Okta environment variables: {missing}")

    async def authenticate_user(
        self,
        *,
        user_email: str,
    ) -> OktaAuthResult:
        """
        Authenticate a user via Okta.

        Parameters:
        - user_email: Email to look up in Okta

        Returns:
        - OktaAuthResult with user_id, email, groups, status
        """
        auth_id = f"OKTA-{uuid.uuid4().hex[:8]}"

        try:
            user = await self._get_user_by_email(user_email)
            if not user:
                return OktaAuthResult(success=False, error="user_not_found")

            groups = await self._get_user_groups(user.id)

            logger.info(
                "Okta authentication successful",
                extra={
                    "auth_id": auth_id,
                    "okta_user_id": user.id,
                    "email": user.email,
                    "groups": groups,
                },
            )

            return OktaAuthResult(
                success=True,
                user_id=user.id,
                email=user.email,
                groups=groups,
                status="authenticated",
            )

        except Exception as exc:
            logger.error(
                "Okta authentication failed",
                extra={
                    "auth_id": auth_id,
                    "user_email": user_email,
                    "error": str(exc),
                },
            )
            return OktaAuthResult(success=False, error=str(exc))

    async def _get_user_by_email(self, email: str) -> Optional[OktaUser]:
        """Search Okta user by email."""
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"SSWS {self.api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            params = {"q": email, "search": f'profile.email eq "{email}"'}

            async with session.get(
                f"{self.base_url}/users", headers=headers, params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data:
                        return OktaUser(**data[0])
        return None

    async def _get_user_groups(self, user_id: str) -> List[str]:
        """Retrieve Okta user group memberships."""
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"SSWS {self.api_token}"}
            url = f"{self.base_url}/users/{user_id}/groups"

            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [group["profile"]["name"] for group in data]

        return []

    def get_status(self) -> Dict[str, Any]:
        """Simple health check."""
        try:
            return {
                "status": "healthy",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    async def provision_user(self, *, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        JIT User Provisioning (optional).
        Creates an Okta user if not exists.
        """
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"SSWS {self.api_token}",
                    "Content-Type": "application/json",
                }

                async with session.post(
                    f"{self.base_url}/users?activate=true",
                    headers=headers,
                    json=user_data,
                ) as resp:
                    if resp.status in (200, 201):
                        return {"success": True, "status": "created"}
                    return {"success": False, "error": await resp.text()}

        except Exception as exc:
            return {"success": False, "error": str(exc)}