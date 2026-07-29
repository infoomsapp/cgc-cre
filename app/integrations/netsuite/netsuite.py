"""
NetSuite Integration - CGC CORE™
Pure External Financial Sync Connector
Olympus Mont Systems LLC © 2025 - Production Ready
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import aiohttp
from dataclasses import dataclass
from requests_oauthlib import OAuth1

logger = logging.getLogger("cgc.integrations.netsuite")


@dataclass
class NetSuiteSyncResult:
    success: bool
    netsuite_id: Optional[str] = None
    record_type: Optional[str] = None
    status: str = "synced"
    error: Optional[str] = None


class NetSuiteIntegration:
    """
    Pure NetSuite REST API integration for CGC CORE.

    Responsibilities:
    - Create NetSuite records
    - Update NetSuite records
    - Search NetSuite records
    - Provide OAuth1 authentication

    This module does NOT:
    - Perform legal analysis
    - Compute CGC or risk
    - Handle tenancy or quotas
    - Contain business logic
    """

    def __init__(self):
        """Initialize NetSuite OAuth1 credentials."""
        self.account_id = os.getenv("NETSUITE_ACCOUNT_ID")
        self.consumer_key = os.getenv("NETSUITE_CONSUMER_KEY")
        self.consumer_secret = os.getenv("NETSUITE_CONSUMER_SECRET")
        self.token_id = os.getenv("NETSUITE_TOKEN_ID")
        self.token_secret = os.getenv("NETSUITE_TOKEN_SECRET")

        self.base_url = (
            f"https://{self.account_id}.suitetalk.api.netsuite.com/services/rest/record/v1"
        )

        self._validate_credentials()
        logger.info("NetSuiteIntegration initialized (pure mode)")

    def _validate_credentials(self) -> None:
        """Ensure all NetSuite credentials exist."""
        required = [
            "NETSUITE_ACCOUNT_ID",
            "NETSUITE_CONSUMER_KEY",
            "NETSUITE_CONSUMER_SECRET",
            "NETSUITE_TOKEN_ID",
            "NETSUITE_TOKEN_SECRET",
        ]
        missing = [var for var in required if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing NetSuite environment variables: {missing}")

    def _oauth(self) -> OAuth1:
        """Return OAuth1 signature object."""
        return OAuth1(
            self.consumer_key,
            client_secret=self.consumer_secret,
            resource_owner_key=self.token_id,
            resource_owner_secret=self.token_secret,
            signature_method="HMAC-SHA256",
            signature_type="auth_header",
        )

    async def create_record(
        self,
        *,
        record_type: str,
        payload: Dict[str, Any],
    ) -> NetSuiteSyncResult:
        """Create a new NetSuite record."""
        try:
            url = f"{self.base_url}/{record_type}"
            auth = self._oauth()
            headers = {"Content-Type": "application/json"}

            async with aiohttp.ClientSession() as session:
                async with session.post(url, auth=auth, headers=headers, json=payload) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        return NetSuiteSyncResult(
                            success=True,
                            netsuite_id=data.get("id"),
                            record_type=record_type,
                        )

                    error_text = await resp.text()
                    return NetSuiteSyncResult(
                        success=False,
                        error=f"netsuite_post_{resp.status}: {error_text}",
                    )

        except Exception as exc:
            return NetSuiteSyncResult(success=False, error=str(exc))

    async def update_record(
        self,
        *,
        record_type: str,
        record_id: str,
        payload: Dict[str, Any],
    ) -> NetSuiteSyncResult:
        """Update an existing NetSuite record."""
        try:
            url = f"{self.base_url}/{record_type}/{record_id}"
            auth = self._oauth()
            headers = {"Content-Type": "application/json"}

            async with aiohttp.ClientSession() as session:
                async with session.patch(url, auth=auth, headers=headers, json=payload) as resp:
                    if resp.status in (200, 204):
                        return NetSuiteSyncResult(
                            success=True,
                            netsuite_id=record_id,
                            record_type=record_type,
                        )

                    error_text = await resp.text()
                    return NetSuiteSyncResult(
                        success=False,
                        error=f"netsuite_patch_{resp.status}: {error_text}",
                    )

        except Exception as exc:
            return NetSuiteSyncResult(success=False, error=str(exc))

    async def search_records(
        self,
        *,
        record_type: str,
        query: str,
    ) -> Dict[str, Any]:
        """Search NetSuite records using SuiteQL-like filters."""
        try:
            url = f"{self.base_url}/{record_type}"
            auth = self._oauth()
            headers = {"Content-Type": "application/json", "Prefer": "transient"}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth, headers=headers, params={"q": query}) as resp:
                    if resp.status == 200:
                        return await resp.json()

                    return {"success": False, "error": await resp.text()}

        except Exception as exc:
            return {"success": False, "error": str(exc)}

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