"""
Microsoft 365 Integration - MS Teams + Outlook
CGC CORE™ External Connector (Pure Integration Layer)
Olympus Mont Systems LLC © 2025 - Production Ready
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from dataclasses import dataclass

import msal
import aiohttp

logger = logging.getLogger("cgc.integrations.microsoft365")


@dataclass
class TeamsNotificationResult:
    success: bool
    message_id: Optional[str] = None
    channel_id: Optional[str] = None
    status: str = "sent"
    error: Optional[str] = None


class Microsoft365Integration:
    """
    Pure Microsoft 365 integration for CGC CORE.

    Responsibilities:
    - Send Teams notifications
    - Send Outlook emails

    This module does NOT:
    - Perform legal analysis
    - Compute CGC or risk
    - Handle tenancy or quotas
    - Contain business logic
    """

    def __init__(self):
        """Initialize Microsoft Graph OAuth2 client."""
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.tenant_id = os.getenv("AZURE_TENANT_ID")

        self._validate_credentials()

        self.scopes = ["https://graph.microsoft.com/.default"]
        self.graph_url = "https://graph.microsoft.com/v1.0"

        logger.info("Microsoft365Integration initialized (Teams + Outlook ready)")

    def _validate_credentials(self) -> None:
        """Ensure Azure AD credentials exist."""
        required = ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]
        missing = [var for var in required if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing Azure AD environment variables: {missing}")

    async def _get_access_token(self) -> Optional[str]:
        """Acquire Microsoft Graph token using client credentials flow."""
        try:
            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
                client_credential=self.client_secret,
            )

            result = app.acquire_token_for_client(scopes=self.scopes)

            if "access_token" in result:
                return result["access_token"]

            logger.error(f"Token acquisition failed: {result.get('error_description')}")
            return None

        except Exception as exc:
            logger.error(f"Token error: {exc}")
            return None

    async def send_teams_message(
        self,
        *,
        channel_id: str,
        html_content: str,
    ) -> TeamsNotificationResult:
        """
        Send a Teams message to a specific channel.

        Parameters:
        - channel_id: "teamId/channelId"
        - html_content: HTML body of the message
        """
        notification_id = f"TEAMS-{uuid.uuid4().hex[:8]}"

        try:
            token = await self._get_access_token()
            if not token:
                return TeamsNotificationResult(success=False, error="token_failed")

            team_id, channel = channel_id.split("/")

            message_body = {
                "body": {
                    "contentType": "html",
                    "content": html_content,
                }
            }

            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }

                url = f"{self.graph_url}/teams/{team_id}/channels/{channel}/messages"

                async with session.post(url, json=message_body, headers=headers) as resp:
                    if resp.status == 201:
                        data = await resp.json()
                        message_id = data.get("id")

                        logger.info(
                            "Teams message sent",
                            extra={
                                "notification_id": notification_id,
                                "channel_id": channel_id,
                                "message_id": message_id,
                            },
                        )

                        return TeamsNotificationResult(
                            success=True,
                            message_id=message_id,
                            channel_id=channel_id,
                        )

                    error_text = await resp.text()
                    logger.error(f"Teams API error {resp.status}: {error_text}")

                    return TeamsNotificationResult(
                        success=False,
                        error=f"teams_api_error_{resp.status}",
                        channel_id=channel_id,
                    )

        except Exception as exc:
            logger.error(
                "Teams message failed",
                extra={
                    "notification_id": notification_id,
                    "channel_id": channel_id,
                    "error": str(exc),
                },
            )
            return TeamsNotificationResult(
                success=False,
                error=str(exc),
                channel_id=channel_id,
            )

    async def send_outlook_email(
        self,
        *,
        recipient_email: str,
        subject: str,
        body_html: str,
    ) -> Dict[str, Any]:
        """
        Send an Outlook email using Microsoft Graph.
        """
        try:
            token = await self._get_access_token()
            if not token:
                return {"success": False, "error": "token_failed"}

            email_body = {
                "message": {
                    "subject": subject,
                    "body": {"contentType": "HTML", "content": body_html},
                    "toRecipients": [{"emailAddress": {"address": recipient_email}}],
                },
                "saveToSentItems": "true",
            }

            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }

                url = f"{self.graph_url}/users/{self.client_id}/sendMail"

                async with session.post(url, json=email_body, headers=headers) as resp:
                    if resp.status == 202:
                        return {"success": True, "status": "sent"}

                    error_text = await resp.text()
                    return {"success": False, "error": error_text}

        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_status(self) -> Dict[str, Any]:
        """Simple health check."""
        try:
            token = msal.ConfidentialClientApplication(
                self.client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
                client_credential=self.client_secret,
            ).acquire_token_for_client(scopes=self.scopes)

            return {
                "status": "healthy" if "access_token" in token else "degraded",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            return {"status": "error", "error": str(exc)}