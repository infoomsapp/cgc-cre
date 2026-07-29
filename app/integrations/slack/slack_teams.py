"""
Slack Integration - CGC CORE™
Pure External Notification Connector
Olympus Mont Systems LLC © 2025 - Production Ready
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import aiohttp
from dataclasses import dataclass
from pydantic import BaseModel, Field

logger = logging.getLogger("cgc.integrations.slack")


@dataclass
class SlackNotificationResult:
    success: bool
    message_ts: Optional[str] = None
    channel_id: Optional[str] = None
    status: str = "sent"
    error: Optional[str] = None


class SlackMessage(BaseModel):
    text: Optional[str] = Field(None, description="Plain text message")
    channel: str = Field(..., description="Channel ID or name")
    username: str = Field("CGC CORE Bot", description="Bot username")
    icon_emoji: str = Field(":robot_face:", description="Bot icon")
    blocks: Optional[list] = Field(default_factory=list, description="Slack Block Kit")


class SlackIntegration:
    """
    Pure Slack integration for CGC CORE.

    Responsibilities:
    - Send Slack messages
    - Send Slack Block Kit messages
    - Reply to threads

    This module does NOT:
    - Perform legal analysis
    - Compute CGC or risk
    - Handle tenancy or quotas
    - Contain business logic
    """

    def __init__(self):
        """Initialize Slack API client."""
        self.bot_token = os.getenv("SLACK_BOT_TOKEN")
        self._validate_credentials()
        self.base_url = "https://slack.com/api"
        logger.info("SlackIntegration initialized (Slack API ready)")

    def _validate_credentials(self) -> None:
        """Ensure Slack credentials exist."""
        if not self.bot_token:
            raise ValueError("SLACK_BOT_TOKEN environment variable is required")

    async def send_message(
        self,
        *,
        channel: str,
        text: Optional[str] = None,
        blocks: Optional[list] = None,
    ) -> SlackNotificationResult:
        """
        Send a Slack message (text or Block Kit).

        Parameters:
        - channel: Slack channel ID or name
        - text: Optional plain text
        - blocks: Optional Slack Block Kit list
        """
        alert_id = f"SLACK-{uuid.uuid4().hex[:8]}"

        try:
            message = SlackMessage(
                channel=channel,
                text=text,
                blocks=blocks or [],
            ).model_dump(exclude_none=True)

            headers = {
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat.postMessage",
                    json=message,
                    headers=headers,
                ) as resp:
                    data = await resp.json()

                    if resp.status == 200 and data.get("ok"):
                        message_ts = data["message"]["ts"]

                        logger.info(
                            "Slack message sent",
                            extra={
                                "alert_id": alert_id,
                                "channel": channel,
                                "message_ts": message_ts,
                            },
                        )

                        return SlackNotificationResult(
                            success=True,
                            message_ts=message_ts,
                            channel_id=channel,
                        )

                    return SlackNotificationResult(
                        success=False,
                        error=data.get("error", f"http_error_{resp.status}"),
                    )

        except Exception as exc:
            logger.error(
                "Slack message failed",
                extra={"alert_id": alert_id, "channel": channel, "error": str(exc)},
            )
            return SlackNotificationResult(success=False, error=str(exc))

    async def reply_in_thread(
        self,
        *,
        channel: str,
        thread_ts: str,
        text: str,
    ) -> Dict[str, Any]:
        """
        Reply to an existing Slack thread.
        """
        try:
            headers = {
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json",
            }

            payload = {
                "channel": channel,
                "text": text,
                "thread_ts": thread_ts,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat.postMessage",
                    json=payload,
                    headers=headers,
                ) as resp:
                    data = await resp.json()

                    if resp.status == 200 and data.get("ok"):
                        return {"success": True, "ts": data["ts"]}

                    return {"success": False, "error": data.get("error")}

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