"""
Zapier Integration - CGC CORE™
Pure External Workflow Trigger Connector
Olympus Mont Systems LLC © 2025 - Production Ready
"""

import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import aiohttp
import hmac
import hashlib
from dataclasses import dataclass

logger = logging.getLogger("cgc.integrations.zapier")


@dataclass
class ZapierTriggerResult:
    success: bool
    zap_id: Optional[str] = None
    execution_id: Optional[str] = None
    status: str = "triggered"
    error: Optional[str] = None


class ZapierIntegration:
    """
    Pure Zapier integration for CGC CORE.

    Responsibilities:
    - Trigger Zapier webhooks
    - Send arbitrary payloads to Zapier
    - Provide HMAC signatures for validation

    This module does NOT:
    - Perform legal analysis
    - Compute CGC or risk
    - Handle tenancy or quotas
    - Contain business logic
    - Decide which workflow to trigger
    """

    def __init__(self):
        """Load Zapier webhook URLs from environment variables."""
        self.webhook_urls = {
            "workflow_1": os.getenv("ZAPIER_WEBHOOK_1"),
            "workflow_2": os.getenv("ZAPIER_WEBHOOK_2"),
            "workflow_3": os.getenv("ZAPIER_WEBHOOK_3"),
            "workflow_4": os.getenv("ZAPIER_WEBHOOK_4"),
        }

        self._validate_credentials()
        logger.info("ZapierIntegration initialized (pure webhook mode)")

    def _validate_credentials(self) -> None:
        """Warn if any webhook URLs are missing."""
        missing = [key for key, url in self.webhook_urls.items() if not url]
        if missing:
            logger.warning(f"Missing Zapier webhooks: {missing}")

    def get_webhook_url(self, workflow_id: str) -> Optional[str]:
        """Return the webhook URL for a given workflow ID."""
        return self.webhook_urls.get(workflow_id)

    async def trigger(
        self,
        *,
        workflow_id: str,
        payload: Dict[str, Any],
    ) -> ZapierTriggerResult:
        """
        Trigger a Zapier workflow.

        Parameters:
        - workflow_id: key in webhook_urls
        - payload: dict to send to Zapier
        """
        trigger_id = f"ZAPIER-{uuid.uuid4().hex[:8]}"

        try:
            webhook_url = self.get_webhook_url(workflow_id)
            if not webhook_url:
                return ZapierTriggerResult(
                    success=False,
                    error="webhook_not_configured",
                )

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "CGC-CORE/1.0",
                "X-Zapier-Signature": self._generate_signature(payload),
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as resp:
                    if resp.status in (200, 202):
                        try:
                            data = await resp.json()
                            execution_id = data.get("execution_id", "unknown")
                        except Exception:
                            execution_id = "unknown"

                        logger.info(
                            "Zapier workflow triggered",
                            extra={
                                "workflow_id": workflow_id,
                                "trigger_id": trigger_id,
                                "execution_id": execution_id,
                            },
                        )

                        return ZapierTriggerResult(
                            success=True,
                            zap_id=workflow_id,
                            execution_id=execution_id,
                        )

                    error_text = await resp.text()
                    return ZapierTriggerResult(
                        success=False,
                        error=f"zapier_http_{resp.status}: {error_text}",
                    )

        except Exception as exc:
            return ZapierTriggerResult(
                success=False,
                error=str(exc),
            )

    def _generate_signature(self, payload: Dict[str, Any]) -> str:
        """Generate HMAC signature for Zapier validation."""
        secret = os.getenv("ZAPIER_WEBHOOK_SECRET", "default_secret")
        payload_str = str(payload).encode("utf-8")
        return hmac.new(secret.encode("utf-8"), payload_str, hashlib.sha256).hexdigest()

    def get_status(self) -> Dict[str, Any]:
        """Simple health check."""
        active = sum(1 for url in self.webhook_urls.values() if url)
        return {
            "status": "healthy" if active > 0 else "degraded",
            "active_webhooks": active,
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def test_webhook(
        self,
        *,
        webhook_url: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Test any Zapier webhook manually."""
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as resp:
                return {
                    "status_code": resp.status,
                    "success": resp.status in (200, 202),
                    "response": await resp.text(),
                }