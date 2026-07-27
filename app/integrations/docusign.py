"""
DocuSign Integration v2.0 - CGC CORE™
Olympus Mont Systems LLC © 2025
"""

import os
import io
import base64
from typing import Dict, Any, Optional
from datetime import datetime
import uuid
from dataclasses import dataclass
import logging

from docusign_esign import ApiClient, EnvelopesApi
from docusign_esign.models import (
    Document,
    Signer,
    Recipients,
    EnvelopeDefinition,
    SignHere,
    Approve,
    Tabs,
)

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

logger = logging.getLogger("cgc.integrations.docusign")


@dataclass
class SigningResult:
    envelope_id: str
    signing_url: str
    risk_level: str
    cgc_score: float
    status: str


class DocuSignIntegration:
    """
    DocuSign eSignature → CGC CORE ecosystem integration.

    This module is a pure integration layer:
    - It does NOT perform legal analysis.
    - It does NOT assess risk.
    - It does NOT handle tenancy or quotas.

    It expects:
    - Precomputed CGC / ethical analysis (cgc_result).
    - Precomputed risk assessment (risk_result).

    Responsibility:
    - Build a PDF embedding the provided analysis.
    - Create a DocuSign envelope with approval + signature tabs.
    - Send the envelope via DocuSign.
    """

    def __init__(self) -> None:
        self.version = "2.0.0"
        self.api_client = ApiClient()
        self.account_id: Optional[str] = None

        self._configure_auth()
        self.envelopes_api = EnvelopesApi(self.api_client)

        logger.info(
            "DocuSignIntegration v%s | pure DocuSign connector ready",
            self.version,
        )

    def _configure_auth(self) -> None:
        """
        Configure JWT Grant authentication for DocuSign.

        Required environment variables:
        - DOCUSIGN_INTEGRATION_KEY
        - DOCUSIGN_USER_ID
        - DOCUSIGN_ACCOUNT_ID
        - DOCUSIGN_PRIVATE_KEY_PATH (optional, defaults to 'private_key.pem')
        """
        # Demo REST API host (for production you may use account.docusign.com / account-d.docusign.com)
        self.api_client.host = "https://demo.docusign.net/restapi"

        integration_key = os.getenv("DOCUSIGN_INTEGRATION_KEY")
        user_id = os.getenv("DOCUSIGN_USER_ID")
        account_id = os.getenv("DOCUSIGN_ACCOUNT_ID")
        private_key_path = os.getenv("DOCUSIGN_PRIVATE_KEY_PATH", "private_key.pem")

        if all([integration_key, user_id, account_id]):
            self.api_client.configure_jwt_authorization_flow(
                private_key_file=private_key_path,
                oauth_base_url="account-d.docusign.com",
                client_id=integration_key,
                user_id=user_id,
                expires_in_hours=24,
            )
            self.account_id = account_id
            logger.info("DocuSign JWT auth configured")
        else:
            logger.warning(
                "DocuSign environment variables incomplete "
                "(DOCUSIGN_INTEGRATION_KEY / DOCUSIGN_USER_ID / DOCUSIGN_ACCOUNT_ID). "
                "Envelope sending will fail until configuration is completed."
            )
            self.account_id = None

    async def create_envelope_with_analysis(
        self,
        *,
        contract_text: str,
        org_id: str,
        signer_email: str,
        signer_name: str,
        cgc_result: Dict[str, Any],
        risk_result: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full envelope creation pipeline using precomputed analysis.

        Parameters
        ----------
        contract_text:
            Raw contract text to embed (truncated) into the PDF.
        org_id:
            Organization identifier (used in naming and logging).
        signer_email:
            Recipient email address.
        signer_name:
            Recipient display name.
        cgc_result:
            Precomputed CGC / ethical analysis. Must include at least:
                - 'ethical_score': float in [0, 1]
        risk_result:
            Precomputed risk analysis. Must include at least:
                - 'risk_summary': {
                    'risk_level': str,
                    'overall_risk_score': float
                  }
        metadata:
            Optional metadata for logging / context (not used in DocuSign).

        Returns
        -------
        Dict[str, Any]:
            JSON-ready result with envelope metadata and signing URL.
        """
        envelope_id_local = f"DOCS-{uuid.uuid4().hex[:8]}"
        metadata = metadata or {}

        try:
            # 1. Generate PDF embedding CGC + risk analysis
            contract_pdf = self._generate_analysis_pdf(
                contract_text=contract_text,
                cgc_result=cgc_result,
                risk_result=risk_result,
            )

            # 2. Build DocuSign envelope
            envelope_definition = self._create_envelope(
                pdf_bytes=contract_pdf,
                cgc_result=cgc_result,
                risk_result=risk_result,
                signer_email=signer_email,
                signer_name=signer_name,
                org_id=org_id,
            )

            # 3. Send envelope
            if not self.account_id:
                raise RuntimeError(
                    "DocuSign account_id is not configured. "
                    "Check DOCUSIGN_ACCOUNT_ID and JWT configuration."
                )

            result = self.envelopes_api.create_envelope(
                account_id=self.account_id,
                envelope_definition=envelope_definition,
            )

            risk_level = risk_result["risk_summary"]["risk_level"]
            ethical_score = float(cgc_result.get("ethical_score", 0.0))

            signing_result = SigningResult(
                envelope_id=result.envelope_id,
                signing_url=(
                    f"https://demo.docusign.net/Member/Status.aspx?"
                    f"EnvelopeId={result.envelope_id}"
                ),
                risk_level=risk_level,
                cgc_score=ethical_score,
                status=result.status,
            )

            # 4. Audit log
            logger.info(
                "DocuSign envelope created",
                extra={
                    "org_id": org_id,
                    "envelope_id": result.envelope_id,
                    "risk_level": signing_result.risk_level,
                    "cgc_score": signing_result.cgc_score,
                    "metadata": metadata,
                },
            )

            return {
                "success": True,
                "envelope_id": signing_result.envelope_id,
                "signing_url": signing_result.signing_url,
                "risk_level": signing_result.risk_level,
                "cgc_score": signing_result.cgc_score,
                "status": signing_result.status,
                "org_id": org_id,
                "analysis": {
                    "cgc_ethical": ethical_score,
                    "risk_score": risk_result["risk_summary"]["overall_risk_score"],
                    "cgc_result": cgc_result,
                    "risk_result": risk_result,
                },
            }

        except Exception as exc:
            logger.error(
                "DocuSign envelope creation failed: %s",
                exc,
                extra={
                    "org_id": org_id,
                    "envelope_id": envelope_id_local,
                    "metadata": metadata,
                },
            )
            return {
                "success": False,
                "reason": "docusign_error",
                "error": str(exc),
                "org_id": org_id,
                "envelope_id": envelope_id_local,
            }

    def _generate_analysis_pdf(
        self,
        *,
        contract_text: str,
        cgc_result: Dict[str, Any],
        risk_result: Dict[str, Any],
    ) -> bytes:
        """
        Generate a PDF that embeds the CGC ethical score and risk analysis.
        The analysis is assumed to be precomputed and trusted.
        """
        packet = io.BytesIO()

        # Register professional font if available
        try:
            pdfmetrics.registerFont(TTFont("Helvetica-Bold", "Helvetica-Bold.ttf"))
            header_font = "Helvetica-Bold"
        except Exception:
            header_font = "Helvetica"

        c = canvas.Canvas(packet, pagesize=letter)
        width, height = letter

        # Header
        c.setFont(header_font, 16)
        c.drawString(72, height - 72, "CGC CORE™ Governed Contract Analysis")

        # CGC Ethical Score
        ethical_score = float(cgc_result.get("ethical_score", 0.0)) * 100.0
        c.setFont(header_font, 24)
        c.drawString(72, height - 120, f"CGC Ethical Score: {ethical_score:.1f}%")

        # Risk Level
        risk_summary = risk_result.get("risk_summary", {})
        risk_level = str(risk_summary.get("risk_level", "UNKNOWN"))
        overall_risk_score = float(risk_summary.get("overall_risk_score", 0.0)) * 100.0

        c.setFont(header_font, 20)
        c.drawString(72, height - 160, f"Risk Level: {risk_level}")
        c.setFont("Helvetica", 12)
        c.drawString(
            72,
            height - 185,
            f"Overall Risk Score: {overall_risk_score:.1f}%",
        )

        # Contract text (truncated preview)
        c.setFont("Helvetica", 10)
        y_pos = height - 220
        for line in contract_text[:4000].split("\n"):
            if y_pos < 100:
                c.showPage()
                c.setFont("Helvetica", 10)
                y_pos = height - 72
            c.drawString(72, y_pos, line[:80])
            y_pos -= 14

        c.save()
        packet.seek(0)
        return packet.read()

    def _create_envelope(
        self,
        *,
        pdf_bytes: bytes,
        cgc_result: Dict[str, Any],
        risk_result: Dict[str, Any],
        signer_email: str,
        signer_name: str,
        org_id: str,
    ) -> EnvelopeDefinition:
        """
        Create a DocuSign envelope with:
        - A PDF document containing CGC + risk analysis.
        - A smart approval button based on risk level.
        - A signature tab anchored on '/Signature/'.
        """
        document = Document(
            document_base64=base64.b64encode(pdf_bytes).decode("utf-8"),
            name=f"CGC_Analysis_{org_id}_{datetime.now().strftime('%Y%m%d')}.pdf",
            file_extension="pdf",
            document_id="1",
        )

        risk_summary = risk_result.get("risk_summary", {})
        risk_level = str(risk_summary.get("risk_level", "UNKNOWN")).upper()
        ethical_score = float(cgc_result.get("ethical_score", 0.0))

        if risk_level in ("NONE", "LOW"):
            approval_text = "APPROVE"
        elif risk_level == "MEDIUM":
            approval_text = "REVIEW THEN APPROVE"
        else:
            approval_text = "REVIEW REQUIRED"

        signer = Signer(
            email=signer_email,
            name=signer_name,
            recipient_id="1",
            routing_order="1",
            tabs=Tabs(
                approve_tabs=[
                    Approve(
                        anchor_string="/Signature/",
                        button_text=approval_text,
                        anchor_units="pixels",
                        anchor_x_offset="20",
                        anchor_y_offset="10",
                    )
                ],
                sign_here_tabs=[
                    SignHere(
                        anchor_string="/Signature/",
                        anchor_units="pixels",
                        anchor_x_offset="0",
                        anchor_y_offset="0",
                    )
                ],
            ),
        )

        email_subject = (
            f"CGC {ethical_score:.1%} | {risk_level} Risk - Action Required"
        )

        return EnvelopeDefinition(
            email_subject=email_subject,
            documents=[document],
            recipients=Recipients(signers=[signer]),
            status="sent",
        )

    def get_status(self) -> Dict[str, Any]:
        """
        Simple integration status for monitoring and health checks.
        """
        return {
            "module": "DocuSign Integration",
            "version": self.version,
            "authenticated": bool(self.account_id),
            "status": "READY" if self.account_id else "CONFIG_REQUIRED",
        }