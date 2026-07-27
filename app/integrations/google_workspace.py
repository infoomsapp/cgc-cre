"""
Google Workspace Integration - Drive + Gmail + Sheets
CGC CORE™ External Connector (Pure Integration Layer)
Olympus Mont Systems LLC © 2025 - Production Ready
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import io
from dataclasses import dataclass

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

logger = logging.getLogger("cgc.integrations.google_workspace")


@dataclass
class GoogleWorkspaceResult:
    success: bool
    file_id: Optional[str] = None
    file_url: Optional[str] = None
    folder_id: Optional[str] = None
    status: str = "uploaded"
    error: Optional[str] = None


class GoogleWorkspaceIntegration:
    """
    Pure Google Workspace integration for CGC CORE.

    Responsibilities:
    - Upload PDFs to Google Drive
    - Send Gmail alerts
    - Append rows to Google Sheets

    This module does NOT:
    - Perform legal analysis
    - Compute CGC or risk
    - Handle tenancy or quotas
    - Contain business logic
    """

    def __init__(self):
        """Initialize Google API clients using a Service Account."""
        self.service_account_file = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
        self._validate_credentials()

        self.drive_service = None
        self.gmail_service = None
        self.sheets_service = None

        self._init_services()
        logger.info("GoogleWorkspaceIntegration initialized (Drive/Gmail/Sheets ready)")

    def _validate_credentials(self) -> None:
        """Ensure the service account JSON file exists."""
        if not self.service_account_file or not os.path.exists(self.service_account_file):
            raise ValueError("GOOGLE_SERVICE_ACCOUNT_JSON path is missing or invalid")

    def _init_services(self) -> None:
        """Initialize Google API clients."""
        credentials = service_account.Credentials.from_service_account_file(
            self.service_account_file,
            scopes=[
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/spreadsheets",
            ],
        )

        self.drive_service = build("drive", "v3", credentials=credentials)
        self.gmail_service = build("gmail", "v1", credentials=credentials)
        self.sheets_service = build("sheets", "v4", credentials=credentials)

    async def save_to_drive(
        self,
        *,
        pdf_bytes: bytes,
        filename: str,
        org_id: str,
        folder_name: Optional[str] = None,
    ) -> GoogleWorkspaceResult:
        """
        Upload a PDF file to Google Drive.

        Parameters:
        - pdf_bytes: PDF content already generated
        - filename: Name of the file to upload
        - org_id: Tenant identifier (used only for folder naming)
        - folder_name: Optional custom folder name
        """
        upload_id = f"DRIVE-{uuid.uuid4().hex[:8]}"

        try:
            folder_id = await self._get_or_create_folder(
                folder_name or f"CGC_CORE_{org_id}"
            )

            media = MediaIoBaseUpload(io.BytesIO(pdf_bytes), mimetype="application/pdf")

            file_metadata = {
                "name": filename,
                "parents": [folder_id],
            }

            file = (
                self.drive_service.files()
                .create(body=file_metadata, media_body=media, fields="id, webViewLink")
                .execute()
            )

            logger.info(
                "Google Drive upload completed",
                extra={
                    "org_id": org_id,
                    "upload_id": upload_id,
                    "file_id": file["id"],
                    "file_url": file["webViewLink"],
                    "folder_id": folder_id,
                },
            )

            return GoogleWorkspaceResult(
                success=True,
                file_id=file["id"],
                file_url=file["webViewLink"],
                folder_id=folder_id,
                status="uploaded",
            )

        except Exception as exc:
            logger.error(
                "Google Drive upload failed",
                extra={
                    "org_id": org_id,
                    "upload_id": upload_id,
                    "error": str(exc),
                },
            )
            return GoogleWorkspaceResult(success=False, error=str(exc))

    async def _get_or_create_folder(self, folder_name: str) -> str:
        """Return an existing folder ID or create a new one."""
        results = (
            self.drive_service.files()
            .list(
                q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false",
                fields="files(id, name)",
            )
            .execute()
        )

        if results.get("files"):
            return results["files"][0]["id"]

        folder_metadata = {
            "name": folder_name,
            "mimeType": "application/vnd.google-apps.folder",
        }

        folder = (
            self.drive_service.files()
            .create(body=folder_metadata, fields="id")
            .execute()
        )

        return folder["id"]

    async def send_gmail_alert(
        self,
        *,
        subject: str,
        message: str,
        recipient_email: str,
    ) -> Dict[str, Any]:
        """
        Send a Gmail alert using the service account.
        """
        try:
            raw_message = (
                f"From: CGC CORE <noreply@cgc-core.ai>\n"
                f"To: {recipient_email}\n"
                f"Subject: {subject}\n\n"
                f"{message}"
            )

            encoded_message = {"raw": raw_message.encode("utf-8").hex()}

            self.gmail_service.users().messages().send(
                userId="me", body=encoded_message
            ).execute()

            return {"success": True, "status": "sent"}

        except Exception as exc:
            return {"success": False, "error": str(exc)}

    async def append_to_sheet(
        self,
        *,
        spreadsheet_id: str,
        sheet_name: str,
        row_values: List[Any],
    ) -> Dict[str, Any]:
        """
        Append a row to a Google Sheet.
        """
        try:
            body = {"values": [row_values]}

            self.sheets_service.spreadsheets().values().append(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1",
                valueInputOption="RAW",
                body=body,
            ).execute()

            return {"success": True, "status": "appended"}

        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_status(self) -> Dict[str, Any]:
        """Simple health check."""
        try:
            self.drive_service.files().list(pageSize=1).execute()
            return {
                "status": "healthy",
                "services": ["drive", "gmail", "sheets"],
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}