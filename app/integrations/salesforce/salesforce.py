"""
Salesforce Integration - CGC CORE™
Production Ready
Olympus Mont Systems LLC © 2025
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
from dataclasses import dataclass

from simple_salesforce import Salesforce
from pydantic import BaseModel, Field

logger = logging.getLogger("cgc.integrations.salesforce")


@dataclass
class SalesforceSyncResult:
    success: bool
    salesforce_id: Optional[str] = None
    contract_name: Optional[str] = None
    status: str = "synced"
    error: Optional[str] = None


class ContractRecord(BaseModel):
    """
    Salesforce Contract object payload.

    This model assumes you have custom fields:
    - Risk_Level__c
    - CGC_Ethical_Score__c
    - Compliance_Score__c
    - Law_Issues__c
    - Status__c
    - Analysis_JSON__c
    - Org_ID__c
    Adjust names/types if your org uses different API names.
    """

    Name: str = Field(..., description="Contract name")
    AccountId: Optional[str] = Field(None, description="Salesforce Account ID")
    Risk_Level__c: str = Field(..., description="CRITICAL/HIGH/MEDIUM/LOW/NONE")
    CGC_Ethical_Score__c: float = Field(0.0, description="CGC ethical score 0-1")
    Compliance_Score__c: Optional[float] = Field(
        None,
        description="Compliance score (0-1 or 0-100, depending on your org)",
    )
    Law_Issues__c: int = Field(0, description="Federal law issues count")
    Status__c: str = Field("Draft", description="Draft/Approved/Review/Rejected")
    Analysis_JSON__c: Optional[str] = Field(
        None,
        description="Full analysis JSON as string",
    )
    Org_ID__c: str = Field(..., description="Tenant org_id")


class SalesforceIntegration:
    """
    Production Salesforce integration for CGC CORE.

    Pure responsibilities:
    - Manage Salesforce connections.
    - Map precomputed analysis into a Salesforce Contract record.
    - Create Contract records in Salesforce.
    - Provide simple health and bulk sync utilities.

    This module does NOT:
    - Perform legal analysis.
    - Compute risk.
    - Handle tenancy, quotas, or CGC business rules.
    """

    def __init__(self) -> None:
        """
        Initialize integration with connection pooling by org_id.
        """
        self.sf_connections: Dict[str, Salesforce] = {}
        self._validate_credentials()
        logger.info("SalesforceIntegration initialized - Production Ready")

    def _validate_credentials(self) -> None:
        """
        Validate required environment variables for Salesforce authentication.

        Required:
        - SF_USERNAME
        - SF_PASSWORD
        - SF_TOKEN
        - SF_DOMAIN  (e.g. 'login' or 'test')
        """
        required = ["SF_USERNAME", "SF_PASSWORD", "SF_TOKEN", "SF_DOMAIN"]
        missing = [var for var in required if not os.getenv(var)]
        if missing:
            logger.error("Salesforce credentials missing: %s", missing)
            raise ValueError(f"Salesforce env vars required: {missing}")

    def _get_sf_connection(self, org_id: str) -> Salesforce:
        """
        Get or create a Salesforce connection for a given org_id.

        Notes:
        - Currently all org_ids share the same credentials and domain.
          You can extend this to per-tenant credentials if needed.
        """
        if org_id not in self.sf_connections:
            domain = os.getenv("SF_DOMAIN", "test")
            self.sf_connections[org_id] = Salesforce(
                username=os.getenv("SF_USERNAME"),
                password=os.getenv("SF_PASSWORD"),
                security_token=os.getenv("SF_TOKEN"),
                domain=domain,
                sandbox=(domain == "test"),
            )
            logger.info("Salesforce connection established for org_id=%s", org_id)
        return self.sf_connections[org_id]

    async def sync_contract_analysis(
        self,
        analysis: Dict[str, Any],
        org_id: str,
    ) -> SalesforceSyncResult:
        """
        Sync a precomputed analysis to a Salesforce Contract record.

        Expected analysis structure (example):
        - analysis['contract_summary']['contract_name'] -> str
        - analysis['risk_summary']['risk_level'] -> str
        - analysis['risk_summary']['policy_action'] -> str
        - analysis['governance']['ethical_score'] -> float
        - analysis['compliance']['overall_compliance_score'] -> float
        - analysis['federal_law_scrutiny']['issues_found'] -> list

        This method does not interpret or validate the semantics,
        it just maps keys into Salesforce fields.
        """
        sync_id = f"SF-SYNC-{uuid.uuid4().hex[:8]}"

        try:
            contract_name = (
                analysis.get("contract_summary", {}).get("contract_name")
                or "Unnamed Contract"
            )

            risk_summary = analysis.get("risk_summary", {})
            governance = analysis.get("governance", {})
            compliance = analysis.get("compliance", {})
            law_issues = analysis.get("federal_law_scrutiny", {})

            sf_record = ContractRecord(
                Name=contract_name,
                AccountId=self._get_account_id(org_id),
                Risk_Level__c=risk_summary.get("risk_level", "UNKNOWN"),
                CGC_Ethical_Score__c=float(governance.get("ethical_score", 0.0)),
                Compliance_Score__c=compliance.get("overall_compliance_score"),
                Law_Issues__c=len(law_issues.get("issues_found", [])),
                Status__c=risk_summary.get("policy_action", "Review"),
                Analysis_JSON__c=str(analysis),
                Org_ID__c=org_id,
            ).model_dump()

            sf = self._get_sf_connection(org_id)
            result = sf.Contract.create(sf_record)

            logger.info(
                "Salesforce sync completed",
                extra={
                    "org_id": org_id,
                    "sync_id": sync_id,
                    "salesforce_id": result.get("id"),
                    "risk_level": sf_record["Risk_Level__c"],
                    "cgc_score": sf_record["CGC_Ethical_Score__c"],
                },
            )

            return SalesforceSyncResult(
                success=True,
                salesforce_id=result.get("id"),
                contract_name=sf_record["Name"],
                status="synced",
            )

        except Exception as exc:
            logger.error(
                "Salesforce sync failed",
                extra={
                    "org_id": org_id,
                    "sync_id": sync_id,
                    "error": str(exc),
                    "analysis_keys": list(analysis.keys())[:5],
                },
            )
            return SalesforceSyncResult(
                success=False,
                error=f"salesforce_error: {str(exc)}",
            )

    def _get_account_id(self, org_id: str) -> Optional[str]:
        """
        Map org_id -> Salesforce AccountId.

        This is a production configuration concern.
        Here, it is a static mapping that you should replace with:
        - a database lookup
        - a config service
        - or environment-driven mapping.
        """
        account_mapping = {
            "lawfirm-abc": "001abc123def456ghi789",
            "lawfirm-xyz": "001xyz987uvw654rst321",
            # Add more tenants as needed...
        }
        account_id = account_mapping.get(org_id)
        if not account_id:
            logger.warning("No Salesforce Account mapped for org_id=%s", org_id)
        return account_id

    def get_status(self) -> Dict[str, Any]:
        """
        Production health check.

        Tries a simple query using a sample org_id mapping.
        Adjust 'lawfirm-abc' to a reliable test tenant in your environment.
        """
        try:
            test_sf = self._get_sf_connection("lawfirm-abc")
            test_sf.query("SELECT Id FROM Account LIMIT 1")
            return {
                "status": "healthy",
                "connections_active": len(self.sf_connections),
                "version": "1.0.0",
                "last_check": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "status": "degraded",
                "error": str(exc),
                "connections_active": len(self.sf_connections),
            }

    async def bulk_sync_contracts(
        self,
        analyses: List[Dict[str, Any]],
        org_id: str,
    ) -> List[SalesforceSyncResult]:
        """
        Bulk sync for enterprise usage (e.g. 500+ contracts).

        Each analysis is processed independently and returns its own result.
        """
        results: List[SalesforceSyncResult] = []
        for analysis in analyses:
            result = await self.sync_contract_analysis(analysis, org_id)
            results.append(result)
        return results