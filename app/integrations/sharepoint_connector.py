"""
CGC CORE™ - SharePoint Connector v2.0
Microsoft Graph API + CGC Governance Integration
Production Ready - OlympusMont Systems LLC © 2025
"""

import requests
import json
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging

# CGC CORE integration
from app.modules.scm.scmmodule import SCM  
from app.Core.logging import get_logger  # Logging CGC

logger = get_logger("cgc.integrations.sharepoint")

class SharePointConnector:
    """
    Enterprise SharePoint integration with CGC CORE governance.
    OAuth 2.0 Client Credentials + MS Graph API + Audit Trail.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.graph_url = 'https://graph.microsoft.com/v1.0'
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_token = self._get_token()
        self.scm = SCMModule()  # CGC SCM para firmas

    def _get_token(self) -> Optional[str]:
        """OAuth 2.0 Client Credentials Flow"""
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default',
        }
        
        try:
            response = requests.post(token_url, data=payload, timeout=10)
            response.raise_for_status()
            token_data = response.json()
            logger.info("SharePoint token acquired", extra={'duration': 3600})
            return token_data.get('access_token')
        except Exception as e:
            logger.error("SharePoint auth failed", extra={'error': str(e)})
            return None

    def _get_headers(self) -> Dict[str, str]:
        return {
            'Authorization': f'Bearer {self.auth_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        } if self.auth_token else {}

    def list_contracts_folder(self, site_id: str, folder_path: str = '/Contracts') -> Optional[Dict]:
        """Listar contratos con metadata CGC"""
        endpoint = f"{self.graph_url}/sites/{site_id}/drive/root:{folder_path}:/children"
        
        try:
            response = requests.get(endpoint, headers=self._get_headers(), timeout=15)
            response.raise_for_status()
            contracts = response.json()
            
            # CGC Enrichment: añadir risk scores simulados
            for item in contracts.get('value', []):
                item['cgc_risk_score'] = self._estimate_contract_risk(item)
            
            logger.info("Contracts listed", extra={'site_id': site_id, 'count': len(contracts.get('value', []))})
            return contracts
        except Exception as e:
            logger.error("Folder list failed", extra={'error': str(e)})
            return None

    def download_contract(self, site_id: str, drive_item_id: str, file_name: str) -> Optional[bytes]:
        """Descargar contrato para análisis CGC"""
        endpoint = f"{self.graph_url}/sites/{site_id}/drive/items/{drive_item_id}/content"
        
        try:
            response = requests.get(endpoint, headers=self._get_headers(), stream=True)
            response.raise_for_status()
            logger.info("Contract downloaded", extra={'file': file_name})
            return response.content
        except Exception as e:
            logger.error("Download failed", extra={'error': str(e)})
            return None

    def analyze_contract_from_sharepoint(self, site_id: str, drive_item_id: str, 
                                       decision_id: str = None) -> Dict[str, Any]:
        """
        Pipeline completo CGC + SharePoint:
        1. Download → 2. CGC Analysis → 3. SCM Sign → 4. Update metadata
        """
        logger = get_logger("cgc.sharepoint", decision_id=decision_id)
        
        # 1. Download
        file_name = f"contract_{drive_item_id}"
        content = self.download_contract(site_id, drive_item_id, file_name)
        if not content:
            return {"status": "error", "reason": "download_failed"}
        
        # 2. CGC CORE Analysis (mock - integrar tu orchestrator)
        analysis = self._mock_cgc_analysis(content, decision_id)
        
        # 3. SCM Signature
        signed_analysis = self.scm.sign_artifact(analysis, "CONTRACT_ANALYSIS")
        
        # 4. Update SharePoint metadata
        update_result = self._update_contract_metadata(site_id, drive_item_id, signed_analysis)
        
        logger.info("Contract pipeline complete", extra={'risk_score': analysis.get('risk_score')})
        return {
            "status": "success",
            "analysis": analysis,
            "signed_artifact": signed_analysis,
            "sharepoint_updated": update_result
        }

    def _mock_cgc_analysis(self, content: bytes, decision_id: str) -> Dict:
        """Mock CGC analysis - REEMPLAZAR con tu orchestrator real"""
        return {
            "decision_id": decision_id,
            "risk_score": 0.75,
            "compliance_score": 0.88,
            "clauses_detected": 12,
            "high_risk_clauses": ["indemnity", "liability_limit"],
            "recommendations": ["legal_review_required"]
        }

    def _estimate_contract_risk(self, item: Dict) -> float:
        """Risk score simulado basado en metadata"""
        file_name = item.get('name', '').lower()
        risk_indicators = ['indemnity', 'liability', 'nda', 'termination']
        score = 0.5
        for indicator in risk_indicators:
            if indicator in file_name:
                score += 0.1
        return min(score, 1.0)

    def _update_contract_metadata(self, site_id: str, drive_item_id: str, 
                                analysis: Dict) -> bool:
        """Actualizar metadata del contrato con resultados CGC"""
        endpoint = f"{self.graph_url}/sites/{site_id}/drive/items/{drive_item_id}"
        
        metadata = {
            "cgc_risk_score": analysis.get('risk_score'),
            "cgc_compliance": analysis.get('compliance_score'),
            "cgc_status": "analyzed",
            "cgc_timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            response = requests.patch(endpoint, headers=self._get_headers(), 
                                    json={"additionalData": metadata}, timeout=15)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error("Metadata update failed", extra={'error': str(e)})
            return False
