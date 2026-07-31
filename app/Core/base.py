# cgc-core/src/core/base.py
"""
Template base para CGC Core - Ciclo de Gobernanza Cognitiva
Proporciona las estructuras fundamentales para gobernanza y auditoría
"""

from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, asdict
import uuid
import hashlib
from abc import ABC, abstractmethod


class DecisionType(str, Enum):
    """Tipos de decisiones auditables"""
    CREDIT_APPROVAL = "credit_approval"
    LEGAL_REVIEW = "legal_review"
    MEDICAL_DIAGNOSIS = "medical_diagnosis"
    RETAIL_RECOMMENDATION = "retail_recommendation"
    COMPLIANCE_CHECK = "compliance_check"


class ComplianceStatus(str, Enum):
    """Estados de cumplimiento"""
    APPROVED = "approved"
    FLAGGED = "flagged"
    REJECTED = "rejected"
    PENDING_REVIEW = "pending_review"


@dataclass
class AuditRecord:
    """Registro de auditoría inmutable"""
    decision_id: str
    agent_id: str
    decision_type: DecisionType
    timestamp: datetime
    decision_data: Dict[str, Any]
    confidence_score: float
    digital_signature: str
    compliance_status: ComplianceStatus
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['decision_type'] = self.decision_type.value
        data['compliance_status'] = self.compliance_status.value
        return data


class GovernanceEngine(ABC):
    """Base abstracta para motores de gobernanza"""
    
    @abstractmethod
    def validate_decision(self, decision_data: Dict[str, Any], agent_id: str) -> bool:
        """Validar decisión antes de ejecución"""
        pass
    
    @abstractmethod
    def audit_decision(self, record: AuditRecord) -> str:
        """Crear registro de auditoría con firma"""
        pass
    
    @abstractmethod
    def verify_integrity(self, decision_id: str) -> bool:
        """Verificar integridad criptográfica"""
        pass


class CGCCore(GovernanceEngine):
    """
    Implementación principal del CGC Core
    Orquesta gobernanza, auditoría y seguridad de decisiones de IA
    """
    
    def __init__(self, sector: str = "generic"):
        self.sector = sector
        self.audit_log: Dict[str, AuditRecord] = {}
        self.policies = self._load_policies()
    
    def _load_policies(self) -> Dict[str, Any]:
        """Cargar políticas por sector"""
        policies = {
            "banking": {
                "max_credit_amount": 1000000,
                "approval_threshold": 0.95,
                "flags_on_high_risk": True
            },
            "legal": {
                "requires_human_review": True,
                "document_integrity_check": True
            },
            "healthcare": {
                "requires_second_opinion": True,
                "patient_data_encryption": "AES-256"
            },
            "generic": {}
        }
        return policies.get(self.sector, {})
    
    def submit_decision(
        self,
        agent_id: str,
        decision_type: DecisionType,
        decision_data: Dict[str, Any],
        confidence_score: float,
        reasoning: str
    ) -> str:
        """
        Enviar decisión de IA para gobernanza
        
        Returns:
            decision_id: Identificador único de la decisión
        """
        # Generar ID único
        decision_id = str(uuid.uuid4())
        
        # Validar decisión según políticas
        if not self.validate_decision(decision_data, agent_id):
            compliance_status = ComplianceStatus.FLAGGED
        else:
            compliance_status = ComplianceStatus.APPROVED
        
        # Crear registro de auditoría
        record = AuditRecord(
            decision_id=decision_id,
            agent_id=agent_id,
            decision_type=decision_type,
            timestamp=datetime.utcnow(),
            decision_data=decision_data,
            confidence_score=confidence_score,
            digital_signature=self._sign_decision(decision_id, decision_data),
            compliance_status=compliance_status
        )
        
        # Almacenar en log
        self.audit_log[decision_id] = record
        
        return decision_id
    
    def _sign_decision(self, decision_id: str, data: Dict[str, Any]) -> str:
        """Generar firma digital criptográfica"""
        content = f"{decision_id}:{str(data)}"
        signature = hashlib.sha256(content.encode()).hexdigest()
        return signature
    
    def validate_decision(self, decision_data: Dict[str, Any], agent_id: str) -> bool:
        """Validar contra políticas del sector"""
        # Implementar lógica de validación por sector
        if self.sector == "banking":
            amount = decision_data.get("amount", 0)
            if amount > self.policies.get("max_credit_amount", float('inf')):
                return False
        
        return True
    
    def audit_decision(self, record: AuditRecord) -> str:
        """Registrar decisión con trazabilidad completa"""
        self.audit_log[record.decision_id] = record
        return record.decision_id
    
    def verify_integrity(self, decision_id: str) -> bool:
        """Verificar que decisión no ha sido modificada"""
        if decision_id not in self.audit_log:
            return False
        
        record = self.audit_log[decision_id]
        expected_signature = self._sign_decision(decision_id, record.decision_data)
        
        return record.digital_signature == expected_signature
    
    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Obtener decisión con trazabilidad completa"""
        if decision_id not in self.audit_log:
            return None
        
        record = self.audit_log[decision_id]
        return {
            **record.to_dict(),
            "is_valid": self.verify_integrity(decision_id)
        }
    
    def get_governance_metrics(self) -> Dict[str, Any]:
        """Dashboard de gobernanza"""
        total_decisions = len(self.audit_log)
        approved = sum(
            1 for r in self.audit_log.values()
            if r.compliance_status == ComplianceStatus.APPROVED
        )
        flagged = sum(
            1 for r in self.audit_log.values()
            if r.compliance_status == ComplianceStatus.FLAGGED
        )
        
        return {
            "total_decisions": total_decisions,
            "approved_decisions": approved,
            "flagged_decisions": flagged,
            "approval_rate": approved / total_decisions if total_decisions > 0 else 0,
            "sector": self.sector
        }


# Use Test
if __name__ == "__main__":
    # Inicializar CGC Core para banca
    cgc = CGCCore(sector="banking")
    
    # Simular decisión de IA
    decision_id = cgc.submit_decision(
        agent_id="agent_creditml_001",
        decision_type=DecisionType.CREDIT_APPROVAL,
        decision_data={
            "applicant_id": "app_12345",
            "amount": 50000,
            "credit_score": 750,
            "risk_category": "low"
        },
        confidence_score=0.97,
        reasoning="Credit score above 700, stable income, low debt ratio"
    )
    
    print(f"Decision ID: {decision_id}")
    print(f"Decision Details: {cgc.get_decision(decision_id)}")
    print(f"Governance Metrics: {cgc.get_governance_metrics()}")
    print(f"Integrity Check: {cgc.verify_integrity(decision_id)}")