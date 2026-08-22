"""
CGC-PreFilter - First Layer Governance Validation (OPTIMIZED)
Ultra-lightweight implementation: Data extraction + validation only
No business logic, no configuration - just pure data.
Olympus Mont Systems LLC  2025
"""

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import time

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

try:
    from Core.logging_config import get_logger
    logger = get_logger("cgc.prefilter")
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] [%(levelname)s] %(message)s"
    )
    logger = logging.getLogger("cgc.prefilter")

try:
    from Core.db.database import get_database
except ImportError:
    # Fallback: si no se puede importar, get_database será None
    # Esto permite que el código funcione sin base de datos en modo desarrollo
    get_database = None


# ============================================================================
# ENUMS & TYPES
# ============================================================================

class GovernanceArea(Enum):
    """Supported governance areas"""
    BANKING = "BANKING"
    LEGAL = "LEGAL"
    RETAIL = "RETAIL"
    AUDIT = "AUDIT"
    FINANCE = "FINANCE"
    HEALTHCARE = "HEALTHCARE"
    DEFAULT = "DEFAULT"


class PreFilterOutcome(Enum):
    """PreFilter outcomes - ONLY boolean or pass-through"""
    ALLOW = "ALLOW"             
    DENY = "DENY"                
    REQUIRE_HUMAN = "REQUIRE_HUMAN" 


# ============================================================================
# DATA CLASSES - Pure Data, No Logic
# ============================================================================

@dataclass
class Agent:
    """Represents an AI agent in the system"""
    id: str
    name: str
    status: str  # PILOT, PRODUCTION, DEPRECATED, INACTIVE
    roles: List[str]
    scopes: List[str]
    owners: List[Dict[str, str]]
    capabilities: List[str]
    created_at: str
    updated_at: str


@dataclass
class EnforcementContext:
    """Request context for PreFilter evaluation"""
    user_id: str
    user_roles: List[str]
    action: str
    data_domains: List[str]
    requested_scopes: List[str]
    area: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreFilterCheck:
    """Individual validation check - atomic result"""
    check_name: str
    passed: bool
    details: Optional[str] = None
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PreFilterResult:
    """Pure data output from PreFilter - NO business logic inside"""

    # Request identification
    trace_id: str
    correlation_id: str
    timestamp: str

    # Outcome
    outcome: str  # ALLOW, DENY, REQUIRE_HUMAN
    short_circuit: bool  # True if DENY (don't pass to Core)

    # Validation results (booleans)
    agentValidated: bool
    agentStatus: Optional[str]
    userRolesMatched: bool
    scopesValid: bool
    blockedDomainsDetected: bool

    # Fields WITHOUT default must come before fields WITH default
    areaIdentified: str
    sensitiveDomainsCount: int

    # Fields WITH default values
    blockedDomainName: Optional[str] = None
    complianceOwnerRequired: bool = False
    complianceOwnerPresent: bool = False
    sensitiveDomainsDetected: List[str] = None

    # Trace for audit
    checks: List[PreFilterCheck] = None

    # Metrics
    latency_ms: float = 0.0

    # For Core modules to self-configure
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "outcome": self.outcome,
            "short_circuit": self.short_circuit,
            "agentValidated": self.agentValidated,
            "agentStatus": self.agentStatus,
            "userRolesMatched": self.userRolesMatched,
            "scopesValid": self.scopesValid,
            "blockedDomainsDetected": self.blockedDomainsDetected,
            "blockedDomainName": self.blockedDomainName,
            "complianceOwnerRequired": self.complianceOwnerRequired,
            "complianceOwnerPresent": self.complianceOwnerPresent,
            "areaIdentified": self.areaIdentified,
            "sensitiveDomainsCount": self.sensitiveDomainsCount,
            "sensitiveDomainsDetected": self.sensitiveDomainsDetected or [],
            "checks": [c.to_dict() for c in self.checks] if self.checks else [],
            "latency_ms": self.latency_ms,
            "reason": self.reason,
        }

# ============================================================================
# STATIC DATA - Area Feature Mappings (NO LOGIC)
# ============================================================================

AREA_DATA_MAPPINGS = {
    "BANKING": {
        "sensitive_domains": ["PAYMENT_CARD", "ACCOUNT_ROUTING", "KYC_DATA", "TRANSACTION_HISTORY"],
        "blocked_domains": [],
    },
    "LEGAL": {
        "sensitive_domains": ["CONFIDENTIAL_CONTRACTS", "LITIGATION_DATA", "LEGAL_OPINIONS", "ATTORNEY_CLIENT"],
        "blocked_domains": [],
    },
    "RETAIL": {
        "sensitive_domains": ["CUSTOMER_PII", "PURCHASE_HISTORY", "PAYMENT_INFO"],
        "blocked_domains": [],
    },
    "AUDIT": {
        "sensitive_domains": ["AUDIT_LOGS", "COMPLIANCE_REPORTS", "RISK_ASSESSMENT"],
        "blocked_domains": [],
    },
    "FINANCE": {
        "sensitive_domains": ["INVESTMENT_DATA", "TRADING_DATA", "PORTFOLIO", "RISK_METRICS"],
        "blocked_domains": [],
    },
    "HEALTHCARE": {
        "sensitive_domains": ["PHI", "MEDICAL_RECORDS", "DIAGNOSIS_DATA", "PRESCRIPTION_DATA", "INSURANCE_CLAIMS"],
        "blocked_domains": [],
    },
    "DEFAULT": {
        "sensitive_domains": ["RESTRICTED", "CONFIDENTIAL"],
        "blocked_domains": [],
    },
}


# ============================================================================
# PreFilter OPTIMIZED - Data Extraction Only
# ============================================================================

class PreFilter:
    """
    CGC_PreFilter - OPTIMIZED
    
    Responsibilities (ONLY):
    1. Validate agent exists 
    2. Check RBAC (user roles in agent roles) 
    3. Validate scopes exist in agent 
    4. Detect blocked domains 
    5. Count sensitive domains 
    6. Identify area 
    7. Extract compliance owner requirement 
    8. Pass pure data to SCM/Core 
    
    NO business logic. NO weighting. NO policy decisions.
    """

    def __init__(self):
        """Initialize PreFilter"""
        self.module_name = "CGC-PreFilter"
        self.version = "2.0.0"  # Optimized version
        self.status = "ACTIVE"
        
        self.total_evaluations = 0
        self.total_allows = 0
        self.total_denies = 0
        self.avg_latency_ms = 0.0
        
        logger.info(f"{self.module_name} v{self.version} initialized (OPTIMIZED)")




    def evaluate(
        self,
        agent: Agent,
        context: EnforcementContext,
    ) -> PreFilterResult:
        """
        Evaluate and extract pure data.
        
        Returns PreFilterResult with ONLY:
        - Booleans (pass/fail)
        - Numbers (counts)
        - Strings (identifications)
        
        NO business logic applied here.
        """
        overall_start = time.time()
        trace_id = self._generate_trace_id()
        correlation_id = context.correlation_id or self._generate_correlation_id()
        timestamp = context.timestamp or self._now_iso()
        
        checks: List[PreFilterCheck] = []
        
        # ====================================================================
        # CHECK 1: Agent Exists
        # ====================================================================
        check_start = time.time()
        agent_validated = agent is not None
        checks.append(PreFilterCheck(
            check_name="agent_exists",
            passed=agent_validated,
            details="Agent found in registry" if agent_validated else "Agent not found",
            latency_ms=self._elapsed_ms(check_start),
        ))
        
        # Short-circuit if agent doesn't exist
        if not agent_validated:
            return self._create_deny_result(
                trace_id, correlation_id, timestamp, checks, overall_start,
                "Agent not found in registry"
            )

        # ====================================================================
        # CHECK 2: Agent Status (extract value, don't decide)
        # ====================================================================
        check_start = time.time()
        # CHANGE: Don't reject here. Extract status and let SCM decide.
        agent_status = agent.status
        status_is_active = agent.status in ["PILOT", "PRODUCTION"]
        
        checks.append(PreFilterCheck(
            check_name="agent_status_active",
            passed=status_is_active,
            details=f"Agent status: {agent.status}",
            latency_ms=self._elapsed_ms(check_start),
        ))

        # ====================================================================
        # CHECK 3: User RBAC
        # ====================================================================
        check_start = time.time()
        user_roles_matched = any(role in agent.roles for role in context.user_roles)
        checks.append(PreFilterCheck(
            check_name="user_rbac",
            passed=user_roles_matched,
            details=f"User roles: {context.user_roles}, Agent requires: {agent.roles}",
            latency_ms=self._elapsed_ms(check_start),
        ))
        
        if not user_roles_matched:
            return self._create_deny_result(
                trace_id, correlation_id, timestamp, checks, overall_start,
                f"User roles {context.user_roles} not in agent roles {agent.roles}"
            )

        # ====================================================================
        # CHECK 4: Scopes Validation
        # ====================================================================
        check_start = time.time()
        # CHANGE: Only check if requested scopes EXIST in agent. Don't check count limits.
        # Count limits are SCM/Core responsibility based on area config.
        all_scopes_exist = all(scope in agent.scopes for scope in context.requested_scopes)
        
        checks.append(PreFilterCheck(
            check_name="scopes_exist",
            passed=all_scopes_exist,
            details=f"Requested: {context.requested_scopes}, Available: {agent.scopes}",
            latency_ms=self._elapsed_ms(check_start),
        ))
        
        if not all_scopes_exist:
            return self._create_deny_result(
                trace_id, correlation_id, timestamp, checks, overall_start,
                "Requested scopes not available in agent"
            )

        # ====================================================================
        # CHECK 5: Area Identification
        # ====================================================================
        check_start = time.time()
        area_identified = context.area or GovernanceArea.DEFAULT.value
        try:
            GovernanceArea[area_identified]
        except KeyError:
            area_identified = GovernanceArea.DEFAULT.value
            logger.warning(f"Unknown area '{context.area}', using DEFAULT")
        
        checks.append(PreFilterCheck(
            check_name="area_identified",
            passed=True,
            details=f"Area: {area_identified}",
            latency_ms=self._elapsed_ms(check_start),
        ))

        # ====================================================================
        # CHECK 6: Blocked Domains Detection
        # ====================================================================
        check_start = time.time()
        area_mapping = AREA_DATA_MAPPINGS.get(area_identified, AREA_DATA_MAPPINGS["DEFAULT"])
        blocked_domains = area_mapping["blocked_domains"]
        blocked_domain_found = None
        
        for domain in context.data_domains:
            if domain in blocked_domains:
                blocked_domain_found = domain
                break
        
        checks.append(PreFilterCheck(
            check_name="blocked_domains",
            passed=blocked_domain_found is None,
            details=f"Blocked: {blocked_domain_found}" if blocked_domain_found else "None",
            latency_ms=self._elapsed_ms(check_start),
        ))
        
        # Short-circuit on blocked domain
        if blocked_domain_found:
            return self._create_deny_result(
                trace_id, correlation_id, timestamp, checks, overall_start,
                f"Blocked domain detected: {blocked_domain_found}"
            )

        # ====================================================================
        # CHECK 7: Sensitive Domains Count (extract, don't decide)
        # ====================================================================
        check_start = time.time()
        sensitive_domains_list = area_mapping["sensitive_domains"]
        sensitive_domains_found = [
            domain for domain in context.data_domains if domain in sensitive_domains_list
        ]
        sensitive_count = len(sensitive_domains_found)
        
        checks.append(PreFilterCheck(
            check_name="sensitive_domains",
            passed=True,  # Sensitive domains are OK, just counted
            details=f"Found {sensitive_count} sensitive domains",
            latency_ms=self._elapsed_ms(check_start),
        ))

        # ====================================================================
        # CHECK 8: Compliance Owner Requirement (extract, don't decide)
        # ====================================================================
        check_start = time.time()
        # Query if compliance owner exists in agent. Don't enforce requirement here.
        compliance_owner_present = any(
            owner.get("role") == "COMPLIANCE_OWNER" for owner in agent.owners
        )
        
        checks.append(PreFilterCheck(
            check_name="compliance_owner_present",
            passed=True,  # Just reporting status
            details="Compliance owner present" if compliance_owner_present else "No compliance owner",
            latency_ms=self._elapsed_ms(check_start),
        ))

        # ====================================================================
        # ALL CHECKS PASSED - RETURN PURE DATA
        # ====================================================================
        total_latency_ms = self._elapsed_ms(overall_start)
        
        result = PreFilterResult(
            trace_id=trace_id,
            correlation_id=correlation_id,
            timestamp=timestamp,
            
            # Outcomes
            outcome=PreFilterOutcome.ALLOW.value,
            short_circuit=False,
            
            # Validation results
            agentValidated=True,
            agentStatus=agent.status,
            userRolesMatched=user_roles_matched,
            scopesValid=all_scopes_exist,
            blockedDomainsDetected=False,
            blockedDomainName=None,
            complianceOwnerRequired=False,  #  SCM will check if required based on area
            complianceOwnerPresent=compliance_owner_present,
            
            # Data extraction
            areaIdentified=area_identified,
            sensitiveDomainsCount=sensitive_count,
            sensitiveDomainsDetected=sensitive_domains_found,
            
            # Audit trail
            checks=checks,
            latency_ms=total_latency_ms,
            reason="All PreFilter checks passed",
        )
        
        self._update_metrics("ALLOW", total_latency_ms)
        
        logger.info(
            f"[PreFilter] ALLOW | Agent: {agent.id} | "
            f"Area: {area_identified} | Sensitive: {sensitive_count} | "
            f"Latency: {total_latency_ms:.2f}ms"
        )
        
        return result

    # ========================================================================
    # PRIVATE HELPERS
    # ========================================================================

    def _create_deny_result(
        self,
        trace_id: str,
        correlation_id: str,
        timestamp: str,
        checks: List[PreFilterCheck],
        overall_start: float,
        reason: str,
    ) -> PreFilterResult:
        """Create DENY result - short-circuit"""
        total_latency_ms = self._elapsed_ms(overall_start)
        
        result = PreFilterResult(
            trace_id=trace_id,
            correlation_id=correlation_id,
            timestamp=timestamp,
            outcome=PreFilterOutcome.DENY.value,
            short_circuit=True,
            agentValidated=False,
            agentStatus=None,
            userRolesMatched=False,
            scopesValid=False,
            blockedDomainsDetected=False,
            complianceOwnerRequired=False,
            complianceOwnerPresent=False,
            areaIdentified="DEFAULT",
            sensitiveDomainsCount=0,
            sensitiveDomainsDetected=[],
            checks=checks,
            latency_ms=total_latency_ms,
            reason=reason,
        )
        
        self._update_metrics("DENY", total_latency_ms)
        logger.warning(f"[PreFilter] DENY | {reason} | Latency: {total_latency_ms:.2f}ms")
        
        return result

    def _update_metrics(self, outcome: str, latency_ms: float) -> None:
        """Update metrics"""
        self.total_evaluations += 1
        
        if outcome == "ALLOW":
            self.total_allows += 1
        elif outcome == "DENY":
            self.total_denies += 1
        
        # Exponential moving average
        alpha = 2 / (self.total_evaluations + 1)
        self.avg_latency_ms = (alpha * latency_ms) + ((1 - alpha) * self.avg_latency_ms)

    def _generate_trace_id(self) -> str:
        """Generate unique trace ID"""
        return f"pf_{secrets.token_hex(8).upper()}"

    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID"""
        return f"corr_{secrets.token_hex(12).upper()}"

    def _now_iso(self) -> str:
        """Get current timestamp in ISO 8601"""
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds"""
        return (time.time() - start_time) * 1000

    # ========================================================================
    # METRICS
    # ========================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Get PreFilter metrics"""
        allow_rate = (self.total_allows / self.total_evaluations * 100) \
            if self.total_evaluations > 0 else 0
        
        return {
            "module": self.module_name,
            "version": self.version,
            "status": self.status,
            "total_evaluations": self.total_evaluations,
            "total_allows": self.total_allows,
            "total_denies": self.total_denies,
            "allow_rate_percent": round(allow_rate, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Sample agent
    agent = Agent(
        id="agent-banking-001",
        name="TransactionBot",
        status="PRODUCTION",
        roles=["ANALYST", "TRANSACTION_PROCESSOR"],
        scopes=["read:accounts", "write:transactions", "read:kyc"],
        owners=[
            {"id": "owner-1", "role": "COMPLIANCE_OWNER"},
            {"id": "owner-2", "role": "TECHNICAL_OWNER"},
        ],
        capabilities=["transfer_funds", "approve_transactions"],
        created_at="2025-01-01T00:00:00Z",
        updated_at="2025-01-15T10:00:00Z",
    )

    # Sample context
    context = EnforcementContext(
        user_id="user-12345",
        user_roles=["ANALYST"],
        action="transfer_funds",
        data_domains=["PAYMENT_CARD", "ACCOUNT_ROUTING", "KYC_DATA"],
        requested_scopes=["read:accounts", "write:transactions"],
        area="BANKING",
    )

    # Initialize and evaluate
    prefilter = CGCPreFilter()
    result = prefilter.evaluate(agent, context)

    # Print results
    print("\n" + "="*80)
    print("PREFILTER RESULT (Pure Data)")
    print("="*80)
    print(json.dumps(result.to_dict(), indent=2))

    print("\n" + "="*80)
    print("PREFILTER METRICS")
    print("="*80)
    print(json.dumps(prefilter.get_metrics(), indent=2))
    
    # Save to database if available
    if get_database:
        try:
            db = get_database()
            db.save_prefilter_result(result.correlation_id, result.to_dict())
        except Exception as e:
            logger.warning(f"Could not save PreFilter result to database: {e}")
