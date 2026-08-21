"""
Guard - Phase 2 of the CGC Core reinforcement plan: external guard.
CGC CORE Module
"""

from .rate_limiter import check_rate_limit
from .login_guard import record_login_attempt, check_login_lockout, detect_credential_stuffing
from .payload_guard import scan_payload, record_suspicious_payload
from .internal_guard import (
    detect_baseline_deviation,
    detect_escalation_chains,
    detect_cross_tenant_reach,
    record_internal_flag,
)

__all__ = [
    "check_rate_limit",
    "record_login_attempt",
    "check_login_lockout",
    "detect_credential_stuffing",
    "scan_payload",
    "record_suspicious_payload",
    "detect_baseline_deviation",
    "detect_escalation_chains",
    "detect_cross_tenant_reach",
    "record_internal_flag",
]
