"""
Guard - CGC Core reinforcement plan: external guard (Phase 2), internal
guard (Phase 3), their dashboard-visibility read functions, and the
soft-flag -> hard-block enforcement-mode switch.
CGC CORE Module
"""

from .rate_limiter import check_rate_limit
from .login_guard import record_login_attempt, check_login_lockout, detect_credential_stuffing, get_login_activity_stats
from .payload_guard import scan_payload, record_suspicious_payload, get_recent_suspicious_payloads
from .internal_guard import (
    detect_baseline_deviation,
    detect_escalation_chains,
    detect_cross_tenant_reach,
    record_internal_flag,
    get_recent_internal_flags,
)
from .enforcement import is_hard_mode

__all__ = [
    "check_rate_limit",
    "record_login_attempt",
    "check_login_lockout",
    "detect_credential_stuffing",
    "get_login_activity_stats",
    "scan_payload",
    "record_suspicious_payload",
    "get_recent_suspicious_payloads",
    "detect_baseline_deviation",
    "detect_escalation_chains",
    "detect_cross_tenant_reach",
    "record_internal_flag",
    "get_recent_internal_flags",
    "is_hard_mode",
]
