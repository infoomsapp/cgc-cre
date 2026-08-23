"""
Lightweight SQLi/XSS-shaped pattern matching on governance request payloads.
A cheap first filter, not a replacement for real input handling elsewhere --
soft-flag only, per the reinforcement plan's own recommended default: logs
and records the match, never alters the response or blocks the request.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.guard.payload")

# (pattern_name, compiled regex) -- deliberately small and cheap, not a WAF.
_PATTERNS = [
    ("sql_comment_marker", re.compile(r"(--|\#|/\*)")),
    ("sql_union_select", re.compile(r"\bunion\b.{1,20}\bselect\b", re.I)),
    ("sql_tautology", re.compile(r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.I)),
    ("script_tag", re.compile(r"<script\b", re.I)),
    ("javascript_uri", re.compile(r"\bjavascript:", re.I)),
    ("inline_event_handler", re.compile(r"\bon\w+\s*=", re.I)),
]

_MAX_SCAN_DEPTH = 3  # shallow -- input_data isn't expected to nest deeply


def _scan_string(value: str) -> List[str]:
    matched = []
    for name, pattern in _PATTERNS:
        if pattern.search(value):
            matched.append(name)
    return matched


def _walk(value: Any, depth: int, field_path: str, findings: Dict[str, List[str]]) -> None:
    if depth > _MAX_SCAN_DEPTH:
        return
    if isinstance(value, str):
        matched = _scan_string(value)
        if matched:
            findings[field_path] = matched
    elif isinstance(value, dict):
        for k, v in value.items():
            _walk(v, depth + 1, f"{field_path}.{k}" if field_path else str(k), findings)
    elif isinstance(value, list):
        for i, v in enumerate(value[:20]):  # cap -- this is a cheap filter, not exhaustive
            _walk(v, depth + 1, f"{field_path}[{i}]", findings)


def scan_payload(action: str, input_data: Any) -> Dict[str, List[str]]:
    """
    Returns {field_path: [matched_pattern_names]} for every field that hit a
    pattern, or {} if nothing matched. Scans `action` plus a shallow walk of
    `input_data`.
    """
    findings: Dict[str, List[str]] = {}
    action_matches = _scan_string(action or "")
    if action_matches:
        findings["action"] = action_matches
    _walk(input_data, 0, "input_data", findings)
    return findings


def record_suspicious_payload(decision_id: Optional[str], org_id: Optional[str], field: str, pattern: str) -> None:
    """Soft-flag record -- stores which pattern/field matched, never the payload content."""
    db = get_database()
    try:
        with db.get_scoped_connection(tenant_id=org_id) as conn:
            if conn is None:
                return
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO cgc_guard.suspicious_payloads (decision_id, org_id, field, pattern_matched) "
                "VALUES (%s, %s, %s, %s)",
                (decision_id, org_id, field, pattern)
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"[guard] failed to record suspicious payload (non-fatal): {e}")


def get_recent_suspicious_payloads(limit: int = 50) -> List[Dict[str, Any]]:
    """Dashboard/visibility read -- most recent soft-flagged payloads, newest first."""
    db = get_database()
    try:
        with db.get_connection() as conn:
            if conn is None:
                return []
            cur = conn.cursor()
            cur.execute(
                "SELECT decision_id, org_id, field, pattern_matched, created_at "
                "FROM cgc_guard.suspicious_payloads ORDER BY created_at DESC LIMIT %s",
                (limit,)
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.warning(f"[guard] failed to read suspicious payloads (non-fatal): {e}")
        return []
