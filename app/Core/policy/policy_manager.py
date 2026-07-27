# policy_manager.py

import time
import copy
from typing import Dict, Any, Optional


class InMemoryPolicyStorage:
    """
    Minimal storage backend for policies.
    In production you would replace this with a DB, KV store, or config service.
    """

    def __init__(self, initial_policies: Dict[str, Any]) -> None:
        # Keep a dict of version_id -> policy_set
        self._versions: Dict[str, Dict[str, Any]] = {}
        # Active policy version metadata
        self._active_version_id: Optional[str] = None

        # Initialize with a first version
        self._init_with_defaults(initial_policies)

    def _init_with_defaults(self, initial_policies: Dict[str, Any]) -> None:
        version_id = self._generate_version_id()
        policy_set = copy.deepcopy(initial_policies)
        policy_set["version"] = version_id
        policy_set["created_at"] = time.time()
        policy_set["created_reason"] = "INITIAL_DEFAULTS"

        self._versions[version_id] = policy_set
        self._active_version_id = version_id

    def _generate_version_id(self) -> str:
        return f"pol-v-{int(time.time() * 1000)}"

    def get_active_policy_set(self) -> Dict[str, Any]:
        if not self._active_version_id:
            raise RuntimeError("No active policy version is set.")
        return self._versions[self._active_version_id]

    def save_new_policy_set(self, policy_set_raw: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> str:
        version_id = self._generate_version_id()
        policy_set = copy.deepcopy(policy_set_raw)
        policy_set["version"] = version_id
        policy_set["created_at"] = time.time()

        metadata = metadata or {}
        policy_set["created_reason"] = metadata.get("reason", "AUTO_UPDATE")
        policy_set["approved_by"] = metadata.get("approved_by", "SYSTEM")
        policy_set["change_type"] = metadata.get("change_type", "INCREMENTAL")

        self._versions[version_id] = policy_set
        self._active_version_id = version_id
        return version_id

    def rollback_to_version(self, version_id: str) -> Dict[str, Any]:
        if version_id not in self._versions:
            raise ValueError(f"Unknown policy version: {version_id}")
        self._active_version_id = version_id
        return self._versions[version_id]

    def get_policy_version(self, version_id: str) -> Dict[str, Any]:
        if version_id not in self._versions:
            raise ValueError(f"Unknown policy version: {version_id}")
        return self._versions[version_id]

    def list_versions(self) -> Dict[str, Dict[str, Any]]:
        return copy.deepcopy(self._versions)

class PolicyManager:
    """

    High-level manager that wraps the storage backend and exposes
    a clean interface for the governance orchestrator.
    """

    def __init__(self, initial_policies: Dict[str, Any]) -> None:
        self._storage = InMemoryPolicyStorage(initial_policies)

    def get_active_policy_set(self) -> Dict[str, Any]:
        return self._storage.get_active_policy_set()

    def save_new_policy_set(self, policy_set_raw: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> str:
        return self._storage.save_new_policy_set(policy_set_raw, metadata)

    def rollback_to_version(self, version_id: str) -> Dict[str, Any]:
        return self._storage.rollback_to_version(version_id)

    def get_policy_version(self, version_id: str) -> Dict[str, Any]:
        return self._storage.get_policy_version(version_id)

    def list_versions(self) -> Dict[str, Any]:
        return self._storage.list_versions()
DEFAULT_POLICIES: Dict[str, Any] = {
    "meta": {
        "name": "CGC-Core Default Policies",
        "description": "Baseline governance policies for risk, ethics and SDA.",
        "jurisdiction": "GLOBAL",
        "sector": "GENERAL",
    },
    "risk": {
        # Allowed risk levels for automatic approval
        "allowed_levels": ["LOW"],
        # Maximum risk score allowed for automatic approval
        "max_risk_score": 70,
        # If risk level is MEDIUM or HIGH, require human review
        "require_human_review_for_levels": ["MEDIUM", "HIGH"],
        # Hard-stop levels: must always be rejected
        "blocked_levels": ["CRITICAL"],
        # Optional safety margin that can be tuned by feedback
        "risk_margin": 0.0,
    },
    "ethics": {
        # Minimal ethical score required for auto-approval
        "min_ethical_score": 90.0,
        # Scores below this threshold are auto-rejected
        "hard_floor_score": 60.0,
        # If ethical score is between floor and min, require human review
        "human_review_range": [60.0, 90.0],
        # Content categories that are always blocked
        "blocked_categories": [
            "ILLEGAL_CONTENT",
            "EXTREME_HARM",
        ],
        # Categories that always require human review
        "human_review_categories": [
            "SENSITIVE_HEALTH",
            "FINANCIAL_ADVICE",
        ],
    },
    "sda": {
        # Maximum number of unresolved recommendations allowed
        "max_allowed_recommendations": 0,
        # Recommendation severities that always trigger human review
        "human_review_severities": ["HIGH"],
        # Recommendation severities that block automatically
        "blocking_severities": ["CRITICAL"],
    },
    "scm": {
        # Example SCM-related configuration hooks
        "require_strong_auth_for_actions": ["GENERATE_CONTRACT", "APPROVE_PAYMENT"],
        "encryption_required": True,
        "min_key_length_bits": 256,
    },
    "review": {
        # Governance cadence / review rhythm
        "continuous_monitoring": True,
        "scheduled_review_days": [1, 15],  # e.g. day of month
        "post_release_hypercare_days": 7,
    },
}
