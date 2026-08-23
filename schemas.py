"""
CGC Core — API Response Models
Pydantic schemas for all API responses.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from datetime import datetime


# ============================================================================
# VERIFY ENDPOINT MODELS
# ============================================================================

class GovernanceInfo(BaseModel):
    action:             str
    area:               str
    sensitivity_level:  str
    outcome:            str
    aggregated_score:   Optional[float] = None
    approval_threshold: Optional[float] = None
    judge_version:      str
    decided_at:         Optional[str] = None
    processing_time_ms: Optional[float] = None


class ProofOfDecision(BaseModel):
    pod_hash:           Optional[str] = None
    triplet_hash:       Optional[str] = None
    triplet_signature:  Optional[str] = None
    timestamp_token:    Optional[str] = None
    merkle_root:        Optional[str] = None
    non_repudiation:    bool = False

    model_config = {"populate_by_name": True}


class ChainPosition(BaseModel):
    block_number:       Optional[int] = None
    previous_pod_hash:  Optional[str] = None
    anchored:           bool = False
    anchor_tx:          Optional[str] = None


class DecisionContext(BaseModel):
    area_identified:            Optional[str] = None
    sensitive_domains_count:    Optional[int] = None
    compliance_owner_present:   Optional[bool] = None
    short_circuit:              Optional[bool] = None


class ModuleScore(BaseModel):
    module_name:        str
    raw_score:          Optional[float] = None
    normalized_score:   Optional[float] = None
    weight_applied:     Optional[float] = None
    contribution:       Optional[float] = None
    concerns:           List[Any] = []
    recommendations:    List[Any] = []


class ChainBlock(BaseModel):
    block_number:       int
    pod_hash:           str
    previous_pod_hash:  Optional[str] = None
    outcome:            str
    created_at:         str


class VerifyResponse(BaseModel):
    decision_id:        str
    verified_at:        str
    tenant_id:          str
    governance:         GovernanceInfo
    proof_of_decision:  ProofOfDecision
    chain:              ChainPosition
    context:            DecisionContext
    module_scores:      Optional[List[ModuleScore]] = None
    chain_proof:        Optional[List[ChainBlock]] = None


# ============================================================================
# CHAIN INTEGRITY MODEL
# ============================================================================

class ChainIntegrityResponse(BaseModel):
    tenant_id:          str
    blocks_verified:    int
    from_block:         Optional[int] = None
    to_block:           Optional[int] = None
    integrity_passed:   bool
    broken_at_block:    Optional[int] = None
    verified_at:        str
    message:            Optional[str] = None


# ============================================================================
# GOVERN ENDPOINT MODELS
# ============================================================================

class GovernRequest(BaseModel):
    decision_id:    str = Field(..., description="Unique ID for this decision")
    module_source:  str = Field(..., description="Originating agent/service ID")
    action:         str = Field(..., description="Action being governed e.g. transfer_funds")
    input_data:     Dict[str, Any] = Field(..., description="Payload for governance modules")
    model_slug:     str = Field(
        default="openai/gpt-4o/2025-12",
        description="Canonical model ID: provider/model/version"
    )
    context:        Optional[Dict[str, Any]] = None


class GovernResponse(BaseModel):
    decision_id:        str
    approved:           bool
    outcome:            str
    reason:             str
    aggregated_score:   Optional[float] = None
    area:               str
    sensitivity_level:  str
    # Was eu_ai_act_compliant: Optional[bool] -- a per-decision "IS
    # compliant" verdict that cgc_loop.py derived solely from a static,
    # hardcoded per-industry NIST RMF "Govern" score in
    # ComplianceEngine._load_profiles() (e.g. every "healthcare" decision
    # got True, every other area got False), with no relation to the actual
    # decision content. A fabricated-looking certification flag, not a real
    # compliance determination -- removed rather than reworded, same as the
    # root endpoint's "compliance" field.
    pod:                Optional[Dict[str, Any]] = None
    processing_time_ms: float
    verify_url:         str = Field(..., description="URL to forensic verification")