"""
CGC Loop Decision - Governance Cycle Orchestrator
Intelligent aggregation of all module signals with context-aware decision logic
Receives PreFilter context and dynamically adjusts weighting and thresholds
CGC core powere by Olympus Mont Systems LLC  2026
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

from app.modules.compliance.compliance_engine import ComplianceEngine
from app.Core.tenant.multi_tenant import tenant_manager
from app.Core.logging import get_logger  
from app.modules.prefilter import PreFilterResult

# FIX 1 — JLA: Model Registry (replaces hardcoded "gpt-4o")
# FIX 2 — PoD: Pre-delivery cryptographic interceptor
from app.modules.pod.pod_interceptor import PoDInterceptor
from app.modules.jla.model_registry import get_model_registry, ModelRegistry

# Inicializar logger primero
logger = get_logger("cgc.loop")

from app.modules.pan.panmodule import PAN
from app.modules.ecm.ecmmodule import ECM  
from app.modules.pfm.pfmmodule import PFM
from app.modules.sda.sdamodule import SDA
from app.modules.tco.tcomodule import TCO

try:
    from .scmmodule import SCMModule as SCM
except ImportError:
    SCM = None
    logger.warning("SCM module not available, continuing without SCM")



# ============================================================================
# DECISION WEIGHTING MATRIX (Area + Sensitivity Based)
# ============================================================================
# Dynamically weights module outputs based on governance area and data sensitivity

DECISION_WEIGHTING_MATRIX = {
    "BANKING": {
        "LOW": {
            "ecm_weight": 0.50,
            "pfm_weight": 0.30,
            "pan_weight": 0.15,
            "sda_weight": 0.05,
            "approval_threshold": 0.80,
            "critical_framework_enforcement": False
        },

        "MEDIUM": {
            "ecm_weight": 0.55,
            "pfm_weight": 0.35,
            "pan_weight": 0.07,
            "sda_weight": 0.03,
            "approval_threshold": 0.85,
            "critical_framework_enforcement": True
        },
        "HIGH": {
            "ecm_weight": 0.65,
            "pfm_weight": 0.25,
            "pan_weight": 0.05,
            "sda_weight": 0.05,
            "approval_threshold": 0.92,
            "critical_framework_enforcement": True,
            "require_human_review": True
        }
    },
    
    "LEGAL": {
        "LOW": {
            "ecm_weight": 0.60,
            "pfm_weight": 0.20,
            "pan_weight": 0.15,
            "sda_weight": 0.05,
            "approval_threshold": 0.82,
            "critical_framework_enforcement": False
        },
        "MEDIUM": {
            "ecm_weight": 0.65,
            "pfm_weight": 0.20,
            "pan_weight": 0.10,
            "sda_weight": 0.05,
            "approval_threshold": 0.87,
            "critical_framework_enforcement": True
        },
        "HIGH": {
            "ecm_weight": 0.75,
            "pfm_weight": 0.15,
            "pan_weight": 0.05,
            "sda_weight": 0.05,
            "approval_threshold": 0.94,
            "critical_framework_enforcement": True,
            "require_human_review": True
        }
    },
    
    "FINANCE": {
        "LOW": {
            "ecm_weight": 0.45,
            "pfm_weight": 0.40,
            "pan_weight": 0.10,
            "sda_weight": 0.05,
            "approval_threshold": 0.82,
            "critical_framework_enforcement": False
        },
        "MEDIUM": {
            "ecm_weight": 0.50,
            "pfm_weight": 0.45,
            "pan_weight": 0.03,
            "sda_weight": 0.02,
            "approval_threshold": 0.88,
            "critical_framework_enforcement": True
        },
        "HIGH": {
            "ecm_weight": 0.55,
            "pfm_weight": 0.40,
            "pan_weight": 0.03,
            "sda_weight": 0.02,
            "approval_threshold": 0.93,
            "critical_framework_enforcement": True,
            "require_human_review": True
        }
    },
    
    "RETAIL": {
        "LOW": {
            "ecm_weight": 0.50,
            "pfm_weight": 0.25,
            "pan_weight": 0.20,
            "sda_weight": 0.05,
            "approval_threshold": 0.75,
            "critical_framework_enforcement": False
        },
        "MEDIUM": {
            "ecm_weight": 0.55,
            "pfm_weight": 0.30,
            "pan_weight": 0.10,
            "sda_weight": 0.05,
            "approval_threshold": 0.80,
            "critical_framework_enforcement": False
        },
        "HIGH": {
            "ecm_weight": 0.60,
            "pfm_weight": 0.30,
            "pan_weight": 0.05,
            "sda_weight": 0.05,
            "approval_threshold": 0.85,
            "critical_framework_enforcement": False,
            "require_human_review": False
        }
    },
    
    "AUDIT": {
        "LOW": {
            "ecm_weight": 0.40,
            "pfm_weight": 0.30,
            "pan_weight": 0.25,
            "sda_weight": 0.05,
            "approval_threshold": 0.80,
            "critical_framework_enforcement": True
        },
        "MEDIUM": {
            "ecm_weight": 0.50,
            "pfm_weight": 0.35,
            "pan_weight": 0.10,
            "sda_weight": 0.05,
            "approval_threshold": 0.85,
            "critical_framework_enforcement": True
        },
        "HIGH": {
            "ecm_weight": 0.60,
            "pfm_weight": 0.30,
            "pan_weight": 0.05,
            "sda_weight": 0.05,
            "approval_threshold": 0.90,
            "critical_framework_enforcement": True,
            "require_human_review": True
        }
    },
    
    "DEFAULT": {
        "LOW": {
            "ecm_weight": 0.40,
            "pfm_weight": 0.35,
            "pan_weight": 0.20,
            "sda_weight": 0.05,
            "approval_threshold": 0.70,
            "critical_framework_enforcement": False
        },
        "MEDIUM": {
            "ecm_weight": 0.45,
            "pfm_weight": 0.40,
            "pan_weight": 0.10,
            "sda_weight": 0.05,
            "approval_threshold": 0.75,
            "critical_framework_enforcement": False
        },
        "HIGH": {
            "ecm_weight": 0.50,
            "pfm_weight": 0.40,
            "pan_weight": 0.05,
            "sda_weight": 0.05,
            "approval_threshold": 0.80,
            "critical_framework_enforcement": False
        }
    }
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ModuleScores:
    """Container for all module scores"""
    pan_score: float  # Feature confidence (0-1)
    ecm_score: float  # Ethical score (0-1)
    pfm_score: float  # Risk score inverted (0-1, where 1 = safe)
    sda_score: float  # Recommendation penalty (0-1)
    
    def to_dict(self) -> Dict[str, float]:
        return {
            "pan": round(self.pan_score, 3),
            "ecm": round(self.ecm_score, 3),
            "pfm": round(self.pfm_score, 3),
            "sda": round(self.sda_score, 3)
        }


@dataclass
class WeightingConfig:
    """Weighting configuration for a specific area + sensitivity combination"""
    ecm_weight: float
    pfm_weight: float
    pan_weight: float
    sda_weight: float
    approval_threshold: float
    critical_framework_enforcement: bool
    require_human_review: bool = False


class LoopOutcome(Enum):
    """Possible governance loop outcomes"""
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"
    ERROR = "ERROR"


# ============================================================================
# GOVERNANCE CYCLE ORCHESTRATOR (ENHANCED)
# ============================================================================

class LOOP:
    """
    CGC Loop Decision - Central orchestrator for governance cycle
    
    Recibe PreFilterResult como primera capa y orquesta todos los módulos
    de gobernanza de manera unificada.
    """
    
    def __init__(self, version: str = "4.0.1"):
        """Initialize Loop Decision with module dependencies"""
        self.module_name = "CGC-Loop-Decision"
        self.version = version
        
        # Module dependencies (con manejo de errores)
        try:
            self.scm = SCM() if SCM else None
        except Exception as e:
            logger.warning(f"SCM initialization failed: {e}, continuing without SCM")
            self.scm = None
        
        self.pan = PAN() if PAN else None
        self.ecm = ECM() if ECM else None
        self.pfm = PFM() if PFM else None
        self.sda = SDA() if SDA else None
        self.tco = TCO() if TCO else None
        
        # ComplianceEngine (solo si SCM y TCO están disponibles)
        try:
            if self.scm and self.tco:
                self.compliance = ComplianceEngine(self.scm, self.tco)
            else:
                logger.warning("ComplianceEngine requires SCM and TCO, initializing without compliance")
                self.compliance = None
        except Exception as e:
            logger.warning(f"ComplianceEngine initialization failed: {e}")
            self.compliance = None
        
        # Weighting matrix
        self.weighting_matrix = DECISION_WEIGHTING_MATRIX

        # FIX 1 — JLA: Provider-agnostic model registry
        # Replaces hardcoded {"name": "gpt-4o"} everywhere in the loop
        self.model_registry: ModelRegistry = get_model_registry()

        # FIX 2 — PoD: Pre-delivery cryptographic interceptor
        # Seals {input_hash, model_id, output_hash} before client delivery
        self.pod = PoDInterceptor(
            signing_key_id=f"cgc-loop-signing-key-v{version}"
        )

        # Metrics
        self.total_decisions = 0
        self.total_approvals = 0
        self.total_rejections = 0
        self.total_human_reviews = 0
        self.avg_decision_time_ms = 0.0
        
        logger.info(
            f"{self.module_name} v{self.version} + PreFilter + "
            f"ComplianceEngine: {'ENABLED' if self.compliance else 'DISABLED'}"
        )

    # ========================================================================
    # MAIN ORCHESTRATION
    # ========================================================================

    def execute_governance_cycle(
        self,
        decision_id: str,
        module_source: str,
        org_id: str,  
        action: str,
        input_data: Dict[str, Any],
        prefilter_result: PreFilterResult,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute full governance cycle with context-aware decision making.
        
        Flujo unificado:
        1. PreFilter (First Layer) - Validación ultra-rápida
        2. SCM Entry Check - Políticas de seguridad
        3. Core Modules (Paralelo) - PAN, ECM, PFM, SDA
        4. Decision & Signing - Agregación y firma
        5. Compliance - EU AI Act + NIST
        6. TCO Audit - Trazabilidad inmutable

        Args:
            decision_id: Unique ID for this decision
            module_source: Originating agent/service ID
            org_id: Organization/tenant ID
            action: Action being governed (e.g., "transfer_funds")
            input_data: Payload for core modules
            prefilter_result: PreFilterResult object (First Layer output)
            context: Optional additional context
        
        Returns:
            Final governance decision artifact (signed and audited)
            {
                "approved": bool,
                "outcome": str,
                "decision_artifact": dict,
                "prefilter_result": dict,
                "processing_time_ms": float
            }
        """
        import time
        overall_start = time.time()
        
        # Convert PreFilterResult to dict if it's an object
        if hasattr(prefilter_result, 'to_dict'):
            prefilter_dict = prefilter_result.to_dict()
        else:
            prefilter_dict = prefilter_result
        
        area_identified = prefilter_dict.get('areaIdentified', 'DEFAULT')
        logger.info(
            f"[Loop] Starting governance cycle | Decision: {decision_id} | "
            f"Area: {area_identified} | Action: {action}"
        )

        # ================================================================
        # STEP 0: PreFilter Short-Circuit Check
        # ================================================================
        if hasattr(prefilter_result, 'short_circuit') and prefilter_result.short_circuit:
            logger.warning(f"[Loop] PreFilter DENY - Short-circuiting: {prefilter_result.reason}")
            return {
                "approved": False,
                "outcome": "REJECT",
                "reason": prefilter_result.reason or "PreFilter validation failed",
                "scm_exit_status": "PREFILTER_DENY",
                "prefilter_result": prefilter_dict,
                "processing_time_ms": (time.time() - overall_start) * 1000
            }

        # ================================================================
        # STEP 0.5: Tenant Quota Check
        # ================================================================
        if not tenant_manager.check_quota(org_id, "decisions"):
            logger.warning(
                f"Tenant {org_id} quota exceeded", 
                extra={'org_id': org_id, 'decision_id': decision_id} 
            )
            audit = self.tco.log_decision(
                decision_id=decision_id,
                module_source=module_source,
                action=action,
                input_data=input_data,
                prefilter_result=prefilter_dict, 
                decision_summary={"outcome": "REJECT", "reason": "TENANT_QUOTA_EXCEEDED"}
            )
            return {
                "approved": False,
                "reason": "monthly_quota_exceeded",
                "scm_exit_status": "QUOTA_BLOCKED",
                "audit": audit,
                "processing_time_ms": (time.time() - overall_start) * 1000
            }

        # Custom policies check
        use_custom_policies = tenant_manager.check_feature(org_id, "custom_policies")

        
        try:
            # ================================================================
            # STEP 1: SCM Entry Check (using PreFilter context)
            # ================================================================
            if not self.scm:
                logger.warning("[Loop] SCM not available, skipping entry check")
                scm_entry = {"approved": True, "reason": "SCM not available"}
            else:
                scm_entry = self.scm.check_entry_policy(
                    action=action,
                    input_data=input_data,
                    prefilter_result=prefilter_dict
                )
            
            if not scm_entry.get("approved", False):
                logger.warning(f"[Loop] SCM Entry rejected: {scm_entry.get('reason')}")
                return self._create_rejection_artifact(
                    decision_id=decision_id,
                    reason="SCM_ENTRY_POLICY_VIOLATION",
                    scm_entry=scm_entry,
                    overall_start=overall_start
                )
            
            # ================================================================
            # FIX 4 — PoD: Begin pre-delivery intercept
            # Captures input hash at transport layer BEFORE model execution
            # Per Patent 1 claim: interceptor positioned before client delivery
            # ================================================================
            pod_model_slug = input_data.get("model_slug", "openai/gpt-4o/2025-12")
            intercept_id = self.pod.begin_intercept(
                decision_id=decision_id,
                tenant_id=org_id,
                model_identifier=pod_model_slug,
                input_payload=input_data
            )
            logger.info(f"[Loop] PoD intercept BEGUN | intercept_id: {intercept_id[:8]}...")

            # ================================================================
            # STEP 2: Execute Core Modules (Parallel-ready, using PreFilter context)
            # ================================================================
            pan_result = self.pan.analyze(input_data=input_data, context=context) if self.pan else {}
            ecm_result = self.ecm.calibrate(
                action=action,
                data=input_data,
                prefilter_result=prefilter_dict,  
                context=context
            ) if self.ecm else {}
            pfm_result = self.pfm.predict(
                action=action,
                input_data=input_data,
                prefilter_result=prefilter_dict,  
                context=context
            ) if self.pfm else {}
            sda_result = self.sda.advise(
                current_data=input_data, 
                prefilter_result=prefilter_dict,  
                context=context
            ) if self.sda else {}
            
            # ================================================================
            # STEP 3: Extract and Normalize Scores
            # ================================================================
            module_scores = self._extract_module_scores(
                pan_result=pan_result,
                ecm_result=ecm_result,
                pfm_result=pfm_result,
                sda_result=sda_result
            )
            
            logger.info(f"[Loop] Module scores extracted: {module_scores.to_dict()}")
            
            # ================================================================
            # STEP 4: Determine Sensitivity Level (from PreFilter)
            # ================================================================
            area = prefilter_dict.get("areaIdentified", "DEFAULT")
            sensitive_count = prefilter_dict.get("sensitiveDomainsCount", 0)
            sensitivity_level = self._determine_sensitivity_level(sensitive_count, area)
            
            logger.info(f"[Loop] Sensitivity determined: {sensitivity_level} ({sensitive_count} domains)")
            
            # ================================================================
            # STEP 5: Get Dynamic Weighting Config
            # ================================================================
            weighting_config = self._get_weighting_config(area, sensitivity_level)
            
            logger.info(
                f"[Loop] Weighting config loaded | Threshold: {weighting_config.approval_threshold} | "
                f"ECM: {weighting_config.ecm_weight}, PFM: {weighting_config.pfm_weight}"
            )
            
            # ================================================================
            # STEP 6: Aggregate Weighted Scores
            # ================================================================
            aggregated_score = self._aggregate_scores(module_scores, weighting_config)
            
            logger.info(f"[Loop] Aggregated score: {aggregated_score:.3f} / {weighting_config.approval_threshold:.3f}")
            
            # ================================================================
            # STEP 7: Check Critical Frameworks (if applicable)
            # ================================================================
            critical_violation = False
            if weighting_config.critical_framework_enforcement:
                critical_violation = self._check_critical_frameworks(ecm_result)
                if critical_violation:
                    logger.warning("[Loop] Critical framework violation detected")
            
            # ================================================================
            # STEP 8: Make Final Decision
            # ================================================================
            decision_outcome, decision_reason = self._make_decision(
                aggregated_score=aggregated_score,
                threshold=weighting_config.approval_threshold,
                critical_violation=critical_violation,
                require_human_review=weighting_config.require_human_review,
                compliance_owner_present=prefilter_dict.get("complianceOwnerPresent", False)
            )
            
            logger.info(f"[Loop] Decision: {decision_outcome.value} | Reason: {decision_reason}")
            
            # ================================================================
            # STEP 9: Build Decision Artifact
            # ================================================================
            decision_artifact = {
                "decision_id": decision_id,
                "module_source": module_source,
                "action": action,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                
                # Governance context
                "area": area,
                "sensitivity_level": sensitivity_level,
                "sensitive_domains_count": sensitive_count,
                
                # Scores
                "module_scores": module_scores.to_dict(),
                "aggregated_score": round(aggregated_score, 3),
                "approval_threshold": weighting_config.approval_threshold,
                
                # Weighting applied
                "weighting_config": {
                    "ecm_weight": weighting_config.ecm_weight,
                    "pfm_weight": weighting_config.pfm_weight,
                    "pan_weight": weighting_config.pan_weight,
                    "sda_weight": weighting_config.sda_weight
                },
                
                # Decision
                "outcome": decision_outcome.value,
                "reason": decision_reason,
                "critical_framework_violated": critical_violation,
                "human_review_required": decision_outcome == LoopOutcome.REQUIRE_HUMAN
            }
            
            # ================================================================
            # STEP 10: SCM SIGN (using PreFilter context)
            # ================================================================
            signed_artifact = decision_artifact  # Default
            if self.scm:
                signed_artifact = self.scm.sign_artifact(
                    artifact=decision_artifact,
                    op_type="LOOP_DECISION",
                    prefilter_result=prefilter_dict
                )
            
            # ================================================================
            # FIX 4 (cont.) — PoD: Seal intercept POST-model, PRE-client delivery
            # This is the critical moment: proof generated while response is
            # still inside the governance layer, before it reaches the caller.
            # ================================================================
            try:
                pod_triplet, pod_block = self.pod.seal_intercept(
                    intercept_id=intercept_id,
                    output_payload=signed_artifact,
                    governance_outcome=decision_outcome.value,
                    compliance_score=aggregated_score
                )
                signed_artifact["pod"] = {
                    "intercept_id":      pod_triplet.intercept_id,
                    "triplet_hash":      pod_triplet.triplet_hash,
                    "model_identifier":  pod_triplet.model_identifier,
                    "intercepted_at":    pod_triplet.intercepted_at,
                    "delivered_at":      pod_triplet.delivered_at,
                    "latency_ms":        pod_triplet.latency_ms,
                    "block_number":      pod_block.block_number,
                    "block_hash":        pod_block.block_hash,
                    "timestamp_token":   pod_triplet.timestamp_token,
                    "timestamp_authority": pod_triplet.timestamp_authority,
                    "pii_detected":      pod_triplet.pii_detected,
                    "non_repudiation":   True   # proof exists in immutable chain
                }
                logger.info(
                    f"[Loop] PoD SEALED | Block: {pod_block.block_number} | "
                    f"Hash: {pod_block.block_hash[:16]}..."
                )
            except Exception as e:
                logger.error(f"[Loop] PoD seal failed: {e}")
                signed_artifact["pod"] = {"status": "ERROR", "error": str(e)}

            # ================================================================
            # STEP 10.5: EU AI Act + NIST COMPLIANCE 
            # ================================================================
            if self.compliance:
                try:
                    compliance_result = self.compliance.validate_eu_ai_act(
                        agent_decision=signed_artifact, 
                        industry=area.lower()  # BANKING -> banking
                    )
                    signed_artifact["compliance"] = compliance_result
                    # FIX 3 — JLA: Use model_registry for agnostic BOM generation
                    # Resolves correct model slug based on area + sensitivity
                    routing = self.model_registry.resolve(
                        requested_slug=input_data.get("model_slug", "openai/gpt-4o/2025-12"),
                        governance_area=area,
                        sensitivity_level=sensitivity_level
                    )
                    bom_components = self.model_registry.get_bom_components(
                        slug=routing.routed_slug,
                        agent_name=f"{area.lower()}_agent",
                        agent_version=self.version
                    )
                    signed_artifact["ai_bom"] = self.compliance.generate_ai_bom(
                        decision_id,
                        bom_components
                    )
                    signed_artifact["model_routing"] = {
                        "requested": routing.requested_slug,
                        "routed_to": routing.routed_slug,
                        "provider":  routing.model_entry.provider.value,
                        "was_substituted": routing.was_substituted,
                        "governance_notes": routing.governance_notes
                    }
                    
                    # Auto-genera PDF report
                    try:
                        report_path = self.compliance.generate_pre_audit_report(
                            compliance_result.profile, 'pdf'
                        )
                        signed_artifact["audit_report_path"] = report_path
                    except Exception as e:
                        logger.warning(f"PDF report generation failed: {e}")
                        signed_artifact["audit_report_path"] = None
                except Exception as e:
                    logger.error(f"Compliance validation failed: {e}")
                    signed_artifact["compliance"] = {"status": "ERROR", "error": str(e)}
                    signed_artifact["ai_bom"] = []
                    signed_artifact["audit_report_path"] = None
            else:
                logger.warning("ComplianceEngine not available, skipping compliance checks")
                signed_artifact["compliance"] = {"status": "SKIPPED", "reason": "ComplianceEngine not available"}
                signed_artifact["ai_bom"] = []
                signed_artifact["audit_report_path"] = None

            
            # ================================================================
            # STEP 11: Audit Log (TCO)
            # ================================================================
            audit_log = None
            if self.tco:
                audit_log = self.tco.log_decision(
                    decision_id=decision_id,
                    module_source=module_source,
                    action=action,
                    input_data=input_data,
                    prefilter_result=prefilter_dict,
                    decision_summary={
                        "outcome": decision_outcome.value,
                        "area": area,
                        "sensitivity_level": sensitivity_level,
                        "aggregated_score": aggregated_score,
                        "modules_executed": ["PAN", "ECM", "PFM", "SDA", "TCO", "SCM"]
                    },
                    loop_result={
                        "module_scores": module_scores.to_dict(),
                        "aggregated_score": aggregated_score
                    }
                )
            
            # ================================================================
            # STEP 12: Update Metrics & Return
            # ================================================================
            tenant_manager.check_quota(org_id, "decisions", increment=1)
            self._update_metrics(decision_outcome, overall_start)
            
            # Determinar cumplimiento EU AI Act
            eu_ai_act_compliant = False
            compliance_report = signed_artifact.get("audit_report_path")
            if self.compliance and "compliance" in signed_artifact:
                try:
                    compliance_data = signed_artifact.get("compliance", {})
                    if hasattr(compliance_data, 'profile'):
                        eu_ai_act_compliant = compliance_data.profile.rmf_score.get("Govern", 0) > 80
                    elif isinstance(compliance_data, dict) and "profile" in compliance_data:
                        profile = compliance_data["profile"]
                        if isinstance(profile, dict) and "rmf_score" in profile:
                            eu_ai_act_compliant = profile["rmf_score"].get("Govern", 0) > 80
                except Exception as e:
                    logger.warning(f"Error checking EU AI Act compliance: {e}")
            
            final_response = {
                "approved": decision_outcome == LoopOutcome.APPROVE,
                "outcome": decision_outcome.value,
                "reason": decision_reason,
                "scm_exit_status": "CLOSED_IMMUTABLE",
                "decision_artifact": signed_artifact,
                "audit": audit_log,
                "processing_time_ms": round((time.time() - overall_start) * 1000, 2),
                "area": area,
                "sensitivity_level": sensitivity_level,
                "eu_ai_act_compliant": eu_ai_act_compliant,
                "compliance_report": compliance_report,
                "prefilter_result": prefilter_dict
            }

            logger.info(f"[Loop] COMPLETE | {decision_id} | {decision_outcome.value} | {aggregated_score:.3f}")
            return final_response
            
        except Exception as exc:
            logger.error(f"[Loop] FAILED {decision_id}: {exc}", exc_info=True)
            return self._create_error_artifact(
                decision_id=decision_id,
                error=str(exc),
                overall_start=overall_start
            )

    # ========================================================================
    # SCORE EXTRACTION & NORMALIZATION
    # ========================================================================

    def _extract_module_scores(
        self,
        pan_result: Dict[str, Any],
        ecm_result: Dict[str, Any],
        pfm_result: Dict[str, Any],
        sda_result: Dict[str, Any]
    ) -> ModuleScores:
        """
        Extract and normalize scores from all modules to 0-1 range.
        Each module returns different formats; normalize them here.
        """
        
        # PAN: Feature confidence (0-1)
        pan_score = pan_result.get("feature_confidence", 0.5)
        
        # ECM: Ethical score (0-1 already, or 0-100 that we normalize)
        ecm_score = ecm_result.get("overall_ethical_score", 0.5)
        if ecm_score > 1.0:
            ecm_score = ecm_score / 100.0
        
        # PFM: Risk score (0-100, need to invert: low risk = high score)
        pfm_risk = pfm_result.get("risk_score", 50)
        pfm_score = (100 - pfm_risk) / 100.0  # Invert: 0 risk  1.0 score
        
        # SDA: Recommendation count (0 recs = good = 1.0, more recs = worse)
        recommendations = sda_result.get("recommendations", [])
        sda_score = max(0.0, 1.0 - (len(recommendations) * 0.7))
        
        logger.info(
            f"[Loop] Normalized scores | PAN: {pan_score:.3f} | ECM: {ecm_score:.3f} | "
            f"PFM: {pfm_score:.3f} | SDA: {sda_score:.3f}"
        )
        
        return ModuleScores(
            pan_score=pan_score,
            ecm_score=ecm_score,
            pfm_score=pfm_score,
            sda_score=sda_score
        )

    # ========================================================================
    # SENSITIVITY & WEIGHTING
    # ========================================================================

    def _determine_sensitivity_level(self, sensitive_count: int, area: str) -> str:
        """
        Determine sensitivity level from domain count and area.
        Same logic as ECM for consistency.
        """
        if area == "BANKING":
            return "HIGH" if sensitive_count >= 3 else ("MEDIUM" if sensitive_count >= 1 else "LOW")
        elif area == "LEGAL":
            return "HIGH" if sensitive_count >= 2 else ("MEDIUM" if sensitive_count >= 1 else "LOW")
        elif area == "FINANCE":
            return "HIGH" if sensitive_count >= 3 else ("MEDIUM" if sensitive_count >= 1 else "LOW")
        else:
            return "HIGH" if sensitive_count >= 4 else ("MEDIUM" if sensitive_count >= 2 else "LOW")

    def _get_weighting_config(self, area: str, sensitivity_level: str) -> WeightingConfig:
        """Retrieve dynamic weighting configuration for area + sensitivity."""
        area_weights = self.weighting_matrix.get(area, self.weighting_matrix["DEFAULT"])
        config_dict = area_weights.get(sensitivity_level, area_weights.get("MEDIUM", {}))
        
        return WeightingConfig(
            ecm_weight=config_dict.get("ecm_weight", 0.5),
            pfm_weight=config_dict.get("pfm_weight", 0.35),
            pan_weight=config_dict.get("pan_weight", 0.10),
            sda_weight=config_dict.get("sda_weight", 0.05),
            approval_threshold=config_dict.get("approval_threshold", 0.80),
            critical_framework_enforcement=config_dict.get("critical_framework_enforcement", False),
            require_human_review=config_dict.get("require_human_review", False)
        )

    def _aggregate_scores(self, scores: ModuleScores, config: WeightingConfig) -> float:
        """Weighted aggregation of all module scores."""
        weighted = (
            (scores.ecm_score * config.ecm_weight) +
            (scores.pfm_score * config.pfm_weight) +
            (scores.pan_score * config.pan_weight) +
            (scores.sda_score * config.sda_weight)
        )
        return min(weighted, 1.0)

    # ========================================================================
    # CRITICAL FRAMEWORKS & DECISION LOGIC
    # ========================================================================

    def _check_critical_frameworks(self, ecm_result: Dict[str, Any]) -> bool:
        """Check if any critical frameworks were violated."""
        concerns = ecm_result.get("concerns", [])
        critical_concerns = [c for c in concerns if c.get("severity") == "CRITICAL"]

        # NIST Govern failure (check via compliance engine)
        # Note: This check is done in compliance validation step, not here

        return len(critical_concerns) > 0

    def _make_decision(
        self,
        aggregated_score: float,
        threshold: float,
        critical_violation: bool,
        require_human_review: bool,
        compliance_owner_present: bool
    ) -> Tuple[LoopOutcome, str]:
        """
        Make final governance decision based on all factors.
        """
        
        # Critical violation  REQUIRE_HUMAN or REJECT
        if critical_violation:
            if compliance_owner_present:
                return LoopOutcome.REQUIRE_HUMAN, "Critical framework violation detected; escalated"
            else:
                return LoopOutcome.REJECT, "Critical framework violation; no compliance owner"
        
        # Check threshold
        if aggregated_score >= threshold:
            if require_human_review:
                return LoopOutcome.REQUIRE_HUMAN, "Above threshold but area requires human review"
            return LoopOutcome.APPROVE, "All checks passed; decision approved"
        else:
            return LoopOutcome.REJECT, f"Below approval threshold ({aggregated_score:.3f} < {threshold:.3f})"

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _create_rejection_artifact(
        self,
        decision_id: str,
        reason: str,
        scm_entry: Dict[str, Any],
        overall_start: float
    ) -> Dict[str, Any]:
        """Create rejection artifact when SCM Entry fails."""
        import time
        return {
            "approved": False,
            "outcome": "REJECT",
            "reason": reason,
            "scm_entry_status": scm_entry,
            "scm_exit_status": "CLOSED_IMMEDIATE",
            "processing_time_ms": (time.time() - overall_start) * 1000
        }

    def _create_error_artifact(
        self,
        decision_id: str,
        error: str,
        overall_start: float
    ) -> Dict[str, Any]:
        """Create error artifact when cycle fails."""
        import time
        return {
            "approved": False,
            "outcome": "ERROR",
            "error": error,
            "scm_exit_status": "ERROR_TRACED",
            "processing_time_ms": (time.time() - overall_start) * 1000
        }

    def _update_metrics(self, outcome: LoopOutcome, overall_start: float) -> None:
        """Update decision metrics."""
        import time
        processing_time = (time.time() - overall_start) * 1000
        
        self.total_decisions += 1
        if outcome == LoopOutcome.APPROVE:
            self.total_approvals += 1
        elif outcome == LoopOutcome.REJECT:
            self.total_rejections += 1
        elif outcome == LoopOutcome.REQUIRE_HUMAN:
            self.total_human_reviews += 1
        
        alpha = 2 / (self.total_decisions + 1)
        self.avg_decision_time_ms = (alpha * processing_time) + ((1 - alpha) * self.avg_decision_time_ms)

    # ========================================================================
    # METRICS
    # ========================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Return Loop Decision metrics."""
        return {
            "module": self.module_name,
            "version": self.version,
            "total_decisions": self.total_decisions,
            "total_approvals": self.total_approvals,
            "total_rejections": self.total_rejections,
            "total_human_reviews": self.total_human_reviews,
            "approval_rate": round(
                (self.total_approvals / self.total_decisions * 100) if self.total_decisions > 0 else 0,
                2
            ),
            "avg_decision_time_ms": round(self.avg_decision_time_ms, 2),
            "weighting_areas": list(self.weighting_matrix.keys())
        }


# ============================================================================
# TEST BLOCK
# ============================================================================

if __name__ == "__main__":
    logger.info("Running CGC Loop Decision test...")
    
    # Simulate module results
    pan_result = {
        "feature_confidence": 0.92,
        "features_extracted": 15
    }
    
    ecm_result = {
        "overall_ethical_score": 0.94,
        "area": "BANKING",
        "sensitivity_level": "HIGH",
        "concerns": [],
        "recommendations": []
    }
    
    pfm_result = {
        "risk_score": 25,  # 25% risk = 75% safety
        "confidence": 0.88
    }
    
    sda_result = {
        "recommendations": ["Monitor for anomalies"],
        "confidence": 0.85
    }
    
    # PreFilter result
    prefilter_result = {
        "areaIdentified": "BANKING",
        "sensitiveDomainsCount": 3,
        "sensitiveDomainsDetected": ["PAYMENT_CARD", "ACCOUNT_ROUTING", "KYC_DATA"],
        "complianceOwnerPresent": True
    }
    
    # Create orchestrator
    orchestrator = LOOP()
    
    # Test score extraction
    print("\n" + "="*80)
    print("MODULE SCORES EXTRACTION")
    print("="*80)
    scores = orchestrator._extract_module_scores(pan_result, ecm_result, pfm_result, sda_result)
    print(json.dumps(scores.to_dict(), indent=2))
    
    # Test weighting
    print("\n" + "="*80)
    print("DYNAMIC WEIGHTING CONFIG")
    print("="*80)
    config = orchestrator._get_weighting_config("BANKING", "HIGH")
    print(json.dumps({
        "ecm_weight": config.ecm_weight,
        "pfm_weight": config.pfm_weight,
        "pan_weight": config.pan_weight,
        "sda_weight": config.sda_weight,
        "approval_threshold": config.approval_threshold,
        "critical_framework_enforcement": config.critical_framework_enforcement
    }, indent=2))
    
    # Test aggregation
    print("\n" + "="*80)
    print("AGGREGATED DECISION SCORE")
    print("="*80)
    agg_score = orchestrator._aggregate_scores(scores, config)
    print(f"Aggregated Score: {agg_score:.3f} / {config.approval_threshold:.3f}")
    
    # Test metrics
    print("\n" + "="*80)
    print("LOOP DECISION METRICS")
    print("="*80)
    print(json.dumps(orchestrator.get_metrics(), indent=2))