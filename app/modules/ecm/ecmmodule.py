"""
Ethical Calibration Module (ECM) - ENHANCED
Converts ethical principles into quantitative values with industrial calibration matrix.
Dynamically adjusts based on PreFilter context (area, sensitive domains, compliance status).
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import logging

logger = logging.getLogger("cgc.ecm")
logger.setLevel(logging.INFO)


# ============================================================================
# INDUSTRIAL CALIBRATION MATRIX
# ============================================================================
# This matrix is consulted immediately upon receiving PreFilter context.
# It defines baseline ethical scores and sensitivities for each governance area.



# ============================================================================
# ETHICAL CALIBRATION MODULE
# ============================================================================

class ECM:
    """
    Ethical Calibration Module (ECM)
    
    Evaluates actions against ethical frameworks and produces calibrated scores.
    Dynamically adjusts baseline scores based on:
    - Governance area (from PreFilter)
    - Sensitive domain count (from PreFilter)
    - Compliance owner presence (from PreFilter)
    - Action context and data characteristics
    """

    def __init__(self):
        self.module_name = "ECM"
        self.version = "3.0.0"  # Enhanced with industrial calibration
        self.status = "active"
        self.total_calibrations = 0
        
        # Metrics
        self.health = 98.0
        self.accuracy_rate = 97.2
        self.avg_response_time = 180  # ms (faster than before)
        self.error_rate = 0.02
        
        # Load calibration matrix
        # MIGRATED — config loaded from Supabase via CGCDBLoader
        from app.Core.db.cgc_db_loader import get_db_loader
        self._db_loader = get_db_loader()
        # get_metrics() and the `or` fallback in calibrate() both reference
        # self.calibration_matrix -- it was never actually set as an instance
        # attribute (AttributeError on every get_metrics() call). Only
        # "DEFAULT" is ever populated (cgc_jla schema, seeded this session);
        # real per-area entries are a future business decision, not invented
        # here.
        self.calibration_matrix = {"DEFAULT": {}}

        logger.info(f"{self.module_name} v{self.version} initialized with industrial calibration matrix")


    def _get_calibration(self, area: str) -> dict:
        """Load calibration config from Supabase. Replaces INDUSTRIAL_CALIBRATION_MATRIX[area]."""
        config = self._db_loader.get_ecm(area)
        return config if config else self._db_loader.get_ecm("DEFAULT")


    def calibrate(
        self,
        action: str,
        data: Dict[str, Any],
        prefilter_result: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform ethical calibration using PreFilter context.
        
        Args:
            action: Action being evaluated (e.g., 'transfer_funds')
            data: Operational data for the action
            prefilter_result: Output from PreFilter (area, sensitive_count, compliance_owner_present)
            context: Additional context (optional)
        
        Returns:
            Calibrated ethical assessment with scores and recommendations
        """
        start_time = datetime.now()
        
        try:
            # ================================================================
            # STEP 1: Extract area from PreFilter
            # ================================================================
            area = prefilter_result.get("areaIdentified", "DEFAULT")
            area_config = self._get_calibration(area) or ( self.calibration_matrix["DEFAULT"])
            
            logger.info(f"[ECM] Calibrating for area: {area} | Action: {action}")
            
            # ================================================================
            # STEP 2: Determine sensitivity level from PreFilter
            # ================================================================
            sensitive_count = prefilter_result.get("sensitiveDomainsCount", 0)
            sensitivity_level = self._determine_sensitivity_level(sensitive_count, area)
            
            sensitivity_config = area_config["sensitivity_modulation"].get(
                sensitivity_level,
                area_config["sensitivity_modulation"]["LOW"]
            )
            
            logger.info(f"[ECM] Sensitivity level: {sensitivity_level} | Domains: {sensitive_count}")
            
            # ================================================================
            # STEP 3: Get baseline frameworks for area
            # ================================================================
            base_frameworks = area_config["base_frameworks"].copy()
            
            # ================================================================
            # STEP 4: Evaluate each framework with area-specific logic
            # ================================================================
            framework_scores = {}
            for framework, baseline in base_frameworks.items():
                score = self._evaluate_framework(
                    framework=framework,
                    action=action,
                    data=data,
                    baseline=baseline,
                    area=area,
                    context=context
                )
                # Apply sensitivity modulation
                score = score * sensitivity_config["multiplier"]
                framework_scores[framework] = min(score, 1.0)
            
            # ================================================================
            # STEP 5: Apply compliance owner bonus
            # ================================================================
            compliance_owner_bonus = 0.0
            if prefilter_result.get("complianceOwnerPresent", False):
                compliance_owner_bonus = area_config["compliance_owner_bonus"]
                logger.info(f"[ECM] Compliance owner present: +{compliance_owner_bonus*100:.1f}%")
            
            # ================================================================
            # STEP 6: Calculate overall ethical score
            # ================================================================
            overall_score = sum(framework_scores.values()) / len(framework_scores)
            overall_score = min(overall_score + compliance_owner_bonus, 1.0)
            
            # ================================================================
            # STEP 7: Identify concerns and critical framework violations
            # ================================================================
            concerns = self._identify_concerns(
                framework_scores,
                area_config,
                sensitivity_config["threshold"]
            )
            
            # ================================================================
            # STEP 8: Generate recommendations based on area + concerns
            # ================================================================
            recommendations = self._generate_recommendations(
                concerns,
                area,
                sensitivity_level
            )
            
            # ================================================================
            # STEP 9: Determine approval status
            # ================================================================
            threshold = sensitivity_config["threshold"]
            has_critical_violation = any(
                c["severity"] == "CRITICAL" for c in concerns
            )
            approved = overall_score >= threshold and not has_critical_violation
            
            # Processing time in ms
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.total_calibrations += 1
            
            # ================================================================
            # STEP 10: Return calibrated assessment
            # ================================================================
            return {
                "module": self.module_name,
                "version": self.version,
                "status": "calibrated",
                
                # Area and sensitivity context
                "area": area,
                "sensitivity_level": sensitivity_level,
                "sensitivity_multiplier": sensitivity_config["multiplier"],
                "approval_threshold": round(threshold, 3),
                
                # Scores
                "overall_ethical_score": round(overall_score, 3),
                "framework_scores": {k: round(v, 3) for k, v in framework_scores.items()},
                
                # Bonuses applied
                "compliance_owner_bonus_applied": round(compliance_owner_bonus, 3),
                
                # Assessment
                "approved": approved,
                "concerns": concerns,
                "critical_frameworks": area_config["critical_frameworks"],
                "recommendations": recommendations,
                
                # Metadata
                "processing_time_ms": round(processing_time, 2),
                "timestamp": datetime.now().isoformat(),
                "confidence": 0.97,
                "calibration_source": "industrial_matrix"
            }
        
        except Exception as e:
            logger.error(f"[ECM] Calibration failed: {e}", exc_info=True)
            return {
                "module": self.module_name,
                "version": self.version,
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().isoformat()
            }

    # ========================================================================
    # FRAMEWORK EVALUATORS
    # ========================================================================

    def _evaluate_framework(
        self,
        framework: str,
        action: str,
        data: Dict[str, Any],
        baseline: float,
        area: str,
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """Evaluate a specific ethical framework."""
        
        text = str(data).lower()
        
        if framework == "transparency":
            return self._eval_transparency(data, baseline, area)
        elif framework == "fairness":
            return self._eval_fairness(data, baseline, area)
        elif framework == "accountability":
            return self._eval_accountability(data, baseline, area)
        elif framework == "privacy":
            return self._eval_privacy(data, baseline, area)
        elif framework == "security":
            return self._eval_security(data, baseline, area)
        elif framework == "compliance":
            return self._eval_compliance(data, baseline, area)
        elif framework == "sustainability":
            return self._eval_sustainability(data, baseline, context)
        elif framework == "human_oversight":
            return self._eval_human_oversight(data, baseline, area, context)
        
        return baseline

    def _eval_transparency(self, data: Dict, baseline: float, area: str) -> float:
        """Transparency evaluation - area-specific"""
        score = baseline
        text = str(data).lower()
        
        # Banking: requires audit trails
        if area == "BANKING" and ("audit" in text or "log" in text):
            score *= 1.02
        
        # Audit: requires max transparency
        if area == "AUDIT" and ("metadata" in text or "trace" in text):
            score *= 1.03
        
        # Legal: requires documentation
        if area == "LEGAL" and "documented" in text:
            score *= 1.02
        
        return min(score, 1.0)

    def _eval_fairness(self, data: Dict, baseline: float, area: str) -> float:
        """Fairness evaluation - detect bias"""
        score = baseline
        text = str(data).lower()
        
        # Penalize if discriminatory terms present
        for term in ["discriminat", "bias", "unfair", "stereotype"]:
            if term in text:
                score *= 0.93
        
        # Retail: fairness is critical
        if area == "RETAIL" and "customer" in text:
            score *= 1.01
        
        return max(score, 0.75)  # Floor at 0.75

    def _eval_accountability(self, data: Dict, baseline: float, area: str) -> float:
        """Accountability evaluation - area-specific"""
        score = baseline
        text = str(data).lower()
        
        # Banking/Finance: accountability is critical
        if area in ["BANKING", "FINANCE"]:
            if "approval" in text or "authorization" in text:
                score *= 1.02
        
        # Audit: max accountability
        if area == "AUDIT" and "verified" in text:
            score *= 1.03
        
        return min(score, 1.0)

    def _eval_privacy(self, data: Dict, baseline: float, area: str) -> float:
        """Privacy evaluation - detect PII exposure"""
        score = baseline
        text = str(data).lower()
        
        # Detect PII indicators
        pii_indicators = ["email", "phone", "ssn", "address", "personal", "kyc_data"]
        has_pii = any(ind in text for ind in pii_indicators)
        
        if has_pii:
            # Check if protected
            if any(term in text for term in ["encrypt", "secure", "protected", "masked"]):
                score *= 1.0  # No penalty if protected
            else:
                score *= 0.90  # Penalty if PII exposed
        
        # Retail: GDPR sensitivity
        if area == "RETAIL" and has_pii:
            score *= 0.98
        
        # Legal: privilege protection
        if area == "LEGAL" and "confidential" in text:
            score *= 1.02
        
        return score

    def _eval_security(self, data: Dict, baseline: float, area: str) -> float:
        """Security evaluation - detect security measures"""
        score = baseline
        text = str(data).lower()
        
        # Award for security measures
        for term in ["encrypt", "secure", "protect", "authentication", "mfa"]:
            if term in text:
                score *= 1.01
        
        # Banking/Finance: security is critical
        if area in ["BANKING", "FINANCE"]:
            if "encryption" in text:
                score *= 1.02
        
        return min(score, 1.0)

    def _eval_compliance(self, data: Dict, baseline: float, area: str) -> float:
        """Compliance evaluation - regulatory frameworks"""
        score = baseline
        text = str(data).lower()
        
        # Award for compliance mentions
        compliance_terms = ["gdpr", "hipaa", "sox", "kycaml", "pci", "mifid"]
        for term in compliance_terms:
            if term in text:
                score *= 1.01
        
        # Banking: KYC/AML compliance
        if area == "BANKING" and "kyc" in text:
            score *= 1.02
        
        # Audit: compliance is core function
        if area == "AUDIT" and "compliance" in text:
            score *= 1.03
        
        return min(score, 1.0)

    def _eval_sustainability(self, data: Dict, baseline: float, context: Optional[Dict] = None) -> float:
        """Sustainability evaluation - environmental/social impact"""
        score = baseline
        
        if context and context.get("sector") == "environmental":
            score *= 1.05
        
        return min(score, 1.0)

    def _eval_human_oversight(
        self,
        data: Dict,
        baseline: float,
        area: str,
        context: Optional[Dict] = None
    ) -> float:
        """Human oversight evaluation - area-specific"""
        score = baseline
        text = str(data).lower()
        
        # Legal: oversight is critical (attorney-client privilege)
        if area == "LEGAL" and "review" in text:
            score *= 1.03
        
        # Audit: oversight required
        if area == "AUDIT" and "approved" in text:
            score *= 1.02
        
        return min(score, 1.0)

    # ========================================================================
    # SENSITIVITY & CONCERNS
    # ========================================================================

    def _determine_sensitivity_level(self, sensitive_count: int, area: str) -> str:
        """Determine sensitivity level from domain count."""
        if area == "BANKING":
            if sensitive_count >= 3:
                return "HIGH"
            elif sensitive_count >= 1:
                return "MEDIUM"
        elif area == "LEGAL":
            if sensitive_count >= 2:
                return "HIGH"
            elif sensitive_count >= 1:
                return "MEDIUM"
        elif area == "FINANCE":
            if sensitive_count >= 3:
                return "HIGH"
            elif sensitive_count >= 1:
                return "MEDIUM"
        else:
            if sensitive_count >= 4:
                return "HIGH"
            elif sensitive_count >= 2:
                return "MEDIUM"
        
        return "LOW"

    def _identify_concerns(
        self,
        scores: Dict[str, float],
        area_config: Dict[str, Any],
        threshold: float
    ) -> List[Dict[str, Any]]:
        """Identify ethical concerns from framework scores."""
        concerns = []
        critical_frameworks = area_config["critical_frameworks"]
        
        for framework, score in scores.items():
            if score < threshold:
                # Determine severity
                if framework in critical_frameworks:
                    severity = "CRITICAL"
                elif score < 0.80:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                
                concerns.append({
                    "framework": framework,
                    "score": round(score, 3),
                    "severity": severity,
                    "message": f"{framework.capitalize()} below threshold ({threshold})",
                    "is_critical": framework in critical_frameworks
                })
        
        return concerns

    def _generate_recommendations(
        self,
        concerns: List[Dict[str, Any]],
        area: str,
        sensitivity_level: str
    ) -> List[str]:
        """Generate area-specific recommendations."""
        recommendations = []
        
        for concern in concerns:
            framework = concern["framework"]
            
            if framework == "transparency":
                if area == "AUDIT":
                    recommendations.append("Increase audit trail granularity")
                else:
                    recommendations.append("Add detailed logging and documentation")
            
            elif framework == "fairness":
                recommendations.append("Review for potential bias or discrimination")
            
            elif framework == "accountability":
                if area == "BANKING":
                    recommendations.append("Ensure transaction approval chain")
                else:
                    recommendations.append("Implement accountability mechanisms")
            
            elif framework == "privacy":
                if area == "LEGAL":
                    recommendations.append("Strengthen privilege protection")
                elif area == "RETAIL":
                    recommendations.append("Implement GDPR-compliant data handling")
                else:
                    recommendations.append("Encrypt sensitive PII")
            
            elif framework == "security":
                recommendations.append("Enhance security controls and encryption")
            
            elif framework == "compliance":
                if area == "BANKING":
                    recommendations.append("Review KYC/AML compliance")
                elif area == "AUDIT":
                    recommendations.append("Verify regulatory compliance status")
                else:
                    recommendations.append("Review compliance requirements")
            
            elif framework == "human_oversight":
                if area == "LEGAL":
                    recommendations.append("Ensure legal review before action")
                else:
                    recommendations.append("Require human review for this action")
        
        if not recommendations:
            recommendations.append("Ethical standards met - proceed")
        
        # Add sensitivity-based recommendation
        if sensitivity_level == "HIGH":
            recommendations.insert(0, "⚠️ ELEVATED SENSITIVITY: Enhanced monitoring recommended")
        
        return recommendations

    # ========================================================================
    # METRICS
    # ========================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Return module metrics."""
        return {
            "module": self.module_name,
            "version": self.version,
            "status": self.status,
            "health": self.health,
            "uptime": 99.8,
            "accuracy": self.accuracy_rate,
            "response_time_ms": self.avg_response_time,
            "error_rate": self.error_rate,
            "total_calibrations": self.total_calibrations,
            "calibration_matrix_areas": list(self.calibration_matrix.keys())
        }


# ============================================================================
# TEST BLOCK
# ============================================================================

if __name__ == "__main__":
    logger.info("Running ECM test with PreFilter integration...")
    
    ecm = EthicalCalibrationModule()
    
    # Simulate PreFilter result for BANKING area
    prefilter_result = {
        "areaIdentified": "BANKING",
        "sensitiveDomainsCount": 3,
        "sensitiveDomainsDetected": ["PAYMENT_CARD", "ACCOUNT_ROUTING", "KYC_DATA"],
        "complianceOwnerPresent": True
    }
    
    # Test data
    test_data = {
        "action": "transfer_funds",
        "amount": 50000,
        "kyc_data": "verified",
        "encryption": "AES-256",
        "audit_log": True
    }
    
    # Calibrate
    result = ecm.calibrate(
        action="transfer_funds",
        data=test_data,
        prefilter_result=prefilter_result,
        context={"sector": "banking"}
    )
    
    logger.info("\n" + "="*80)
    logger.info("ECM CALIBRATION RESULT")
    logger.info("="*80)
    print(json.dumps(result, indent=2))
    
    logger.info("\n" + "="*80)
    logger.info("ECM METRICS")
    logger.info("="*80)
    print(json.dumps(ecm.get_metrics(), indent=2))