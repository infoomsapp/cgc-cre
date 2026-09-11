"""
CGC Compliance Engine v1.0.0
EU AI Act High-Risk Checklist + NIST AI RMF Profiles
Production Ready - OlympusMont Systems LLC
"""

import json
import os
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

# SCM integration fallback logic
try:
    from cgc_modules.scm_module import SCMModule
except ImportError:
    try:
        from cgc_modules import SCM as SCMModule
    except ImportError:
        SCMModule = None

# TCO integration fallback logic
try:
    from cgc_modules.tcomodule import TraceabilityOversight as TCOModule
except ImportError:
    try:
        from cgc_modules import TCO as TCOModule
    except ImportError:
        TCOModule = None


class EUAIActRequirement(str, Enum):
    # str mixin: makes members JSON-serializable directly (json.dumps on
    # asdict(profile) elsewhere in this module was always raising
    # TypeError before this -- audit_report_path silently stayed None).
    DATA_REPRESENTATIVE = "data_representative"
    TRANSPARENCY = "transparency"
    HUMAN_OVERSIGHT = "human_oversight"
    CYBERSECURITY = "cybersecurity"
    PERFORMANCE_LOGS = "performance_logs"
    CE_MARKING = "ce_marking"
    SYSTEM_REGISTRY = "system_registry"


@dataclass
class AI_BOM_Component:
    component_id: str
    type: str
    version: str
    vendor: str
    risk_level: str
    sha256: str
    compliance_status: str


@dataclass
class EUAIActChecklist:
    requirement: EUAIActRequirement
    status: str
    evidence: Dict[str, Any]
    score: Optional[float]  # None for MANUAL_REVIEW_REQUIRED -- not automatable
    timestamp: str


@dataclass
class NISTProfile:
    industry: str
    maturity_level: str
    bom: List[AI_BOM_Component]
    rmf_score: Dict[str, float]
    checklist: List[EUAIActChecklist]


@dataclass
class ComplianceSummary:
    profile: NISTProfile
    overall_score: float
    passed: int
    failed: int
    pending: int
    manual_review: int = 0


class ComplianceEngine:
    """
    Core Compliance Engine for CGC CORE.
    Implements EU AI Act High-Risk validation and NIST AI RMF scoring.
    """

    def __init__(self, scm: SCMModule, tco: TCOModule):
        self.scm = scm
        self.tco = tco
        self.profiles = self._load_profiles()

    def _load_profiles(self) -> Dict[str, NISTProfile]:
        """
        Load predefined NIST AI RMF industry profiles.
        """
        return {
            "banking": NISTProfile(
                industry="banking",
                maturity_level="3",
                bom=[],
                rmf_score={"Govern": 75, "Map": 82, "Measure": 68, "Manage": 71},
                checklist=[]
            ),
            "healthcare": NISTProfile(
                industry="healthcare",
                maturity_level="4",
                bom=[],
                rmf_score={"Govern": 88, "Map": 90, "Measure": 85, "Manage": 92},
                checklist=[]
            )
        }

    def validate_eu_ai_act(self, agent_decision: Dict[str, Any], industry: str) -> ComplianceSummary:
        """
        Validate an AI decision against all 7 EU AI Act high-risk
        requirements. Returns a ComplianceSummary object.

        REAL CHECKS (2026-09-11 rewrite): before this, only 2 of the 7
        EUAIActRequirement members were ever evaluated, and both were
        hardcoded placeholders (_check_data_representative/
        _check_transparency always returned status="PASS" with a fixed
        score, regardless of agent_decision's actual content) -- caught
        during an external assessment of this codebase. The other 5
        requirements were silently never checked at all.
        Now: 4 requirements are evaluated for real from fields this
        pipeline actually produces (TRANSPARENCY, HUMAN_OVERSIGHT,
        CYBERSECURITY, PERFORMANCE_LOGS). The remaining 3
        (DATA_REPRESENTATIVE, CE_MARKING, SYSTEM_REGISTRY) are properties
        of the training dataset or an organizational/regulatory filing --
        genuinely not verifiable from a single decision's runtime payload
        -- so they're honestly reported as MANUAL_REVIEW_REQUIRED with an
        evidence note explaining why, rather than a fabricated PASS.
        """
        checkers = {
            EUAIActRequirement.DATA_REPRESENTATIVE: self._check_data_representative,
            EUAIActRequirement.TRANSPARENCY: self._check_transparency,
            EUAIActRequirement.HUMAN_OVERSIGHT: self._check_human_oversight,
            EUAIActRequirement.CYBERSECURITY: self._check_cybersecurity,
            EUAIActRequirement.PERFORMANCE_LOGS: self._check_performance_logs,
            EUAIActRequirement.CE_MARKING: self._check_ce_marking,
            EUAIActRequirement.SYSTEM_REGISTRY: self._check_system_registry,
        }

        checklist_items = []
        for requirement, checker in checkers.items():
            result = checker(agent_decision)
            checklist_items.append(EUAIActChecklist(
                requirement=requirement,
                status=result["status"],
                evidence=result["evidence"],
                score=result["score"],
                timestamp=datetime.utcnow().isoformat()
            ))

        profile = self.profiles.get(industry, self.profiles["banking"])
        profile.checklist = checklist_items

        return self._generate_compliance_summary(profile)

    def _generate_compliance_summary(self, profile: NISTProfile) -> ComplianceSummary:
        """
        Compute aggregated compliance metrics for the profile.

        MANUAL_REVIEW_REQUIRED items (score=None -- genuinely not
        automatable, see validate_eu_ai_act's docstring) are counted
        separately and excluded from overall_score's average, rather
        than either faking a numeric score for them or letting a
        division silently treat None as 0 -- either would misrepresent
        what fraction of the AUTOMATABLE checks actually passed.
        """
        passed = sum(1 for c in profile.checklist if c.status == "PASS")
        failed = sum(1 for c in profile.checklist if c.status == "FAIL")
        pending = sum(1 for c in profile.checklist if c.status == "PENDING")
        manual_review = sum(1 for c in profile.checklist if c.status == "MANUAL_REVIEW_REQUIRED")

        scored = [c.score for c in profile.checklist if c.score is not None]
        overall = (sum(scored) / len(scored)) if scored else 0.0

        return ComplianceSummary(
            profile=profile,
            overall_score=overall,
            passed=passed,
            failed=failed,
            pending=pending,
            manual_review=manual_review,
        )

    def generate_ai_bom(self, agent_id: str, components: List[Dict]) -> List[AI_BOM_Component]:
        """
        Generate an AI Bill of Materials (AI-BOM) for traceability and compliance.
        """
        bom = []
        for comp in components:
            bom.append(AI_BOM_Component(
                component_id=f"{agent_id}_{comp['name']}",
                type=comp['type'],
                version=comp['version'],
                vendor=comp.get('vendor', 'unknown'),
                risk_level=comp.get('risk_level', 'medium'),
                sha256=hashlib.sha256(json.dumps(comp).encode()).hexdigest()[:64],
                compliance_status='pending'
            ))
        return bom

    def generate_pre_audit_report(self, profile: NISTProfile, format: str = 'json', tenant_id: str = "default") -> str:
        """
        Generate a pre-audit report in JSON or PDF format.
        """
        if format == 'pdf':
            return self._generate_pdf_report(profile, tenant_id)
        return json.dumps(asdict(profile), indent=2)

    def _generate_pdf_report(self, profile: NISTProfile, tenant_id: str = "default") -> str:
        """
        Generate a PDF report suitable for CE Marking and audit trails.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        filename = f"cgc_compliance_report_{timestamp.replace(':', '-')}.pdf"
        # Used to write straight into the process CWD -- fails outright on
        # Vercel's read-only filesystem (caught upstream in LOOP, but
        # audit_report_path stayed null on every real request as a result).
        # tempfile.gettempdir() is always writable and portable (Vercel:
        # /tmp, local dev: OS temp dir) -- no new env var needed.
        reports_dir = os.path.join(tempfile.gettempdir(), "cgc_reports")
        os.makedirs(reports_dir, exist_ok=True)
        filepath = os.path.join(reports_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("CGC CORE - EU AI Act Compliance Report", styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Industry: {profile.industry} | Maturity: {profile.maturity_level}", styles['Heading2']))

        bom_data = [["ID", "Type", "Version", "Vendor", "Risk", "Status"]]
        for comp in profile.bom:
            bom_data.append([
                comp.component_id,
                comp.type,
                comp.version,
                comp.vendor,
                comp.risk_level,
                comp.compliance_status
            ])
        story.append(Table(bom_data))

        checklist_data = [["Requirement", "Status", "Score"]]
        for item in profile.checklist:
            checklist_data.append([
                item.requirement.value,
                item.status,
                f"{item.score}%" if item.score is not None else "N/A (manual review)"
            ])
        story.append(Table(checklist_data))

        # sign_data(data: str, tenant_id: str, ...) -> Dict, not raw bytes --
        # this used to call it with a single positional arg (missing the
        # required tenant_id) and pre-encoded bytes where a str is
        # expected, then treat the returned dict as if it were raw
        # signature bytes (.hex()) -- would have raised on every real call
        # even once actually reached.
        if self.scm:
            signature_result = self.scm.sign_data(
                json.dumps(asdict(profile), default=str, sort_keys=True),
                tenant_id,
                context={"operation": "COMPLIANCE_PDF_REPORT"},
            )
            story.append(Paragraph(f"Digital Signature: {signature_result['signature'][:32]}...", styles['Normal']))

        doc.build(story)
        return filepath

    def _check_data_representative(self, decision: Dict) -> Dict:
        """
        Article 10 (data governance): is the training/eval data
        representative of the population the system decides about? This
        is a property of the DATASET, not of any single runtime decision
        -- nothing in a per-decision payload (module scores, weights,
        signature) can answer it. Honestly reported as
        MANUAL_REVIEW_REQUIRED rather than a fabricated PASS.
        """
        return {
            "status": "MANUAL_REVIEW_REQUIRED",
            "evidence": {
                "reason": "Dataset representativeness cannot be assessed from a single "
                          "decision's runtime payload -- this pipeline tracks no dataset "
                          "lineage/statistics. Requires a separate, org-level data audit.",
            },
            "score": None,
        }

    def _check_transparency(self, decision: Dict) -> Dict:
        """
        Article 13 (transparency): can the person affected by this
        decision understand why it was made? Real check against the
        actual decision payload -- PASS only if a human-readable reason
        AND the full per-module score breakdown are both present, not
        just that the keys technically exist with empty values.
        """
        reason = decision.get("reason")
        module_scores = decision.get("module_scores") or {}
        expected_modules = {"pan", "ecm", "pfm", "sda"}
        has_full_breakdown = expected_modules.issubset(module_scores.keys())
        has_reason = isinstance(reason, str) and len(reason.strip()) > 0

        passed = has_reason and has_full_breakdown
        return {
            "status": "PASS" if passed else "FAIL",
            "evidence": {
                "reason_present": has_reason,
                "module_score_breakdown_present": has_full_breakdown,
                "module_scores": module_scores,
                "decision_reason": reason,
                "methodology_endpoint": "GET /governance/scoring-methodology",
            },
            "score": 100.0 if passed else 0.0,
        }

    def _check_human_oversight(self, decision: Dict) -> Dict:
        """
        Article 14 (human oversight): a decision the pipeline itself
        flagged with a critical governance-framework violation must
        never be silently auto-approved. This is a real structural
        invariant _make_decision() already enforces (cgc_loop.py) --
        this check verifies it actually held for THIS decision, rather
        than assuming the code is correct and never checking.
        """
        critical_violation = bool(decision.get("critical_framework_violated"))
        outcome = decision.get("outcome")
        violated_without_oversight = critical_violation and outcome == "APPROVE"

        return {
            "status": "FAIL" if violated_without_oversight else "PASS",
            "evidence": {
                "critical_framework_violated": critical_violation,
                "outcome": outcome,
                "human_review_required": decision.get("human_review_required"),
                "invariant_checked": "critical_framework_violated implies outcome != APPROVE",
            },
            "score": 0.0 if violated_without_oversight else 100.0,
        }

    def _check_cybersecurity(self, decision: Dict) -> Dict:
        """
        Article 15 (accuracy, robustness, cybersecurity): is the decision
        output cryptographically sealed and tamper-evident? Checks for a
        real signature block (SCM.sign_artifact's actual output shape --
        signature_id + data_hash), not just that a "signature" key exists.
        """
        signature = decision.get("signature") or {}
        has_signature_id = bool(signature.get("signature_id"))
        has_data_hash = bool(signature.get("data_hash"))
        signed = has_signature_id and has_data_hash

        return {
            "status": "PASS" if signed else "FAIL",
            "evidence": {
                "signature_id_present": has_signature_id,
                "data_hash_present": has_data_hash,
                "key_id": signature.get("key_id"),
            },
            "score": 100.0 if signed else 0.0,
        }

    def _check_performance_logs(self, decision: Dict) -> Dict:
        """
        Article 12 (record-keeping/logging): does this system actually
        have an active, wired automatic-logging capability? Checks the
        real TCO module dependency this ComplianceEngine instance was
        constructed with, rather than inspecting the decision payload
        (TCO's own log_decision() call happens AFTER compliance
        validation in cgc_loop.py's pipeline order, so the payload itself
        never carries proof of its own future log entry).
        """
        tco_wired = self.tco is not None and hasattr(self.tco, "log_decision")

        return {
            "status": "PASS" if tco_wired else "FAIL",
            "evidence": {
                "tco_module_active": tco_wired,
                "note": "Verifies the logging capability itself is wired and active, "
                        "not this specific decision's own (not-yet-written) log entry.",
            },
            "score": 100.0 if tco_wired else 0.0,
        }

    def _check_ce_marking(self, decision: Dict) -> Dict:
        """
        Article 48 (CE marking): a physical/documentary conformity-
        marking process performed once per product release by the
        provider organization -- not something any runtime decision can
        prove or disprove. Honestly MANUAL_REVIEW_REQUIRED.
        """
        return {
            "status": "MANUAL_REVIEW_REQUIRED",
            "evidence": {
                "reason": "CE marking is an organizational conformity-assessment and "
                          "documentation process, performed once per release -- not "
                          "verifiable from a runtime decision payload.",
            },
            "score": None,
        }

    def _check_system_registry(self, decision: Dict) -> Dict:
        """
        Article 71 (EU database registration of high-risk AI systems):
        a one-time regulatory filing, not a per-decision property.
        Reports honestly based on whether the operator has recorded a
        real registration (env var, set manually once actually filed)
        instead of ever fabricating PASS.
        """
        registered = os.getenv("EU_AI_ACT_SYSTEM_REGISTERED", "").strip().lower() in ("true", "1", "yes")
        return {
            "status": "PASS" if registered else "MANUAL_REVIEW_REQUIRED",
            "evidence": {
                "eu_ai_act_system_registered_env_set": registered,
                "reason": None if registered else (
                    "No EU AI Act high-risk system registration recorded "
                    "(EU_AI_ACT_SYSTEM_REGISTERED unset) -- a one-time regulatory "
                    "filing, not something this pipeline can complete on its own."
                ),
            },
            "score": 100.0 if registered else None,
        }


def integrate_with_cgc_loop(compliance_engine: ComplianceEngine):
    """
    Integration hook for CGC Loop orchestration.
    Extends the governance cycle with compliance validation.
    """
    def enhanced_govern_cycle(self, agent_decision: Dict, industry: str):
        result = self._run_core_modules(agent_decision)

        eu_summary = compliance_engine.validate_eu_ai_act(result, industry)

        result["compliance"] = asdict(eu_summary)
        result["ai_bom"] = compliance_engine.generate_ai_bom(
            "agent_123",
            [{"name": "gpt-4o", "type": "model", "version": "2025-12"}]
        )

        report_path = compliance_engine.generate_pre_audit_report(eu_summary.profile, 'pdf')
        result["audit_report"] = report_path

        return self.scm.seal_result(result)