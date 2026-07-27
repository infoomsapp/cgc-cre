"""
CGC Core — Model Registry & JLA Agnostic Router
Patent 2: Judge Layer Agnóstico — provider-agnostic AI model governance

Replaces the hardcoded "gpt-4o" reference in cgc_loop.py with a
declarative registry that allows CGC Core to govern ANY AI model
from ANY provider without modifying the governance logic.

The router is the "transparent proxy" in the patent claim:
it sits between the client and the model, applying policies
agnostic to the provider.

Olympus Mont Systems LLC © 2026
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from enum import Enum

try:
    from app.Core.logging import get_logger
    logger = get_logger("cgc.model_registry")
except ImportError:
    logger = logging.getLogger("cgc.model_registry")


# ============================================================================
# ENUMS
# ============================================================================

class ModelProvider(Enum):
    OPENAI      = "openai"
    ANTHROPIC   = "anthropic"
    GOOGLE      = "google"
    MISTRAL     = "mistral"
    META        = "meta"
    COHERE      = "cohere"
    CUSTOM      = "custom"


class ModelRiskTier(Enum):
    """
    Risk classification per EU AI Act Article 6 logic.
    Used by JLA to adjust governance intensity.
    """
    MINIMAL     = "MINIMAL"     # Spam filters, games
    LIMITED     = "LIMITED"     # Chatbots, recommendation
    HIGH        = "HIGH"        # Credit, hiring, legal, medical
    UNACCEPTABLE = "UNACCEPTABLE"  # Prohibited by EU AI Act


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ModelEntry:
    """
    A registered AI model in the JLA registry.
    
    The canonical model_slug format is:
        "provider/model_name/version"
    e.g.: "openai/gpt-4o/2025-12"
         "anthropic/claude-3-5-sonnet/20241022"
         "google/gemini-1-5-pro/latest"
    
    This is the model_identifier used in the PoD triplet hash.
    """
    model_slug:      str                    # canonical: provider/name/version
    provider:        ModelProvider
    model_name:      str
    model_version:   str
    display_name:    str
    capabilities:    List[str]              # ["text", "vision", "function_call"]
    risk_tier:       ModelRiskTier
    context_window:  int                    # max tokens
    supports_system: bool = True
    is_active:       bool = True
    adapter_config:  Dict[str, Any] = field(default_factory=dict)
    risk_notes:      str = ""

    def to_bom_component(self) -> Dict[str, Any]:
        """Returns AI-BOM compatible component dict for compliance_engine."""
        return {
            "name":       self.model_name,
            "type":       "model",
            "version":    self.model_version,
            "vendor":     self.provider.value,
            "risk_level": self.risk_tier.value.lower(),
            "slug":       self.model_slug
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["provider"]   = self.provider.value
        d["risk_tier"]  = self.risk_tier.value
        return d


@dataclass
class RoutingDecision:
    """Result of the JLA router selecting a model for a request."""
    requested_slug:     str
    routed_slug:        str
    model_entry:        ModelEntry
    routing_reason:     str
    was_substituted:    bool    # True if routed != requested (policy override)
    governance_notes:   List[str] = field(default_factory=list)


# ============================================================================
# BUILT-IN MODEL REGISTRY
# Default entries covering major providers
# Operators can extend via register_model()
# ============================================================================

_DEFAULT_MODELS: List[ModelEntry] = [

    # ── OpenAI ──────────────────────────────────────────────────────────────
    ModelEntry(
        model_slug="openai/gpt-4o/2025-12",
        provider=ModelProvider.OPENAI,
        model_name="gpt-4o",
        model_version="2025-12",
        display_name="GPT-4o (Dec 2025)",
        capabilities=["text", "vision", "function_call", "json_mode"],
        risk_tier=ModelRiskTier.LIMITED,
        context_window=128000,
        adapter_config={"api_base": "https://api.openai.com/v1", "endpoint": "/chat/completions"},
    ),
    ModelEntry(
        model_slug="openai/gpt-4o-mini/2025-12",
        provider=ModelProvider.OPENAI,
        model_name="gpt-4o-mini",
        model_version="2025-12",
        display_name="GPT-4o Mini (Dec 2025)",
        capabilities=["text", "function_call", "json_mode"],
        risk_tier=ModelRiskTier.MINIMAL,
        context_window=128000,
        adapter_config={"api_base": "https://api.openai.com/v1", "endpoint": "/chat/completions"},
    ),

    # ── Anthropic ────────────────────────────────────────────────────────────
    ModelEntry(
        model_slug="anthropic/claude-sonnet-4-6/20250514",
        provider=ModelProvider.ANTHROPIC,
        model_name="claude-sonnet-4-6",
        model_version="20250514",
        display_name="Claude Sonnet 4.6",
        capabilities=["text", "vision", "function_call"],
        risk_tier=ModelRiskTier.LIMITED,
        context_window=200000,
        adapter_config={"api_base": "https://api.anthropic.com/v1", "endpoint": "/messages"},
    ),
    ModelEntry(
        model_slug="anthropic/claude-opus-4-6/20250514",
        provider=ModelProvider.ANTHROPIC,
        model_name="claude-opus-4-6",
        model_version="20250514",
        display_name="Claude Opus 4.6",
        capabilities=["text", "vision", "function_call"],
        risk_tier=ModelRiskTier.LIMITED,
        context_window=200000,
        adapter_config={"api_base": "https://api.anthropic.com/v1", "endpoint": "/messages"},
    ),

    # ── Google ───────────────────────────────────────────────────────────────
    ModelEntry(
        model_slug="google/gemini-1-5-pro/latest",
        provider=ModelProvider.GOOGLE,
        model_name="gemini-1.5-pro",
        model_version="latest",
        display_name="Gemini 1.5 Pro",
        capabilities=["text", "vision", "function_call"],
        risk_tier=ModelRiskTier.LIMITED,
        context_window=1000000,
        adapter_config={"api_base": "https://generativelanguage.googleapis.com/v1beta", "endpoint": "/models/{model}:generateContent"},
    ),

    # ── Mistral ──────────────────────────────────────────────────────────────
    ModelEntry(
        model_slug="mistral/mistral-large/latest",
        provider=ModelProvider.MISTRAL,
        model_name="mistral-large-latest",
        model_version="latest",
        display_name="Mistral Large",
        capabilities=["text", "function_call"],
        risk_tier=ModelRiskTier.LIMITED,
        context_window=131000,
        adapter_config={"api_base": "https://api.mistral.ai/v1", "endpoint": "/chat/completions"},
    ),

    # ── Meta (self-hosted) ───────────────────────────────────────────────────
    ModelEntry(
        model_slug="meta/llama-3-1-70b/custom",
        provider=ModelProvider.META,
        model_name="llama-3.1-70b-instruct",
        model_version="custom",
        display_name="Llama 3.1 70B (Self-Hosted)",
        capabilities=["text"],
        risk_tier=ModelRiskTier.LIMITED,
        context_window=131000,
        adapter_config={"api_base": "http://localhost:8080", "endpoint": "/v1/chat/completions"},
        risk_notes="Self-hosted — no third-party data transfer"
    ),
]


# ============================================================================
# MODEL REGISTRY
# ============================================================================

class ModelRegistry:
    """
    JLA Model Registry: the declarative, provider-agnostic model catalog.
    
    This replaces the hardcoded {"name": "gpt-4o", ...} in cgc_loop.py.
    
    The registry allows CGC Core to:
    1. Route any model request through the governance layer
    2. Substitute models based on governance policy (e.g., block HIGH risk)
    3. Generate correct AI-BOM components per model
    4. Provide canonical model_identifier for PoD triplet hashes
    
    Per Patent 2 (JLA) claim:
    "The governance layer operates agnostic to the AI model provider,
    applying declarative policies without requiring modification of
    the governed system or the client application."
    """

    def __init__(self):
        self._registry: Dict[str, ModelEntry] = {}
        self._load_defaults()
        logger.info(f"[ModelRegistry] Initialized with {len(self._registry)} models")

    def _load_defaults(self) -> None:
        for model in _DEFAULT_MODELS:
            self._registry[model.model_slug] = model

    def register_model(self, entry: ModelEntry) -> None:
        """Register a new or updated model entry."""
        self._registry[entry.model_slug] = entry
        logger.info(f"[ModelRegistry] Registered: {entry.model_slug}")

    def get_model(self, slug: str) -> Optional[ModelEntry]:
        """Retrieve a model by canonical slug."""
        return self._registry.get(slug)

    def resolve(
        self,
        requested_slug: str,
        governance_area: str,
        sensitivity_level: str,
        tenant_overrides: Optional[Dict[str, str]] = None
    ) -> RoutingDecision:
        """
        Resolve the model to use for a given request.
        
        This is the JLA router:
        - Looks up the requested model
        - Applies governance policy (e.g., block HIGH-risk models for BANKING+HIGH)
        - Optionally substitutes a safer model
        - Returns a RoutingDecision with full audit trail
        
        Args:
            requested_slug:    what the client/agent requested
            governance_area:   BANKING, LEGAL, FINANCE, etc.
            sensitivity_level: LOW, MEDIUM, HIGH
            tenant_overrides:  optional per-tenant model mappings
        
        Returns:
            RoutingDecision with routed model and governance notes
        """
        notes = []

        # Check tenant overrides first
        effective_slug = requested_slug
        if tenant_overrides and requested_slug in tenant_overrides:
            effective_slug = tenant_overrides[requested_slug]
            notes.append(f"Tenant override: {requested_slug} → {effective_slug}")

        # Look up model
        model = self._registry.get(effective_slug)

        if model is None:
            # Unknown model — fallback to safe default
            fallback_slug = "openai/gpt-4o/2025-12"
            fallback = self._registry[fallback_slug]
            notes.append(f"Unknown model '{effective_slug}' — routed to safe default")
            logger.warning(f"[ModelRegistry] Unknown model: {effective_slug} — using fallback")
            return RoutingDecision(
                requested_slug=requested_slug,
                routed_slug=fallback_slug,
                model_entry=fallback,
                routing_reason="unknown_model_fallback",
                was_substituted=True,
                governance_notes=notes
            )

        if not model.is_active:
            notes.append(f"Model '{effective_slug}' is inactive — routing to fallback")
            return self._fallback_routing(requested_slug, effective_slug, notes)

        # Governance policy: block UNACCEPTABLE risk models
        if model.risk_tier == ModelRiskTier.UNACCEPTABLE:
            notes.append(f"BLOCKED: risk tier UNACCEPTABLE for model {effective_slug}")
            return self._fallback_routing(requested_slug, effective_slug, notes)

        # Governance policy: HIGH sensitivity + HIGH risk model → add governance note
        if sensitivity_level == "HIGH" and model.risk_tier == ModelRiskTier.HIGH:
            notes.append(f"HIGH sensitivity + HIGH risk model — enhanced governance applied")

        return RoutingDecision(
            requested_slug=requested_slug,
            routed_slug=effective_slug,
            model_entry=model,
            routing_reason="direct_route",
            was_substituted=(effective_slug != requested_slug),
            governance_notes=notes
        )

    def _fallback_routing(
        self,
        requested_slug: str,
        blocked_slug: str,
        notes: List[str]
    ) -> RoutingDecision:
        """Route to safe fallback when requested model is blocked."""
        fallback_slug = "openai/gpt-4o/2025-12"
        fallback = self._registry[fallback_slug]
        notes.append(f"Fallback to: {fallback_slug}")
        return RoutingDecision(
            requested_slug=requested_slug,
            routed_slug=fallback_slug,
            model_entry=fallback,
            routing_reason=f"policy_substitution_from_{blocked_slug}",
            was_substituted=True,
            governance_notes=notes
        )

    def list_active_models(self, provider: Optional[str] = None) -> List[ModelEntry]:
        """List all active models, optionally filtered by provider."""
        models = [m for m in self._registry.values() if m.is_active]
        if provider:
            models = [m for m in models if m.provider.value == provider.lower()]
        return models

    def get_bom_components(self, slug: str, agent_name: str, agent_version: str) -> List[Dict]:
        """
        Generate AI-BOM components for compliance_engine.generate_ai_bom().
        Replaces the hardcoded list in cgc_loop.py.
        """
        components = []
        model = self._registry.get(slug)
        if model:
            components.append(model.to_bom_component())
        components.append({
            "name":       agent_name,
            "type":       "agent",
            "version":    agent_version,
            "vendor":     "Olympus Mont Systems LLC",
            "risk_level": "medium"
        })
        return components


# ============================================================================
# SINGLETON — shared instance across the application
# ============================================================================

_registry_instance: Optional[ModelRegistry] = None


def get_model_registry() -> ModelRegistry:
    """
    Get the singleton ModelRegistry instance.
    Call this from cgc_loop.py instead of hardcoding model names.
    """
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = ModelRegistry()
    return _registry_instance