"""
CGC Core — Proof-of-Decision (PoD) Interceptor
Patent 1: Pre-delivery cryptographic non-repudiation of AI decisions

Captures the triplet {input_hash, model_identifier, output_hash} at the
transport layer BEFORE the response is delivered to the client application.

This is the core innovation: the intercept happens pre-delivery, generating
a cryptographic proof that cannot be created retroactively.

OlympusMont Systems LLC © 2025
"""

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

try:
    from app.Core.logging import get_logger
    logger = get_logger("cgc.pod")
except ImportError:
    logger = logging.getLogger("cgc.pod")
    logging.basicConfig(level=logging.INFO)

# PoD Repository: PostgreSQL persistence
# Imported lazily to allow in-memory fallback when DB is unavailable
try:
    from app.modules.pod.pod_repository import get_pod_repository
    DB_AVAILABLE = True
except ImportError:
    try:
        from pod_repository import get_pod_repository
        DB_AVAILABLE = True
    except ImportError:
        get_pod_repository = None
        DB_AVAILABLE = False
        logger.warning("[PoD] pod_repository not found — in-memory mode only")


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class InterceptTriplet:
    """
    The core patent artifact: {input_hash, model_identifier, output_hash}
    
    Per patent claim: captured at transport layer before client delivery.
    Content (input/output) is NEVER stored — only cryptographic hashes.
    This is the zero-knowledge design: CGC Core proves WHAT happened
    without storing WHAT was said.
    """
    intercept_id:        str
    decision_id:         str
    tenant_id:           str

    # The triplet — all hashed, never plaintext
    input_payload_hash:  str   # SHA256 of raw input payload
    model_identifier:    str   # canonical: "provider/model_name/version"
    output_payload_hash: str   # SHA256 of raw output payload

    # Composite proof
    triplet_hash:        str   # SHA256(input_hash || model_identifier || output_hash)
    triplet_signature:   str   # RSA-PSS-SHA256 signature of triplet_hash
    signing_key_id:      str

    # Timing — proves pre-delivery capture
    intercepted_at:      str   # ISO8601 UTC — when PoD intercepted
    delivered_at:        Optional[str]  # ISO8601 UTC — when client received response
    latency_ms:          Optional[float]

    # External timestamp (RFC 3161)
    timestamp_token:     Optional[str]   # RFC 3161 token from TSA
    timestamp_authority: Optional[str]   # TSA endpoint used

    # Privacy metadata
    pii_detected:        bool
    pii_fields_count:    int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PoDBlock:
    """
    A block in the PoD immutable ledger chain.
    Each block seals one InterceptTriplet into the chain.
    """
    block_uuid:           str
    tenant_id:            str
    intercept_id:         str
    decision_id:          str

    block_number:         int
    previous_block_hash:  str
    block_hash:           str         # SHA256(all block content + previous_hash)

    triplet_hash:         str
    governance_outcome:   str         # APPROVE / REJECT / REQUIRE_HUMAN
    compliance_score:     Optional[float]

    sealed_at:            str
    sealed_by:            str         # service identity

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# RFC 3161 TIMESTAMP CLIENT
# ============================================================================

class RFC3161TimestampClient:
    """
    Obtains trusted timestamps from an external TSA (Timestamp Authority).
    Per patent claim: external timestamp source for non-repudiation.
    
    Default: DigiCert TSA (free tier, RFC 3161 compliant)
    """

    DEFAULT_TSA = "http://timestamp.digicert.com"

    def __init__(self, tsa_url: Optional[str] = None):
        self.tsa_url = tsa_url or self.DEFAULT_TSA

    def get_timestamp(self, data_hash: str) -> Tuple[Optional[str], str]:
        """
        Request a trusted timestamp for a data hash.
        
        Returns:
            (timestamp_token_base64, authority_url)
            token is None if TSA is unreachable (falls back gracefully)
        """
        try:
            import base64
            import struct
            import urllib.request

            # Build minimal TSA request (RFC 3161)
            hash_bytes = bytes.fromhex(data_hash)

            # ASN.1 DER for TimeStampReq — minimal structure
            # hashAlgorithm: SHA-256 OID = 2.16.840.1.101.3.4.2.1
            sha256_oid = bytes([
                0x30, 0x31,                   # SEQUENCE
                0x30, 0x0d,                   # SEQUENCE
                0x06, 0x09,                   # OID
                0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # SHA256
                0x05, 0x00,                   # NULL
                0x04, 0x20,                   # OCTET STRING (32 bytes)
            ]) + hash_bytes

            # TSA request wrapper
            tsa_req = bytes([0x30, len(sha256_oid) + 5]) + bytes([
                0x02, 0x01, 0x01,  # version INTEGER 1
            ]) + bytes([0x30, len(sha256_oid)]) + sha256_oid

            req = urllib.request.Request(
                self.tsa_url,
                data=tsa_req,
                headers={"Content-Type": "application/timestamp-query"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                token_bytes = resp.read()
                token_b64 = base64.b64encode(token_bytes).decode()
                logger.info(f"[PoD] RFC3161 timestamp obtained from {self.tsa_url}")
                return token_b64, self.tsa_url

        except Exception as e:
            logger.warning(f"[PoD] TSA unreachable ({self.tsa_url}): {e} — using local timestamp fallback")
            return None, self.tsa_url


# ============================================================================
# IN-MEMORY CHAIN STATE (for when DB is not available)
# ============================================================================

class InMemoryChain:
    """Fallback chain state when PostgreSQL is not available."""

    def __init__(self):
        self._blocks: list = []
        self._last_hash = "0" * 64  # genesis

    def get_last_hash(self) -> str:
        return self._last_hash

    def get_next_number(self) -> int:
        return len(self._blocks)

    def append(self, block: PoDBlock) -> None:
        self._blocks.append(block)
        self._last_hash = block.block_hash

    def get_chain(self) -> list:
        return list(self._blocks)


# ============================================================================
# POD INTERCEPTOR — CORE CLASS
# ============================================================================

class PoDInterceptor:
    """
    Proof-of-Decision Interceptor.

    Patent 1 implementation: intercepts {input, model_id, output} at the
    transport layer BEFORE delivery to the client application, generating
    a cryptographic triplet hash sealed into an immutable ledger.

    Usage in the governance cycle:
        1. BEFORE calling the AI model:
           pod.begin_intercept(decision_id, tenant_id, model_id, input_payload)

        2. AFTER receiving model response, BEFORE returning to client:
           triplet = pod.seal_intercept(intercept_id, output_payload, outcome)

    The time between begin_intercept and seal_intercept is the latency_ms,
    proving the intercept happened at inference time.
    """

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        private_key_pem: Optional[bytes] = None,
        signing_key_id: str = "local-rsa-key-001",
        tsa_url: Optional[str] = None,
        detect_pii: bool = True,
        db_persist: bool = True
    ):
        self.signing_key_id = signing_key_id
        self.tsa_client = RFC3161TimestampClient(tsa_url)
        self.detect_pii = detect_pii
        self._chain = InMemoryChain()
        self._pending_intercepts: Dict[str, Dict] = {}  # intercept_id -> partial data

        # PostgreSQL persistence layer (graceful fallback to in-memory)
        self._repo = None
        if db_persist and DB_AVAILABLE and get_pod_repository:
            try:
                self._repo = get_pod_repository()
                if self._repo:
                    logger.info("[PoD] PostgreSQL persistence ENABLED")
                else:
                    logger.warning("[PoD] Repository returned None — in-memory fallback")
            except Exception as e:
                logger.warning(f"[PoD] DB init failed ({e}) — in-memory fallback")

        # Load or generate RSA signing key
        if private_key_pem:
            self._private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
        else:
            from cryptography.hazmat.primitives.asymmetric import rsa as rsa_gen
            self._private_key = rsa_gen.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            logger.warning("[PoD] Using ephemeral RSA key — load persistent key in production")

        logger.info(f"[PoD] Interceptor initialized | Key: {signing_key_id} | TSA: {self.tsa_client.tsa_url}")

    # -------------------------------------------------------------------------
    # PHASE 1: Begin intercept (pre-model call)
    # -------------------------------------------------------------------------

    def begin_intercept(
        self,
        decision_id: str,
        tenant_id: str,
        model_identifier: str,
        input_payload: Any
    ) -> str:
        """
        Called BEFORE the AI model receives the request.
        Records the input hash and timestamps the start of the intercept.

        Args:
            decision_id:       governance decision ID
            tenant_id:         tenant UUID
            model_identifier:  canonical model ID, e.g. "openai/gpt-4o/2025-12"
            input_payload:     raw input (dict, str, etc.) — hashed, never stored

        Returns:
            intercept_id: UUID to pass to seal_intercept()
        """
        intercept_id = str(uuid.uuid4())
        intercepted_at = datetime.now(timezone.utc)

        # Hash the input — zero-knowledge design
        input_hash = self._hash_payload(input_payload)

        self._pending_intercepts[intercept_id] = {
            "decision_id":        decision_id,
            "tenant_id":          tenant_id,
            "model_identifier":   model_identifier,
            "input_payload_hash": input_hash,
            "intercepted_at":     intercepted_at,
        }

        logger.info(
            f"[PoD] Intercept BEGUN | ID: {intercept_id[:8]}... | "
            f"Model: {model_identifier} | Input hash: {input_hash[:16]}..."
        )
        return intercept_id

    # -------------------------------------------------------------------------
    # PHASE 2: Seal intercept (post-model, pre-client-delivery)
    # -------------------------------------------------------------------------

    def seal_intercept(
        self,
        intercept_id: str,
        output_payload: Any,
        governance_outcome: str,
        compliance_score: Optional[float] = None
    ) -> Tuple[InterceptTriplet, PoDBlock]:
        """
        Called AFTER receiving the AI model response, BEFORE returning to client.
        
        This is the critical moment: the proof is generated while the response
        is still in the governance layer, before it reaches the caller.

        Args:
            intercept_id:        from begin_intercept()
            output_payload:      raw model response — hashed, never stored
            governance_outcome:  APPROVE / REJECT / REQUIRE_HUMAN
            compliance_score:    optional overall compliance score

        Returns:
            (InterceptTriplet, PoDBlock) — the sealed proof artifacts
        """
        if intercept_id not in self._pending_intercepts:
            raise ValueError(f"[PoD] Unknown intercept_id: {intercept_id}")

        pending = self._pending_intercepts.pop(intercept_id)
        delivered_at = datetime.now(timezone.utc)

        # Hash the output — zero-knowledge design
        output_hash = self._hash_payload(output_payload)

        # Build the canonical triplet hash
        # SHA256(input_hash || model_identifier || output_hash)
        triplet_hash = self._build_triplet_hash(
            input_hash=pending["input_payload_hash"],
            model_identifier=pending["model_identifier"],
            output_hash=output_hash
        )

        # Sign the triplet hash with RSA-PSS-SHA256
        signature = self._sign(triplet_hash)

        # Get external RFC 3161 timestamp
        timestamp_token, timestamp_authority = self.tsa_client.get_timestamp(triplet_hash)

        # PII detection (metadata only — no content scanning)
        pii_detected, pii_count = self._detect_pii_metadata(output_payload)

        # Calculate latency (proves pre-delivery timing)
        latency_ms = (
            delivered_at - pending["intercepted_at"]
        ).total_seconds() * 1000

        triplet = InterceptTriplet(
            intercept_id=intercept_id,
            decision_id=pending["decision_id"],
            tenant_id=pending["tenant_id"],
            input_payload_hash=pending["input_payload_hash"],
            model_identifier=pending["model_identifier"],
            output_payload_hash=output_hash,
            triplet_hash=triplet_hash,
            triplet_signature=signature,
            signing_key_id=self.signing_key_id,
            intercepted_at=pending["intercepted_at"].isoformat(),
            delivered_at=delivered_at.isoformat(),
            latency_ms=round(latency_ms, 3),
            timestamp_token=timestamp_token,
            timestamp_authority=timestamp_authority,
            pii_detected=pii_detected,
            pii_fields_count=pii_count
        )

        # Seal into the immutable chain (in-memory always)
        block = self._seal_to_chain(triplet, governance_outcome, compliance_score)

        # Persist to PostgreSQL (if repository is available)
        db_meta: Optional[Dict] = None
        if self._repo:
            try:
                db_meta = self._repo.persist(
                    triplet=triplet,
                    block=block,
                    decision_id=pending["decision_id"]
                )
                # Sync authoritative block_hash from DB back to in-memory block
                if db_meta and db_meta.get("block_hash"):
                    block.block_hash    = db_meta["block_hash"]
                    block.block_number  = db_meta["block_number"]
            except Exception as e:
                logger.error(f"[PoD] DB persist failed: {e} — proof sealed in-memory only")

        logger.info(
            f"[PoD] Intercept SEALED | ID: {intercept_id[:8]}... | "
            f"Block: {block.block_number} | Hash: {block.block_hash[:16]}... | "
            f"Outcome: {governance_outcome} | Latency: {latency_ms:.1f}ms"
        )

        return triplet, block

    # -------------------------------------------------------------------------
    # CHAIN VERIFICATION
    # -------------------------------------------------------------------------

    def verify_chain_integrity(self, tenant_id: str) -> Dict[str, Any]:
        """
        Verify the integrity of the entire PoD chain for a tenant.

        Uses PostgreSQL repository when available (authoritative source).
        Falls back to in-memory chain for development/testing.

        Returns verification report suitable for auditor submission.
        """
        # Use DB repo if available — it is the authoritative source
        if self._repo:
            try:
                return self._repo.verify_chain(tenant_id)
            except Exception as e:
                logger.error(f"[PoD] DB verification failed: {e} — using in-memory")

        blocks = self._chain.get_chain()
        tenant_blocks = [b for b in blocks if b.tenant_id == tenant_id]

        broken_at = None
        prev_hash = self.GENESIS_HASH

        for block in tenant_blocks:
            # Recompute expected hash
            expected_hash = self._compute_block_hash(block, prev_hash)
            if block.block_hash != expected_hash:
                broken_at = block.block_number
                break
            if block.previous_block_hash != prev_hash:
                broken_at = block.block_number
                break
            prev_hash = block.block_hash

        return {
            "tenant_id":        tenant_id,
            "blocks_verified":  len(tenant_blocks),
            "integrity_passed": broken_at is None,
            "broken_at_block":  broken_at,
            "verified_at":      datetime.now(timezone.utc).isoformat(),
            "chain_height":     len(tenant_blocks)
        }

    def verify_single_decision(
        self,
        decision_id: str,
        input_payload: Any,
        output_payload: Any,
        model_identifier: str,
        claimed_triplet_hash: str
    ) -> Dict[str, Any]:
        """
        Forensic verification: re-derive the triplet hash from raw inputs
        and compare against the stored hash in the ledger.
        
        This is the "30-second proof" described in the patent pitch:
        given original data, prove what the AI decided.
        """
        recomputed = self._build_triplet_hash(
            input_hash=self._hash_payload(input_payload),
            model_identifier=model_identifier,
            output_hash=self._hash_payload(output_payload)
        )

        match = hmac.compare_digest(recomputed, claimed_triplet_hash)

        return {
            "decision_id":          decision_id,
            "verification_passed":  match,
            "recomputed_hash":      recomputed,
            "claimed_hash":         claimed_triplet_hash,
            "hash_match":           match,
            "verified_at":          datetime.now(timezone.utc).isoformat()
        }

    # -------------------------------------------------------------------------
    # INTERNAL HELPERS
    # -------------------------------------------------------------------------

    def _hash_payload(self, payload: Any) -> str:
        """SHA256 of any payload. Normalizes to JSON for dict/list."""
        if isinstance(payload, (dict, list)):
            raw = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        elif isinstance(payload, bytes):
            raw = payload.decode("utf-8", errors="replace")
        else:
            raw = str(payload)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _build_triplet_hash(
        self,
        input_hash: str,
        model_identifier: str,
        output_hash: str
    ) -> str:
        """
        SHA256(input_hash || "||" || model_identifier || "||" || output_hash)
        The || separator prevents hash collision across fields.
        """
        canonical = f"{input_hash}||{model_identifier}||{output_hash}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _sign(self, data_hex: str) -> str:
        """RSA-PSS-SHA256 signature of hex data. Returns hex signature."""
        data_bytes = bytes.fromhex(data_hex)
        signature = self._private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def _seal_to_chain(
        self,
        triplet: InterceptTriplet,
        governance_outcome: str,
        compliance_score: Optional[float]
    ) -> PoDBlock:
        """Append a new block to the immutable chain."""
        prev_hash = self._chain.get_last_hash()
        block_number = self._chain.get_next_number()

        block = PoDBlock(
            block_uuid=str(uuid.uuid4()),
            tenant_id=triplet.tenant_id,
            intercept_id=triplet.intercept_id,
            decision_id=triplet.decision_id,
            block_number=block_number,
            previous_block_hash=prev_hash,
            block_hash="",               # computed below
            triplet_hash=triplet.triplet_hash,
            governance_outcome=governance_outcome,
            compliance_score=compliance_score,
            sealed_at=datetime.now(timezone.utc).isoformat(),
            sealed_by="cgc-pod-interceptor-v2"
        )
        block.block_hash = self._compute_block_hash(block, prev_hash)
        self._chain.append(block)
        return block

    def _compute_block_hash(self, block: PoDBlock, previous_hash: str) -> str:
        """SHA256 of deterministic block content + previous hash."""
        content = json.dumps({
            "block_uuid":          block.block_uuid,
            "tenant_id":           block.tenant_id,
            "intercept_id":        block.intercept_id,
            "decision_id":         block.decision_id,
            "block_number":        block.block_number,
            "previous_block_hash": previous_hash,
            "triplet_hash":        block.triplet_hash,
            "governance_outcome":  block.governance_outcome,
            "sealed_at":           block.sealed_at,
            "sealed_by":           block.sealed_by,
        }, sort_keys=True)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _detect_pii_metadata(self, payload: Any) -> Tuple[bool, int]:
        """
        Lightweight PII detection on payload structure (not content scanning).
        Checks for common PII field names in dict keys only.
        """
        PII_FIELD_PATTERNS = {
            "ssn", "social_security", "dob", "date_of_birth",
            "credit_card", "card_number", "cvv", "account_number",
            "routing_number", "passport", "drivers_license",
            "email", "phone", "address", "zip_code", "postal_code"
        }
        if not isinstance(payload, dict):
            return False, 0

        keys_lower = {k.lower().replace("-", "_") for k in self._flatten_keys(payload)}
        pii_fields = keys_lower & PII_FIELD_PATTERNS
        return bool(pii_fields), len(pii_fields)

    def _flatten_keys(self, d: dict, prefix: str = "") -> list:
        """Recursively extract all dict keys."""
        keys = []
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            keys.append(full_key)
            if isinstance(v, dict):
                keys.extend(self._flatten_keys(v, full_key))
        return keys