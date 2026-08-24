"""
SCM™ - Security & Cryptographic Module

Powere by Olympus Mont Systems LLC

Integrated Features:

- Multi-tenant with strict isolation
- KMS Integration (AWS KMS, Local KMS; extensible to GCP/Azure/HSM)
- Real cryptography (Fernet AES-256 + RSA-PSS-SHA256)
- Security Policy Matrix per governance area
- Sensitivity-based encryption (double encryption for HIGH sensitivity data)
- Persistent Merkle Chain with SQLite
- Immutable Audit Trail for legal compliance
- Automatic Key Rotation
- Compliance-standard tracking (cgc_jla.scm_compliance_standards) -- empty by
  default; this module has never received an independent certification
  against any framework, so none are asserted here. Populate that table only
  once a real audit backs a specific entry.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from enum import Enum
from abc import ABC, abstractmethod

import yaml
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Try to import boto3 for AWS KMS (optional)
try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
    AWS_KMS_AVAILABLE = True
except ImportError:
    AWS_KMS_AVAILABLE = False

load_dotenv()

logger = logging.getLogger("cgc.scm.integrated")
logger.setLevel(logging.INFO)

# Configure handler if none exists
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# ============================================================================
# ENTERPRISE CONFIGURATION
# ============================================================================

SCM_CONFIG: Dict[str, Any] = {
    "database": os.getenv("SCM_DB_PATH", "data/scm_integrated.db"),
    "max_chain_nodes": int(os.getenv("SCM_MAX_CHAIN_NODES", "100000")),
    "key_rotation_days": int(os.getenv("SCM_KEY_ROTATION_DAYS", "90")),
    "tenant_isolation": os.getenv("SCM_TENANT_ISOLATION", "strict").lower()
    in ["true", "1", "yes"],
    "audit_retention_days": int(os.getenv("SCM_AUDIT_RETENTION_DAYS", "365")),
    "log_level": os.getenv("SCM_LOG_LEVEL", "INFO"),
}

# ============================================================================
# SECURITY POLICY MATRIX
# ============================================================================

# ============================================================================
# SENSITIVITY-BASED ENCRYPTION CONFIG
# ============================================================================


# ============================================================================
# KMS PROVIDER ABSTRACTION
# ============================================================================


class KMSProvider(ABC):
    """Abstract interface for KMS providers."""

    @abstractmethod
    def generate_data_key(self, key_id: str, tenant_id: str) -> Tuple[bytes, bytes]:
        """Generate data key and return plaintext + encrypted key material."""
        raise NotImplementedError

    @abstractmethod
    def decrypt_data_key(self, encrypted_key: bytes, context: Dict[str, str]) -> bytes:
        """Decrypt key material."""
        raise NotImplementedError

    @abstractmethod
    def sign_data(self, data: bytes, key_id: str) -> bytes:
        """Sign data using KMS key (RSA-PSS)."""
        raise NotImplementedError

    @abstractmethod
    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify signature using KMS public key."""
        raise NotImplementedError

    @abstractmethod
    def rotate_key(self, key_id: str) -> str:
        """Schedule key rotation and return rotation date."""
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Return provider health status."""
        raise NotImplementedError


class AWSKMSProvider(KMSProvider):
    """AWS KMS integration."""

    def __init__(self) -> None:
        if not AWS_KMS_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Install with: pip install boto3")

        try:
            # use_fips_endpoint routes every call through AWS's dedicated
            # kms-fips.<region>.amazonaws.com endpoint instead of the
            # standard one. AWS KMS's standard endpoints are ALSO backed by
            # FIPS 140-2 Level 2 validated HSMs, but the FIPS endpoint is
            # what makes that boundary explicit/contractual rather than
            # incidental -- the distinction that matters when a government
            # reviewer asks "how do you know," not just "is it true."
            # CGC_KMS_USE_FIPS_ENDPOINT defaults on; set to "false" only if
            # a target region genuinely lacks a FIPS endpoint.
            use_fips = os.getenv("CGC_KMS_USE_FIPS_ENDPOINT", "true").lower() != "false"
            self.kms = boto3.client(
                "kms",
                region_name=os.getenv("AWS_REGION", "us-east-1"),
                config=BotoConfig(use_fips_endpoint=use_fips),
            )
            self.master_key_id = os.getenv("AWS_KMS_MASTER_KEY_ID")
            if not self.master_key_id:
                raise ValueError(
                    "AWS_KMS_MASTER_KEY_ID environment variable is not configured"
                )
            logger.info(
                f"[KMS] AWS KMS provider initialized - Region: {os.getenv('AWS_REGION')} - FIPS endpoint: {use_fips}"
            )
        except Exception as e:
            logger.error(f"[KMS] Error initializing AWS KMS: {e}")
            raise

    def generate_data_key(self, key_id: str, tenant_id: str) -> Tuple[bytes, bytes]:
        """
        Generate tenant-specific data key via AWS KMS.

        `key_id` (e.g. "primary" from register_tenant()) is another of
        LocalKMSProvider's internal naming conventions, not a real AWS KMS
        key -- same issue and same fix as sign_data()/verify_signature()
        above: always derive from the one shared master key, per the
        one-shared-signing-key decision extended consistently to
        encryption too.
        """
        try:
            response = self.kms.generate_data_key(
                KeyId=self.master_key_id,
                KeySpec="AES_256",
                EncryptionContext={"tenant_id": tenant_id, "purpose": "data_encryption"},
            )
            plaintext = response["Plaintext"]
            encrypted = response["CiphertextBlob"]
            logger.info(f"[KMS] Data key generated for tenant {tenant_id}")
            return plaintext, encrypted
        except Exception as e:
            logger.error(f"[KMS] Error generating AWS data key: {e}")
            raise

    def decrypt_data_key(self, encrypted_key: bytes, context: Dict[str, str]) -> bytes:
        """Decrypt data key using AWS KMS."""
        try:
            response = self.kms.decrypt(
                CiphertextBlob=encrypted_key,
                EncryptionContext=context,
            )
            logger.info("[KMS] Data key decrypted successfully")
            return response["Plaintext"]
        except Exception as e:
            logger.error(f"[KMS] Error decrypting AWS key: {e}")
            raise

    def sign_data(self, data: bytes, key_id: str) -> bytes:
        """
        Sign using AWS KMS RSA key.

        `key_id` (e.g. "tenant_abc123") is LocalKMSProvider's own internal
        naming convention for its per-tenant key store -- not a real AWS
        KMS key identifier, and AWS would reject it outright as an
        invalid KeyId. 2026-08 government-readiness decision: one shared
        KMS signing key for every tenant (not one real KMS key per tenant
        -- simpler, and CGC Core's differentiator is the non-repudiable
        signature on the decision itself, not per-customer key isolation),
        so every call resolves to self.master_key_id regardless of what
        the caller passed.
        """
        try:
            response = self.kms.sign(
                KeyId=self.master_key_id,
                Message=data,
                SigningAlgorithm="RSASSA_PSS_SHA_256",
                MessageFormat="RAW",
            )
            logger.info("[KMS] AWS KMS signature generated")
            return response["Signature"]
        except Exception as e:
            logger.error(f"[KMS] Error signing with AWS: {e}")
            raise

    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify signature in AWS KMS. See sign_data() -- key_id is ignored, same reason."""
        try:
            response = self.kms.verify(
                KeyId=self.master_key_id,
                Message=data,
                Signature=signature,
                SigningAlgorithm="RSASSA_PSS_SHA_256",
                MessageFormat="RAW",
            )
            is_valid = bool(response.get("SignatureValid", False))
            logger.info(f"[KMS] AWS signature verification: {'VALID' if is_valid else 'INVALID'}")
            return is_valid
        except Exception as e:
            logger.error(f"[KMS] Error verifying signature in AWS: {e}")
            return False

    def rotate_key(self, key_id: str) -> str:
        """Schedule AWS key rotation (using key deletion as placeholder)."""
        try:
            response = self.kms.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=7,
            )
            deletion_date = response["DeletionDate"].isoformat()
            logger.info(f"[KMS] AWS key rotation scheduled: {deletion_date}")
            return deletion_date
        except Exception as e:
            logger.error(f"[KMS] Error rotating AWS key: {e}")
            raise

    def health_check(self) -> Dict[str, Any]:
        """Check AWS KMS health."""
        try:
            response = self.kms.describe_key(KeyId=self.master_key_id)
            meta = response["KeyMetadata"]
            return {
                "provider": "AWS_KMS",
                "status": "connected",
                "key_id": meta["KeyId"],
                "key_state": meta["KeyState"],
                "creation_date": meta["CreationDate"].isoformat(),
            }
        except Exception as e:
            return {
                "provider": "AWS_KMS",
                "status": "disconnected",
                "error": str(e),
            }


class LocalKMSProvider(KMSProvider):
    """
    Local KMS Provider (development/testing only).

    In production use AWS/GCP/Azure/HSM instead.
    """

    def __init__(self) -> None:
        self.master_key_id = "local_master_v1"

        stored_key = os.getenv("CGC_SCM_ENC_MASTER_V1")
        if stored_key:
            try:
                self.master_key = base64.urlsafe_b64decode(stored_key.encode())
                self.fernet = Fernet(self.master_key)
            except Exception:
                self.master_key = Fernet.generate_key()
                self.fernet = Fernet(self.master_key)
                logger.warning(
                    "[KMS] Invalid master key in CGC_SCM_ENC_MASTER_V1, generated new one. "
                    "Update .env for persistence."
                )
        else:
            self.master_key = Fernet.generate_key()
            self.fernet = Fernet(self.master_key)
            logger.warning(
                "[KMS] LOCAL KMS INITIALIZED - DEVELOPMENT ONLY\n"
                f"Set CGC_SCM_ENC_MASTER_V1 in .env:\n"
                f"{base64.urlsafe_b64encode(self.master_key).decode()}\n"
                "For production, use AWS KMS, GCP KMS or Azure Key Vault."
            )

        self._private_key = None
        self._public_key = None
        self._load_rsa_keys()

    def _load_rsa_keys(self) -> None:
        """Load RSA keys from .env or generate new ones."""
        rsa_priv_b64 = os.getenv("CGC_SCM_RSA_PRIV_V1")
        rsa_pub_b64 = os.getenv("CGC_SCM_RSA_PUB_V1")

        if rsa_priv_b64 and rsa_pub_b64:
            try:
                priv_pem = base64.urlsafe_b64decode(rsa_priv_b64.encode())
                pub_pem = base64.urlsafe_b64decode(rsa_pub_b64.encode())
                self._private_key = serialization.load_pem_private_key(
                    priv_pem, password=None, backend=default_backend()
                )
                self._public_key = serialization.load_pem_public_key(
                    pub_pem, backend=default_backend()
                )
                logger.info("[KMS] RSA keys loaded from .env")
                return
            except Exception as e:
                logger.warning(f"[KMS] Error loading RSA keys from .env: {e}, generating new keys")

        self._generate_rsa_keys()

    def _generate_rsa_keys(self) -> None:
        """Generate new RSA key pair for local use."""
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._private_key = key
        self._public_key = key.public_key()

        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        logger.warning(
            "[KMS] Local RSA keys generated. Configure in .env:\n"
            f"CGC_SCM_RSA_PRIV_V1={base64.urlsafe_b64encode(priv_pem).decode()}\n"
            f"CGC_SCM_RSA_PUB_V1={base64.urlsafe_b64encode(pub_pem).decode()}\n"
        )

    def generate_data_key(self, key_id: str, tenant_id: str) -> Tuple[bytes, bytes]:
        """Generate local data key."""
        plaintext = Fernet.generate_key()
        encrypted = self.fernet.encrypt(plaintext)
        logger.info(f"[KMS] Local data key generated for tenant {tenant_id}")
        return plaintext, encrypted

    def decrypt_data_key(self, encrypted_key: bytes, context: Dict[str, str]) -> bytes:
        """Decrypt local key."""
        return self.fernet.decrypt(encrypted_key)

    def sign_data(self, data: bytes, key_id: str) -> bytes:
        """Sign using local RSA private key."""
        return self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify signature using local RSA public key."""
        try:
            self._public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def rotate_key(self, key_id: str) -> str:
        """Schedule local key rotation (development only)."""
        logger.warning("[KMS] Local key rotation is for development only")
        return (datetime.utcnow() + timedelta(days=90)).isoformat()

    def health_check(self) -> Dict[str, Any]:
        """Return local KMS health."""
        return {
            "provider": "LOCAL_KMS",
            "status": "connected",
            "warning": "DEVELOPMENT_ONLY",
        }


# ============================================================================
# PERSISTENT MERKLE CHAIN & AUDIT DATABASE
# ============================================================================


class IntegratedAuditDatabase:
    """Persistent database with Merkle Chain and immutable Audit Trail."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        db_dir = os.path.dirname(self.db_path) or "."
        os.makedirs(db_dir, exist_ok=True)
        self._init_database()

    def _init_database(self) -> None:
        """Initialize full SQLite schema."""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()

        # Merkle Chain (multi-tenant)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS merkle_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                node_id TEXT UNIQUE NOT NULL,
                node_hash TEXT NOT NULL,
                prev_hash TEXT,
                data_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Tenant Keys Registry
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_keys (
                tenant_id TEXT PRIMARY KEY,
                enc_key_id TEXT NOT NULL,
                sig_key_id TEXT NOT NULL,
                governance_area TEXT DEFAULT 'DEFAULT',
                last_rotated DATETIME DEFAULT CURRENT_TIMESTAMP,
                rotation_due DATETIME NOT NULL,
                version INTEGER DEFAULT 1,
                kms_provider TEXT DEFAULT 'LOCAL_KMS'
            )
            """
        )

        # Signature Ledger (immutable)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS signature_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                signature_id TEXT UNIQUE NOT NULL,
                data_hash TEXT NOT NULL,
                signature_value TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                kms_provider TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                context_json TEXT,
                verified_at TEXT,
                verification_result BOOLEAN,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Encryption Audit
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS encryption_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                operation_id TEXT UNIQUE NOT NULL,
                data_hash TEXT NOT NULL,
                encrypted_hash TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                sensitivity_level TEXT,
                double_encrypted BOOLEAN DEFAULT 0,
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Key Rotation Audit
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS key_rotation_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                rotation_timestamp TEXT NOT NULL,
                reason TEXT,
                old_key_hash TEXT,
                new_key_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Compliance Verification
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS compliance_verification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                signature_id TEXT NOT NULL,
                verification_timestamp TEXT NOT NULL,
                verified_by TEXT,
                compliance_status TEXT,
                standards TEXT,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # SCM Metrics
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scm_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT,
                total_encryptions INTEGER DEFAULT 0,
                total_signatures INTEGER DEFAULT 0,
                total_verifications INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        self.conn.commit()
        logger.info(f"[AUDIT] Database initialized: {self.db_path}")

    def add_merkle_node(self, tenant_id: str, node_data: Dict[str, Any]) -> str:
        """Add node to tenant-specific Merkle chain."""
        cursor = self.conn.cursor()
        node_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO merkle_chain
            (tenant_id, node_id, node_hash, prev_hash, data_hash, signature, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                node_id,
                node_data["node_hash"],
                node_data.get("prev_hash"),
                node_data["data_hash"],
                node_data["signature"],
                node_data["timestamp"],
                json.dumps(node_data.get("metadata", {})),
            ),
        )
        self.conn.commit()
        return node_id

    def get_tenant_chain(self, tenant_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get tenant-specific chain for verification."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM merkle_chain
            WHERE tenant_id = ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (tenant_id, limit),
        )
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def verify_tenant_chain(self, tenant_id: str) -> bool:
        """Verify integrity of tenant chain."""
        chain = self.get_tenant_chain(tenant_id)
        if not chain:
            return True
        for i, node in enumerate(chain):
            if i > 0 and node.get("prev_hash") != chain[i - 1].get("node_hash"):
                logger.error(
                    f"[AUDIT] Chain broken at node {node.get('node_id')} for tenant {tenant_id}"
                )
                return False
        return True

    def record_signature(
        self,
        tenant_id: str,
        data_hash: str,
        signature: str,
        algo: str,
        key_id: str,
        kms_provider: str,
        context: Dict[str, Any],
    ) -> str:
        """Record immutable cryptographic signature."""
        sig_id = str(uuid.uuid4())
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO signature_ledger
            (tenant_id, signature_id, data_hash, signature_value, signature_algorithm,
             key_id, kms_provider, timestamp, context_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                sig_id,
                data_hash,
                signature,
                algo,
                key_id,
                kms_provider,
                datetime.utcnow().isoformat(),
                json.dumps(context),
            ),
        )
        self.conn.commit()
        logger.info(f"[AUDIT] Signature recorded: {sig_id} for tenant {tenant_id}")
        return sig_id

    def record_encryption(
        self,
        tenant_id: str,
        data_hash: str,
        encrypted_hash: str,
        algo: str,
        key_id: str,
        sensitivity: str,
        double_encrypted: bool = False,
    ) -> str:
        """Record encryption operation."""
        op_id = str(uuid.uuid4())
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO encryption_audit
            (tenant_id, operation_id, data_hash, encrypted_hash, algorithm, key_id,
             sensitivity_level, double_encrypted, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                op_id,
                data_hash,
                encrypted_hash,
                algo,
                key_id,
                sensitivity,
                int(double_encrypted),
                datetime.utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        return op_id

    def record_verification(
        self,
        tenant_id: str,
        signature_id: str,
        verified_by: str,
        compliance_status: str,
        standards: List[str],
    ) -> bool:
        """Record compliance verification for legal audit."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO compliance_verification
            (tenant_id, signature_id, verification_timestamp, verified_by,
             compliance_status, standards)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                signature_id,
                datetime.utcnow().isoformat(),
                verified_by,
                compliance_status,
                json.dumps(standards),
            ),
        )
        self.conn.commit()
        logger.info(f"[AUDIT] Verification recorded for {signature_id}")
        return True

    def get_audit_trail(
        self, tenant_id: str, signature_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get immutable audit trail."""
        cursor = self.conn.cursor()
        if signature_id:
            cursor.execute(
                """
                SELECT * FROM signature_ledger
                WHERE tenant_id = ? AND signature_id = ?
                LIMIT 1
                """,
                (tenant_id, signature_id),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM signature_ledger
                WHERE tenant_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            )
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_compliance_report(self, tenant_id: str, signature_id: str) -> Dict[str, Any]:
        """Generate legal compliance report for a given signature."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM signature_ledger WHERE tenant_id = ? AND signature_id = ?
            """,
            (tenant_id, signature_id),
        )
        sig_row = cursor.fetchone()
        if not sig_row:
            return {"error": "Signature not found"}

        sig_columns = [col[0] for col in cursor.description]
        sig_dict = dict(zip(sig_columns, sig_row))

        cursor.execute(
            """
            SELECT * FROM compliance_verification
            WHERE tenant_id = ? AND signature_id = ?
            ORDER BY created_at DESC
            """,
            (tenant_id, signature_id),
        )
        ver_columns = [col[0] for col in cursor.description]
        verifications = [dict(zip(ver_columns, row)) for row in cursor.fetchall()]

        return {
            "signature_id": signature_id,
            "tenant_id": tenant_id,
            "data_hash": sig_dict["data_hash"],
            "signature_algorithm": sig_dict["signature_algorithm"],
            "kms_provider": sig_dict["kms_provider"],
            "timestamp": sig_dict["timestamp"],
            "verifications": verifications,
            "compliance_standards": self._get_compliance_standards(),
        }


# ============================================================================
# SCM INTEGRATED
# ============================================================================


class SCM:
    """
    SCM - Security & Cryptographic Module

    Integrated module with key functionalities:

    - Multi-tenant with strict isolation
    - KMS Integration (AWS, Local)
    - Real cryptography (Fernet + RSA-PSS)
    - Security Policy Matrix
    - Sensitivity-based encryption
    - Persistent Merkle Chain
    - Immutable Audit Trail
    - Automatic Key Rotation
    - Compliance Standards
    """

    def __init__(self, kms_provider: str = "auto", config: Optional[Dict[str, Any]] = None) -> None:
        self.module_name = "SCM_Module"
        self.version = "4.0.0"
        self.schema_version = "1"
        self.config = config or SCM_CONFIG

        self.kms: KMSProvider = self._init_kms_provider(kms_provider)
        self.db = IntegratedAuditDatabase(self.config["database"])

        # MIGRATED — security policies loaded from Supabase via CGCDBLoader
        from app.Core.db.cgc_db_loader import get_db_loader
        self._db_loader = get_db_loader()

        self.tenant_keys: Dict[str, Dict[str, Any]] = {}
        self._load_tenant_keys()

        self.metrics: Dict[str, int] = {
            "total_encryptions": 0,
            "total_signatures": 0,
            "total_verifications": 0,
            "encryption_errors": 0,
            "signing_errors": 0,
        }

        kms_health = self.kms.health_check()
        logger.info(
            f"{self.module_name} v{self.version} initialized | "
            f"KMS: {kms_health.get('provider')} | "
            f"Standards: {', '.join(self._get_compliance_standards())}"
        )

    def _init_kms_provider(self, provider: str) -> KMSProvider:
        """Initialize KMS provider."""
        if provider == "aws":
            try:
                return AWSKMSProvider()
            except Exception as e:
                logger.warning(f"AWS KMS initialization failed: {e}, falling back to local")
                return LocalKMSProvider()
        if provider == "local":
            return LocalKMSProvider()

        # auto mode
        if os.getenv("AWS_KMS_MASTER_KEY_ID"):
            try:
                return AWSKMSProvider()
            except Exception:
                return LocalKMSProvider()
        return LocalKMSProvider()

    def _load_tenant_keys(self) -> None:
        """Load tenant keys from persistent storage."""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT * FROM tenant_keys")
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            tenant_dict = dict(zip(columns, row))
            tenant_id = tenant_dict["tenant_id"]
            self.tenant_keys[tenant_id] = tenant_dict

    def register_tenant(self, tenant_id: str, governance_area: str = "DEFAULT") -> Dict[str, Any]:
        """Register new tenant with isolated keys."""
        if tenant_id in self.tenant_keys:
            return self.tenant_keys[tenant_id]

        plaintext_key, encrypted_key = self.kms.generate_data_key("primary", tenant_id)
        policy = self._get_policy(governance_area)
        rotation_due = datetime.utcnow() + timedelta(days=policy["min_key_rotation_days"])

        enc_key_id = f"enc_{tenant_id}_{uuid.uuid4().hex[:8]}"
        sig_key_id = f"sig_{tenant_id}_{uuid.uuid4().hex[:8]}"

        cursor = self.db.conn.cursor()
        cursor.execute(
            """
            INSERT INTO tenant_keys
            (tenant_id, enc_key_id, sig_key_id, governance_area, rotation_due, kms_provider)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                enc_key_id,
                sig_key_id,
                governance_area,
                rotation_due.isoformat(),
                self.kms.health_check()["provider"],
            ),
        )
        self.db.conn.commit()

        self.tenant_keys[tenant_id] = {
            "tenant_id": tenant_id,
            "governance_area": governance_area,
            "enc_key_id": enc_key_id,
            "sig_key_id": sig_key_id,
            "plaintext_key": plaintext_key,
            "encrypted_key": encrypted_key,
            "created_at": datetime.utcnow().isoformat(),
            "last_rotated": datetime.utcnow().isoformat(),
            "rotation_due": rotation_due.isoformat(),
            "key_version": 1,
            "kms_provider": self.kms.health_check()["provider"],
        }

        logger.info(f"[SCM] Tenant registered: {tenant_id} ({governance_area})")
        return self.tenant_keys[tenant_id]

    def _get_policy(self, area: str) -> Dict[str, Any]:
        """Load security policy from Supabase. Replaces SECURITY_POLICY_MATRIX[area]."""
        rows = self._db_loader._query(
            "SELECT * FROM cgc_jla.scm_security_policies "
            "WHERE governance_area = %s AND is_active = TRUE LIMIT 1",
            (area,)
        )
        if rows:
            return dict(rows[0])
        rows = self._db_loader._query(
            "SELECT * FROM cgc_jla.scm_security_policies "
            "WHERE governance_area = 'DEFAULT' AND is_active = TRUE LIMIT 1"
        )
        return dict(rows[0]) if rows else {
            "encryption_required": True, "signing_required": True,
            "fingerprint_required": False, "min_key_rotation_days": 90,
            "audit_log_required": True, "chain_validation_strict": False,
            "hash_algorithm": "sha256", "signing_algorithm": "rsa_pss_2048",
            "double_encryption_threshold": 5, "audit_retention_years": 2,
            "description": "Fallback default policy"
        }

    def _get_sensitivity_config(self, level: str) -> Dict[str, Any]:
        """Load sensitivity config from Supabase. Replaces SENSITIVITY_ENCRYPTION_CONFIG[level]."""
        rows = self._db_loader._query(
            "SELECT * FROM cgc_jla.scm_sensitivity_config "
            "WHERE sensitivity_level = %s AND is_active = TRUE LIMIT 1",
            (level,)
        )
        if rows:
            return dict(rows[0])
        # Fallback
        defaults = {
            "LOW":    {"additional_encryption": False, "compression_enabled": True,  "include_metadata": False, "ttl_hours": 24,  "require_compliance_owner_sig": False},
            "MEDIUM": {"additional_encryption": False, "compression_enabled": False, "include_metadata": True,  "ttl_hours": 12,  "require_compliance_owner_sig": False},
            "HIGH":   {"additional_encryption": True,  "compression_enabled": False, "include_metadata": True,  "ttl_hours": 6,   "require_compliance_owner_sig": True},
        }
        return defaults.get(level, defaults["MEDIUM"])

    def _get_compliance_standards(self) -> List[str]:
        """
        Real, DB-backed list of standards this deployment has been
        independently certified against -- empty until one actually has been.
        Was a hardcoded fallback of 7 major certifications (FIPS-140-2,
        SOC2-Type2, ISO27001, HIPAA, PCI-DSS-v3.2.1, EU-GDPR, EU-AI-Act) that
        this system has never received, fed directly into get_metrics(),
        sign_artifact()'s output, and this module's own init log line -- a
        compliance claim asserted in code, not backed by any audit.
        """
        rows = self._db_loader._query(
            "SELECT standard FROM cgc_jla.scm_compliance_standards "
            "WHERE is_active = TRUE ORDER BY standard"
        )
        return [r["standard"] for r in rows] if rows else []


    def get_security_policy(self, area: str) -> Dict[str, Any]:
        """Return security policy for governance area."""
        policy = self._get_policy(area)
        logger.info(f"[SCM] Security policy for {area}: {policy['description']}")
        return policy

    def check_entry_policy(
        self,
        action: str,
        input_data: Dict[str, Any],
        prefilter_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Entry-point gate consulted by LOOP.execute_governance_cycle() before
        running the core governance modules. Never existed on this class --
        LOOP was written calling self.scm.check_entry_policy(...), which
        meant every real governance decision failed at this exact first
        SCM call, before ECM/PFM/PAN/SDA ever ran. Permissive pass-through
        that surfaces the area's security policy; real entry-rejection
        criteria (e.g. reject unsigned high-sensitivity requests) is a
        future security/business decision, not invented here.
        """
        area = (prefilter_result or {}).get("areaIdentified", "DEFAULT")
        policy = self.get_security_policy(area)
        return {
            "approved": True,
            "reason": "Entry policy check passed",
            "area": area,
            "action": action,
            "policy": policy,
        }

    def get_encryption_config(self, sensitivity_level: str) -> Dict[str, Any]:
        """Return encryption configuration for sensitivity level."""
        config = self._get_sensitivity_config(sensitivity_level)
        logger.info(
            f"[SCM] Sensitivity configuration: {sensitivity_level} | "
            f"Double encryption: {config['additional_encryption']}"
        )
        return config

    def encrypt_data(
        self,
        data: str,
        tenant_id: str,
        area: str = "DEFAULT",
        sensitivity_level: str = "MEDIUM",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Encrypt data with tenant isolation and sensitivity-based protections."""
        self.register_tenant(tenant_id, area)
        try:
            tenant_key = self.tenant_keys[tenant_id]["plaintext_key"]
            fernet = Fernet(tenant_key)

            encrypted_once = fernet.encrypt(data.encode()).decode()

            policy = self.get_security_policy(area)
            enc_config = self.get_encryption_config(sensitivity_level)
            sensitive_count = len(context.get("sensitive_domains", [])) if context else 0

            double_encrypted = False
            if enc_config["additional_encryption"] or sensitive_count >= policy.get(
                "double_encryption_threshold", 5
            ):
                encrypted_twice = fernet.encrypt(encrypted_once.encode()).decode()
                encrypted_data = encrypted_twice
                double_encrypted = True
                logger.info("[SCM] Double encryption applied for high sensitivity data")
            else:
                encrypted_data = encrypted_once

            data_hash = hashlib.sha256(data.encode()).hexdigest()
            encrypted_hash = hashlib.sha256(encrypted_data.encode()).hexdigest()

            audit_id = self.db.record_encryption(
                tenant_id,
                data_hash,
                encrypted_hash,
                "AES-256-Fernet",
                self.tenant_keys[tenant_id]["enc_key_id"],
                sensitivity_level,
                double_encrypted,
            )

            node_data = {
                "node_hash": hashlib.sha256(
                    (data_hash + encrypted_hash).encode()
                ).hexdigest(),
                "data_hash": data_hash,
                "signature": "",
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": {
                    "sensitivity": sensitivity_level,
                    "double_encrypted": double_encrypted,
                    "area": area,
                },
            }
            node_id = self.db.add_merkle_node(tenant_id, node_data)

            self.metrics["total_encryptions"] += 1
            logger.info(
                f"[SCM] Data encrypted: {len(data)} bytes | Tenant: {tenant_id} | "
                f"Double: {double_encrypted} | Audit: {audit_id}"
            )

            return {
                "encrypted_content": encrypted_data,
                "tenant_id": tenant_id,
                "data_hash": data_hash,
                "encrypted_hash": encrypted_hash,
                "sensitivity_level": sensitivity_level,
                "double_encrypted": double_encrypted,
                "algorithm": "AES-256-Fernet",
                "key_id": self.tenant_keys[tenant_id]["enc_key_id"],
                "timestamp": datetime.utcnow().isoformat(),
                "audit_id": audit_id,
                "node_id": node_id,
            }
        except Exception as e:
            self.metrics["encryption_errors"] += 1
            logger.error(f"[SCM] Encryption error: {e}")
            raise RuntimeError(f"encryption_failed: {str(e)}") from e

    def decrypt_data(self, encrypted_data: str, tenant_id: str) -> str:
        """Decrypt data (supports single or double encryption)."""
        try:
            tenant_key = self.tenant_keys[tenant_id]["plaintext_key"]
            fernet = Fernet(tenant_key)

            decrypted_once = fernet.decrypt(encrypted_data.encode()).decode()
            try:
                decrypted_twice = fernet.decrypt(decrypted_once.encode()).decode()
                logger.info("[SCM] Double decryption successful")
                return decrypted_twice
            except Exception:
                return decrypted_once
        except Exception as e:
            self.metrics["encryption_errors"] += 1
            logger.error(f"[SCM] Decryption error: {e}")
            raise ValueError(f"decryption_failed: {str(e)}") from e

    def sign_data(
        self, data: str, tenant_id: str, context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Sign data with RSA-PSS using KMS provider."""
        self.register_tenant(tenant_id)
        try:
            if isinstance(data, str) and data.startswith("{"):
                try:
                    data_obj = json.loads(data)
                    canonical = json.dumps(data_obj, sort_keys=True, separators=(",", ":"))
                except Exception:
                    canonical = data
            else:
                canonical = data

            data_hash = hashlib.sha256(canonical.encode()).hexdigest()
            signature = self.kms.sign_data(canonical.encode(), f"tenant_{tenant_id}")
            signature_b64 = base64.urlsafe_b64encode(signature).decode()

            sig_id = self.db.record_signature(
                tenant_id,
                data_hash,
                signature_b64,
                "RSA-2048-PSS-SHA256",
                self.tenant_keys[tenant_id]["sig_key_id"],
                self.kms.health_check()["provider"],
                context or {},
            )

            self.metrics["total_signatures"] += 1
            logger.info(
                f"[SCM] Data signed | Tenant: {tenant_id} | Algorithm: RSA-PSS-SHA256 | Signature ID: {sig_id}"
            )

            return {
                "signature_id": sig_id,
                "data_hash": data_hash,
                "signature": signature_b64,
                "algorithm": "RSA-2048-PSS-SHA256",
                "tenant_id": tenant_id,
                "signed_at": datetime.utcnow().isoformat(),
                "signer": f"CGC_SCM_INTEGRATED/{tenant_id}",
                "key_id": self.tenant_keys[tenant_id]["sig_key_id"],
                "kms_provider": self.kms.health_check()["provider"],
                "schema_version": self.schema_version,
                "canonical_data": canonical,
            }
        except Exception as e:
            self.metrics["signing_errors"] += 1
            logger.error(f"[SCM] Signing error: {e}")
            raise RuntimeError(f"signing_failed: {str(e)}") from e

    def sign_artifact(
        self,
        artifact: Dict[str, Any],
        op_type: str,
        prefilter_result: Optional[Dict[str, Any]] = None,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Signs a governance decision artifact for LOOP.execute_governance_cycle()
        -- same gap as check_entry_policy above: LOOP was written calling
        self.scm.sign_artifact(...), which never existed, so decisions never
        reached a signed state. Delegates to the real sign_data() (the same
        method /audit/seal already uses) and attaches the signature onto a
        copy of the artifact rather than mutating the caller's dict.
        """
        payload = json.dumps(artifact, sort_keys=True, default=str)
        signature_result = self.sign_data(
            payload, tenant_id, context={"operation": op_type}
        )
        signed = dict(artifact)
        signed["signature"] = signature_result
        return signed

    def verify_signature(
        self,
        signature_id: str,
        tenant_id: str,
        signature: str,
        data_hash: str,
    ) -> Dict[str, Any]:
        """Verify RSA-PSS signature using KMS provider."""
        try:
            sig_bytes = base64.urlsafe_b64decode(signature.encode())
            is_valid = self.kms.verify_signature(
                data_hash.encode(), sig_bytes, f"tenant_{tenant_id}"
            )

            self.db.record_verification(
                tenant_id,
                signature_id,
                verified_by="SCMIntegrated_Verifier",
                compliance_status="VALID" if is_valid else "INVALID",
                standards=self._get_compliance_standards(),
            )

            self.metrics["total_verifications"] += 1
            logger.info(
                f"[SCM] Signature verification: {'VALID' if is_valid else 'INVALID'} "
                f"(Signature: {signature_id})"
            )

            return {
                "signature_id": signature_id,
                "is_valid": is_valid,
                "verified_at": datetime.utcnow().isoformat(),
                "compliance_standards": self._get_compliance_standards(),
            }
        except Exception as e:
            logger.error(f"[SCM] Verification error: {e}")
            return {
                "signature_id": signature_id,
                "is_valid": False,
                "error": str(e),
                "verified_at": datetime.utcnow().isoformat(),
            }

    def rotate_tenant_keys(self, tenant_id: str) -> Dict[str, Any]:
        """Rotate tenant encryption keys via KMS."""
        if tenant_id not in self.tenant_keys:
            raise ValueError(f"Tenant {tenant_id} is not registered")

        governance_area = self.tenant_keys[tenant_id]["governance_area"]
        policy = self.get_security_policy(governance_area)

        plaintext_key, encrypted_key = self.kms.generate_data_key("rotation", tenant_id)
        rotation_due = datetime.utcnow() + timedelta(days=policy["min_key_rotation_days"])

        cursor = self.db.conn.cursor()
        cursor.execute(
            """
            UPDATE tenant_keys
            SET last_rotated = CURRENT_TIMESTAMP,
                rotation_due = ?,
                version = version + 1
            WHERE tenant_id = ?
            """,
            (rotation_due.isoformat(), tenant_id),
        )
        self.db.conn.commit()

        current_version = self.tenant_keys[tenant_id].get("key_version", 1) + 1
        self.tenant_keys[tenant_id].update(
            {
                "plaintext_key": plaintext_key,
                "encrypted_key": encrypted_key,
                "last_rotated": datetime.utcnow().isoformat(),
                "rotation_due": rotation_due.isoformat(),
                "key_version": current_version,
            }
        )

        logger.info(f"[SCM] Key rotation completed for tenant {tenant_id}")

        return {
            "tenant_id": tenant_id,
            "rotation_completed_at": datetime.utcnow().isoformat(),
            "new_key_version": current_version,
            "next_rotation_due": rotation_due.isoformat(),
        }

    def get_compliance_audit_report(self, tenant_id: str, signature_id: str) -> Dict[str, Any]:
        """Generate legal audit report for compliance."""
        report = self.db.get_compliance_report(tenant_id, signature_id)
        report.update(
            {
                "generated_at": datetime.utcnow().isoformat(),
                "module": self.module_name,
                "version": self.version,
                "kms_provider": self.kms.health_check()["provider"],
                "compliance_standards": self._get_compliance_standards(),
            }
        )
        return report

    def get_audit_trail(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Return full immutable audit trail."""
        return self.db.get_audit_trail(tenant_id, limit=limit)

    def get_enterprise_dashboard(self) -> Dict[str, Any]:
        """Enterprise-level dashboard metrics."""
        kms_health = self.kms.health_check()
        cursor = self.db.conn.cursor()
        total_chain_nodes = cursor.execute("SELECT COUNT(*) FROM merkle_chain").fetchone()[0]
        chain_integrity = all(self.db.verify_tenant_chain(t) for t in self.tenant_keys.keys())

        return {
            "module": self.module_name,
            "version": self.version,
            "status": "OPERATIONAL",
            "database": self.config["database"],
            "kms_provider": kms_health,
            "tenant_count": len(self.tenant_keys),
            "total_chain_nodes": total_chain_nodes,
            "global_encryptions": self.metrics["total_encryptions"],
            "global_signatures": self.metrics["total_signatures"],
            "global_verifications": self.metrics["total_verifications"],
            "tenant_isolation": self.config["tenant_isolation"],
            "key_rotation_days": self.config["key_rotation_days"],
            "chain_integrity": chain_integrity,
            "compliance": self._get_compliance_standards(),
            "security_policies_loaded": 7,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Return core SCM metrics."""
        return {
            "module": self.module_name,
            "version": self.version,
            "status": "active",
            "metrics": self.metrics,
            "kms_provider": self.kms.health_check()["provider"],
            "tenant_count": len(self.tenant_keys),
        }


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

_scm_integrated_instance: Optional["SCM"] = None


def get_scm_integrated(
    kms_provider: str = "auto", config: Optional[Dict[str, Any]] = None
) -> "SCM":
    """Get or create SCMIntegrated singleton instance."""
    global _scm_integrated_instance
    if _scm_integrated_instance is None:
        _scm_integrated_instance = SCM(kms_provider=kms_provider, config=config)
    return _scm_integrated_instance


if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("SCM™ INTEGRATED - Security & Cryptographic Module")
    logger.info("=" * 80)

    scm = get_scm_integrated(kms_provider="auto")

    tenant_id = "acme_bank_001"
    scm.register_tenant(tenant_id, "BANKING")

    banking_data = json.dumps(
        {
            "account": "1234567890",
            "amount": 50000.00,
            "currency": "USD",
        }
    )

    encryption_result = scm.encrypt_data(
        banking_data,
        tenant_id,
        area="BANKING",
        sensitivity_level="HIGH",
        context={
            "sensitive_domains": ["PAYMENT_CARD", "ACCOUNT_ROUTING", "FINANCIAL_DATA"],
        },
    )
    logger.info("Encryption Result (metadata only):")
    print(json.dumps({k: v for k, v in encryption_result.items() if k != "encrypted_content"}, indent=2))

    signature_result = scm.sign_data(
        encryption_result["encrypted_content"],
        tenant_id,
        context={"operation": "TRANSFER", "amount": 50000},
    )
    logger.info("Signature Result (without signature body):")
    print(json.dumps({k: v for k, v in signature_result.items() if k != "signature"}, indent=2))

    verification_result = scm.verify_signature(
        signature_result["signature_id"],
        tenant_id,
        signature_result["signature"],
        signature_result["data_hash"],
    )
    logger.info("Verification Result:")
    print(json.dumps(verification_result, indent=2))

    audit_report = scm.get_compliance_audit_report(tenant_id, signature_result["signature_id"])
    logger.info("Compliance Audit Report:")
    print(json.dumps(audit_report, indent=2))

    dashboard = scm.get_enterprise_dashboard()
    logger.info("Enterprise Dashboard:")
    print(json.dumps(dashboard, indent=2))