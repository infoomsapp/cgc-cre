"""
CGC Core — PoD PostgreSQL Repository
Persistence layer for Proof-of-Decision interceptor.

Handles all database operations for:
  - cgc_pod.inference_intercepts  (the triplet records)
  - cgc_pod.pod_ledger            (the immutable chain blocks)
  - cgc_pod.chain_integrity_log   (verification audit)

Uses asyncpg for high-performance async I/O.
Falls back gracefully to in-memory mode when DB is unavailable.

Install: pip install asyncpg
Env var: CGC_DATABASE_URL=postgresql://user:pass@host:5432/cgc_core

Olympus Mont Systems LLC © 2026
"""

import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

try:
    from app.Core.logging import get_logger
    logger = get_logger("cgc.pod.repository")
except ImportError:
    logger = logging.getLogger("cgc.pod.repository")

if TYPE_CHECKING:
    from app.modules.pod.pod_interceptor import InterceptTriplet, PoDBlock


# ============================================================================
# CONNECTION POOL
# ============================================================================

_pool: Optional[Any] = None


async def get_pool() -> Optional[Any]:
    """
    Get or create the global asyncpg connection pool.
    Returns None if DB unavailable — callers fall back to in-memory.
    """
    global _pool
    if _pool is not None:
        return _pool

    if not ASYNCPG_AVAILABLE:
        logger.warning("[PoDRepo] asyncpg not installed — pip install asyncpg")
        return None

    dsn = os.getenv(
        "CGC_DATABASE_URL",
        "postgresql://cgc_user:cgc_password@localhost:5432/cgc_core"
    )

    try:
        _pool = await asyncpg.create_pool(
            dsn=dsn,
            min_size=2,
            max_size=10,
            command_timeout=30,
            server_settings={"application_name": "cgc_pod_interceptor"}
        )
        logger.info("[PoDRepo] PostgreSQL connection pool established")
        return _pool
    except Exception as e:
        logger.error(f"[PoDRepo] Failed to connect to PostgreSQL: {e}")
        return None


async def close_pool() -> None:
    """Gracefully close the connection pool on app shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("[PoDRepo] Connection pool closed")


@asynccontextmanager
async def get_connection(tenant_id: Optional[str] = None):
    """
    Context manager: single DB connection with tenant RLS applied.
    Sets cgc.current_tenant_id so Row Level Security policies activate.
    Yields None if pool is unavailable.
    """
    pool = await get_pool()
    if pool is None:
        yield None
        return

    async with pool.acquire() as conn:
        if tenant_id:
            # set_config() is parameterizable (unlike `SET LOCAL var = 'value'`,
            # which doesn't support bind params) -- SQL injection fix:
            # tenant_id traces back to client-supplied org_id, and this used
            # to be an f-string interpolated straight into raw SQL.
            await conn.execute(
                "SELECT set_config('cgc.current_tenant_id', $1, true)", tenant_id
            )
        yield conn


# ============================================================================
# POD REPOSITORY
# ============================================================================

class PoDRepository:
    """
    Async PostgreSQL repository for the PoD system.

    Design principles:
    - Never raises to caller — DB failure logs and returns None/False
    - All writes are idempotent (ON CONFLICT DO NOTHING)
    - save_intercept_and_block uses a transaction for atomicity
    - pod_ledger is append-only (enforced by DB RULE, not just code)
    - RLS ensures tenant data isolation at the DB level
    """

    # ─────────────────────────────────────────────────────────────────────────
    # CHAIN STATE
    # ─────────────────────────────────────────────────────────────────────────

    async def get_last_block_hash(self, tenant_id: str) -> str:
        GENESIS = "0" * 64
        try:
            async with get_connection(tenant_id) as conn:
                if conn is None:
                    return GENESIS
                row = await conn.fetchrow(
                    """
                    SELECT block_hash
                    FROM   cgc_pod.pod_ledger
                    WHERE  tenant_id = $1
                    ORDER  BY block_number DESC
                    LIMIT  1
                    """,
                    tenant_id
                )
                return row["block_hash"] if row else GENESIS
        except Exception as e:
            logger.error(f"[PoDRepo] get_last_block_hash: {e}")
            return "0" * 64

    async def get_next_block_number(self, tenant_id: str) -> int:
        try:
            async with get_connection(tenant_id) as conn:
                if conn is None:
                    return 0
                row = await conn.fetchrow(
                    """
                    SELECT COALESCE(MAX(block_number), -1) + 1 AS next_num
                    FROM   cgc_pod.pod_ledger
                    WHERE  tenant_id = $1
                    """,
                    tenant_id
                )
                return int(row["next_num"]) if row else 0
        except Exception as e:
            logger.error(f"[PoDRepo] get_next_block_number: {e}")
            return 0

    async def get_chain_height(self, tenant_id: str) -> int:
        try:
            async with get_connection(tenant_id) as conn:
                if conn is None:
                    return 0
                row = await conn.fetchrow(
                    "SELECT COUNT(*) AS h FROM cgc_pod.pod_ledger WHERE tenant_id = $1",
                    tenant_id
                )
                return int(row["h"]) if row else 0
        except Exception as e:
            logger.error(f"[PoDRepo] get_chain_height: {e}")
            return 0

    # ─────────────────────────────────────────────────────────────────────────
    # ATOMIC WRITE
    # ─────────────────────────────────────────────────────────────────────────

    async def save_intercept_and_block(
        self,
        triplet: "InterceptTriplet",
        block: "PoDBlock",
        signing_key_db_id: str,
        model_db_id: str
    ) -> bool:
        """
        Atomically persist InterceptTriplet + PoDBlock in one transaction.
        If either write fails, both are rolled back.
        The pod_ledger insert is effectively immutable — DB RULE prevents
        any future UPDATE or DELETE on that table.
        """
        try:
            async with get_connection(triplet.tenant_id) as conn:
                if conn is None:
                    return False

                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO cgc_pod.inference_intercepts (
                            intercept_id, decision_id, tenant_id, model_id,
                            input_payload_hash, model_identifier, output_payload_hash,
                            intercepted_at, delivery_at, latency_ms,
                            triplet_hash, triplet_signature, signing_key_id,
                            timestamp_token, timestamp_authority,
                            pii_detected, pii_fields_count
                        ) VALUES (
                            $1,$2,$3,$4,$5,$6,$7,
                            $8::TIMESTAMPTZ,$9::TIMESTAMPTZ,$10,
                            $11,$12,$13,$14,$15,$16,$17
                        )
                        ON CONFLICT (intercept_id) DO NOTHING
                        """,
                        triplet.intercept_id, triplet.decision_id,
                        triplet.tenant_id, model_db_id,
                        triplet.input_payload_hash, triplet.model_identifier,
                        triplet.output_payload_hash,
                        triplet.intercepted_at, triplet.delivered_at,
                        triplet.latency_ms,
                        triplet.triplet_hash, triplet.triplet_signature,
                        signing_key_db_id,
                        triplet.timestamp_token, triplet.timestamp_authority,
                        triplet.pii_detected, triplet.pii_fields_count
                    )
                    await conn.execute(
                        """
                        INSERT INTO cgc_pod.pod_ledger (
                            block_uuid, tenant_id, intercept_id, decision_id,
                            block_number, previous_block_hash, block_hash,
                            triplet_hash, governance_outcome, compliance_score,
                            chain_height, sealed_at, sealed_by, tamper_detected
                        ) VALUES (
                            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
                            $12::TIMESTAMPTZ,$13,FALSE
                        )
                        ON CONFLICT (block_hash) DO NOTHING
                        """,
                        block.block_uuid, block.tenant_id,
                        block.intercept_id, block.decision_id,
                        block.block_number, block.previous_block_hash,
                        block.block_hash, block.triplet_hash,
                        block.governance_outcome, block.compliance_score,
                        block.block_number, block.sealed_at, block.sealed_by
                    )

                logger.info(
                    f"[PoDRepo] Atomic OK | intercept={triplet.intercept_id[:8]} "
                    f"block=#{block.block_number} hash={block.block_hash[:12]}..."
                )
                return True

        except Exception as e:
            logger.error(f"[PoDRepo] TRANSACTION FAILED: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # READ / FORENSIC
    # ─────────────────────────────────────────────────────────────────────────

    async def get_chain_range(
        self, tenant_id: str, from_block: int, to_block: int
    ) -> List[Dict]:
        try:
            async with get_connection(tenant_id) as conn:
                if conn is None:
                    return []
                rows = await conn.fetch(
                    """
                    SELECT block_number, block_hash, previous_block_hash,
                           triplet_hash, governance_outcome, sealed_at,
                           tamper_detected
                    FROM   cgc_pod.pod_ledger
                    WHERE  tenant_id    = $1
                      AND  block_number >= $2
                      AND  block_number <= $3
                    ORDER  BY block_number ASC
                    """,
                    tenant_id, from_block, to_block
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[PoDRepo] get_chain_range: {e}")
            return []

    async def forensic_lookup(
        self, decision_id: str, tenant_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Full forensic record for a decision.
        Returns everything an auditor needs to verify an AI decision:
        chain position, cryptographic proof, governance outcome, privacy metadata.
        This is the 'prove it in 30 seconds' capability from the patent pitch.
        """
        try:
            async with get_connection(tenant_id) as conn:
                if conn is None:
                    return None
                row = await conn.fetchrow(
                    """
                    SELECT
                        pl.block_number, pl.block_hash, pl.previous_block_hash,
                        pl.governance_outcome, pl.compliance_score,
                        pl.sealed_at, pl.tamper_detected,
                        ii.intercept_id,
                        ii.input_payload_hash, ii.model_identifier,
                        ii.output_payload_hash, ii.triplet_hash,
                        ii.triplet_signature, ii.intercepted_at, ii.delivery_at,
                        ii.latency_ms, ii.timestamp_token, ii.timestamp_authority,
                        ii.pii_detected, ii.pii_fields_count
                    FROM   cgc_pod.pod_ledger pl
                    JOIN   cgc_pod.inference_intercepts ii
                           ON pl.intercept_id = ii.intercept_id
                    WHERE  pl.decision_id = $1 AND pl.tenant_id = $2
                    """,
                    decision_id, tenant_id
                )
                if not row:
                    return None
                return {
                    "decision_id": decision_id,
                    "chain": {
                        "block_number":    row["block_number"],
                        "block_hash":      row["block_hash"],
                        "previous_hash":   row["previous_block_hash"],
                        "sealed_at":       str(row["sealed_at"]),
                        "tamper_detected": row["tamper_detected"]
                    },
                    "proof": {
                        "triplet_hash":       row["triplet_hash"],
                        "triplet_signature":  row["triplet_signature"],
                        "model_identifier":   row["model_identifier"],
                        "input_hash":         row["input_payload_hash"],
                        "output_hash":        row["output_payload_hash"],
                        "intercepted_at":     str(row["intercepted_at"]),
                        "delivered_at":       str(row["delivery_at"]) if row["delivery_at"] else None,
                        "latency_ms":         float(row["latency_ms"]) if row["latency_ms"] else None,
                        "timestamp_token":    row["timestamp_token"],
                        "timestamp_authority": row["timestamp_authority"],
                    },
                    "governance": {
                        "outcome":          row["governance_outcome"],
                        "compliance_score": float(row["compliance_score"]) if row["compliance_score"] else None,
                    },
                    "privacy": {
                        "pii_detected":  row["pii_detected"],
                        "pii_fields":    row["pii_fields_count"],
                        "content_stored": False
                    },
                    "non_repudiation": not row["tamper_detected"]
                }
        except Exception as e:
            logger.error(f"[PoDRepo] forensic_lookup: {e}")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # INTEGRITY VERIFICATION
    # ─────────────────────────────────────────────────────────────────────────

    async def run_integrity_verification(
        self,
        tenant_id: str,
        verified_by: str = "cgc-pod-verifier"
    ) -> Dict[str, Any]:
        """
        Full chain integrity verification.
        Walks all blocks, verifies previous_hash linkage.
        Persists result to cgc_pod.chain_integrity_log.
        Returns audit report for legal submission.
        """
        start = time.monotonic()
        GENESIS = "0" * 64

        blocks = await self.get_chain_range(tenant_id, 0, 999_999_999)
        if not blocks:
            return {
                "tenant_id": tenant_id, "blocks_verified": 0,
                "integrity_passed": True, "broken_at_block": None,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "message": "Empty chain"
            }

        broken_at = None
        prev_hash = GENESIS
        for block in blocks:
            if block["previous_block_hash"] != prev_hash:
                broken_at = block["block_number"]
                break
            prev_hash = block["block_hash"]

        elapsed_ms = (time.monotonic() - start) * 1000

        try:
            async with get_connection(tenant_id) as conn:
                if conn:
                    await conn.execute(
                        """
                        INSERT INTO cgc_pod.chain_integrity_log (
                            tenant_id, verified_from_block, verified_to_block,
                            blocks_verified, integrity_passed, broken_at_block,
                            verification_time_ms, verified_by
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                        """,
                        tenant_id,
                        blocks[0]["block_number"], blocks[-1]["block_number"],
                        len(blocks), broken_at is None, broken_at,
                        round(elapsed_ms, 3), verified_by
                    )
        except Exception as e:
            logger.warning(f"[PoDRepo] Could not persist integrity log: {e}")

        if broken_at is None:
            logger.info(f"[PoDRepo] Chain VERIFIED | {len(blocks)} blocks | {elapsed_ms:.1f}ms")
        else:
            logger.critical(f"[PoDRepo] CHAIN INTEGRITY FAILURE at block #{broken_at}")

        return {
            "tenant_id":        tenant_id,
            "blocks_verified":  len(blocks),
            "integrity_passed": broken_at is None,
            "broken_at_block":  broken_at,
            "chain_height":     len(blocks),
            "verification_ms":  round(elapsed_ms, 3),
            "verified_by":      verified_by,
            "verified_at":      datetime.now(timezone.utc).isoformat()
        }


# ============================================================================
# SINGLETON
# ============================================================================

_instance: Optional[PoDRepository] = None


def get_pod_repository() -> PoDRepository:
    global _instance
    if _instance is None:
        _instance = PoDRepository()
    return _instance