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

import asyncio
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


def _ledger_uid(value: str) -> str:
    """
    cgc_pod.pod_ledger pre-dates this session (confirmed via a live
    information_schema check -- it was never created by this codebase) and
    its tenant_id/decision_id columns are UUID-typed, but the application
    generates both as arbitrary strings (caller-supplied org_id, a
    prefixed decision token). uuid5 gives a stable, reproducible mapping
    without changing either side, so every write and every read filters
    through this same conversion. intercept_id is already a real UUID
    (str(uuid.uuid4()) in begin_intercept) and is used as-is everywhere,
    since it already matches the value stored in inference_intercepts for
    forensic_lookup's JOIN.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, value))


# ============================================================================
# CONNECTION POOL
# ============================================================================

_pool: Optional[Any] = None
_pool_lock: Optional[Any] = None  # created lazily -- see get_pool()


async def get_pool() -> Optional[Any]:
    """
    Get or create the global asyncpg connection pool.
    Returns None if DB unavailable — callers fall back to in-memory.

    Guarded by an asyncio.Lock, double-checked before and after acquiring
    it. Found live: 5 genuinely concurrent /governance/decision calls for
    the same tenant (a real Vercel cold instance, _pool still None) all
    independently saw `_pool is None` and each launched its OWN
    asyncpg.create_pool() at the same time -- an unguarded "cache
    stampede". Firing 5 simultaneous new-connection bursts at Supabase's
    PgBouncer is exactly the kind of burst a transient rejection would
    hit, and get_pool()'s own except swallowed whichever ones failed,
    returning None with no detail -- confirmed via a temporary diagnostic
    that bypassed every wrapping try/except (all 5 failed identically
    with no pool ever available). The lock makes every caller after the
    first simply await the one real creation instead of racing it.
    """
    global _pool, _pool_lock
    if _pool is not None:
        return _pool

    if _pool_lock is None:
        _pool_lock = asyncio.Lock()

    async with _pool_lock:
        if _pool is not None:  # someone else won the race while we waited
            return _pool

        if not ASYNCPG_AVAILABLE:
            logger.warning("[PoDRepo] asyncpg not installed — pip install asyncpg")
            return None

        # Same fallback as cgc_db_loader.py: CGC_DATABASE_URL was never
        # provisioned as a separate database -- cgc_pod lives in the same
        # Postgres as DATABASE_URL (Database._create_pod_schema() creates
        # it there). Falling back to DATABASE_URL means this works with
        # zero new secrets.
        dsn = (
            os.getenv("CGC_DATABASE_URL")
            or os.getenv("DATABASE_URL")
            or "postgresql://cgc_user:cgc_password@localhost:5432/cgc_core"
        )

        try:
            _pool = await asyncpg.create_pool(
                dsn=dsn,
                min_size=2,
                max_size=10,
                command_timeout=30,
                # Supabase's connection pooler runs PgBouncer in transaction
                # mode, which doesn't support asyncpg's default server-side
                # prepared statements (each "connection" can be a different
                # backend per transaction) -- disabling the statement cache is
                # the standard asyncpg+PgBouncer mitigation.
                statement_cache_size=0,
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

    The set_config(..., true) call is transaction-LOCAL by design (`true`
    means is_local -- safe against a pooled connection leaking one
    tenant's scope into the next request that reuses it, unlike
    is_local=false which would persist on the physical connection past
    this block). That safety only holds if the value is set inside the
    SAME transaction as whatever the caller does with the yielded
    connection -- found live (2026-08-23, right after cutting this
    connection over to the real RLS-restricted `cgc_app` role, which is
    what finally made the gap observable): set_config was previously
    called as its own standalone statement, auto-committed in its own
    implicit transaction the instant it ran, *before* callers like
    seal_block_atomic opened their own separate `async with
    conn.transaction():` for the actual writes -- so the tenant scope was
    already gone by the time those writes ran, and every real PoD write
    silently failed the RLS check (fail-open, no visible error;
    /verify/{decision_id} started returning proof_of_decision: null for
    every new decision). Wrapping the whole yielded block in one explicit
    transaction here fixes it -- a caller's own `async with
    conn.transaction():` nests as a savepoint inside this one, so
    existing callers (seal_block_atomic) need no changes.
    """
    pool = await get_pool()
    if pool is None:
        yield None
        return

    async with pool.acquire() as conn:
        if tenant_id:
            async with conn.transaction():
                # set_config() is parameterizable (unlike `SET LOCAL var = 'value'`,
                # which doesn't support bind params) -- SQL injection fix:
                # tenant_id traces back to client-supplied org_id, and this used
                # to be an f-string interpolated straight into raw SQL.
                await conn.execute(
                    "SELECT set_config('cgc.current_tenant_id', $1, true)", tenant_id
                )
                yield conn
        else:
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
    - seal_block_atomic uses a per-tenant advisory lock + one transaction
      for both correct block sequencing and atomicity
    - pod_ledger is append-only (enforced by DB RULE, not just code)
    - RLS ensures tenant data isolation at the DB level
    """

    # ─────────────────────────────────────────────────────────────────────────
    # CHAIN STATE
    # ─────────────────────────────────────────────────────────────────────────

    async def get_chain_height(self, tenant_id: str) -> int:
        try:
            async with get_connection(tenant_id) as conn:
                if conn is None:
                    return 0
                row = await conn.fetchrow(
                    "SELECT COUNT(*) AS h FROM cgc_pod.pod_ledger WHERE tenant_id = $1",
                    _ledger_uid(tenant_id)
                )
                return int(row["h"]) if row else 0
        except Exception as e:
            logger.error(f"[PoDRepo] get_chain_height: {e}")
            return 0

    # ─────────────────────────────────────────────────────────────────────────
    # ATOMIC WRITE
    # ─────────────────────────────────────────────────────────────────────────

    async def seal_block_atomic(
        self,
        triplet: "InterceptTriplet",
        governance_outcome: str,
        compliance_score: Optional[float],
        block_factory,
    ) -> Optional["PoDBlock"]:
        """
        Atomically determines this tenant's next block_number/previous_hash
        and persists the sealed block -- replaces the old design where
        PoDInterceptor computed both values from a per-process in-memory
        counter that resets to zero on every cold start. On Vercel that
        means "every cold start", not just genuine concurrency -- without
        this, every fresh instance independently believes it's sealing
        block #0 for a tenant that may already have real history.

        A per-tenant Postgres advisory lock (`pg_advisory_xact_lock`,
        transaction-scoped, auto-released on commit/rollback) serializes
        concurrent seals for the SAME tenant across instances, while
        different tenants proceed fully in parallel. Locks on
        _ledger_uid(tenant_id) -- the same identity space the block
        query/insert already use (an earlier version locked on the raw
        tenant_id string instead; still self-consistent per tenant since
        the mapping is deterministic, but conceptually mismatched).
        block_factory(next_number, prev_hash) -> PoDBlock is called while
        the lock is held, since the block's hash is a pure function of
        both values and must be computed before a concurrent writer for
        this tenant could act on stale numbers.

        The pod_ledger insert is effectively immutable -- DB RULE/trigger
        prevents any future UPDATE or DELETE on that table.
        """
        def _ts(iso_str: Optional[str]):
            # InterceptTriplet/PoDBlock store timestamps as ISO strings
            # (needed for JSON serialization elsewhere); unlike psycopg2,
            # asyncpg's binary protocol resolves $N::TIMESTAMPTZ params to
            # a strict `timestamptz` codec that rejects a plain str -- it
            # needs a real datetime.datetime, converted only here at the
            # DB-write boundary.
            return datetime.fromisoformat(iso_str) if iso_str else None

        GENESIS = "0" * 64
        try:
            async with get_connection(triplet.tenant_id) as conn:
                if conn is None:
                    return None

                async with conn.transaction():
                    await conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtext($1))",
                        _ledger_uid(triplet.tenant_id)
                    )

                    row = await conn.fetchrow(
                        """
                        SELECT COALESCE(MAX(block_number), -1) + 1 AS next_num,
                               (SELECT block_hash FROM cgc_pod.pod_ledger
                                 WHERE tenant_id = $1
                                 ORDER BY block_number DESC LIMIT 1) AS last_hash
                        FROM   cgc_pod.pod_ledger
                        WHERE  tenant_id = $1
                        """,
                        _ledger_uid(triplet.tenant_id)
                    )
                    next_number = int(row["next_num"]) if row and row["next_num"] is not None else 0
                    prev_hash = row["last_hash"] if row and row["last_hash"] else GENESIS

                    block = block_factory(next_number, prev_hash)

                    await conn.execute(
                        """
                        INSERT INTO cgc_pod.inference_intercepts (
                            intercept_id, decision_id, tenant_id,
                            input_payload_hash, model_identifier, output_payload_hash,
                            intercepted_at, delivery_at, latency_ms,
                            triplet_hash, triplet_signature, signing_key_id,
                            timestamp_token, timestamp_authority,
                            pii_detected, pii_fields_count
                        ) VALUES (
                            $1,$2,$3,$4,$5,$6,
                            $7::TIMESTAMPTZ,$8::TIMESTAMPTZ,$9,
                            $10,$11,$12,$13,$14,$15,$16
                        )
                        ON CONFLICT (intercept_id) DO NOTHING
                        """,
                        triplet.intercept_id, triplet.decision_id,
                        triplet.tenant_id,
                        triplet.input_payload_hash, triplet.model_identifier,
                        triplet.output_payload_hash,
                        _ts(triplet.intercepted_at), _ts(triplet.delivered_at),
                        triplet.latency_ms,
                        triplet.triplet_hash, triplet.triplet_signature,
                        triplet.signing_key_id,
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
                        block.block_uuid, _ledger_uid(block.tenant_id),
                        block.intercept_id, _ledger_uid(block.decision_id),
                        block.block_number, block.previous_block_hash,
                        block.block_hash, block.triplet_hash,
                        block.governance_outcome, block.compliance_score,
                        block.block_number, _ts(block.sealed_at), block.sealed_by
                    )

                logger.info(
                    f"[PoDRepo] Atomic OK | intercept={triplet.intercept_id[:8]} "
                    f"block=#{block.block_number} hash={block.block_hash[:12]}..."
                )
                return block

        except Exception as e:
            logger.error(f"[PoDRepo] seal_block_atomic FAILED: {e}")
            return None

    async def verify_chain(self, tenant_id: str) -> Dict[str, Any]:
        """
        Adapter used by PoDInterceptor.verify_chain_integrity() -- same gap
        as persist() above, different method name (verify_chain vs the
        actual run_integrity_verification).
        """
        return await self.run_integrity_verification(tenant_id)

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
                    _ledger_uid(tenant_id), from_block, to_block
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
                           ON pl.intercept_id::text = ii.intercept_id
                    WHERE  pl.decision_id = $1 AND pl.tenant_id = $2
                    """,
                    _ledger_uid(decision_id), _ledger_uid(tenant_id)
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
        verified_by: str = "cgc-pod-verifier",
        from_block: int = 0,
        to_block: int = 999_999_999
    ) -> Dict[str, Any]:
        """
        Chain integrity verification over [from_block, to_block] (default:
        the whole chain). Walks the range, verifies previous_hash linkage.
        Persists result to cgc_pod.chain_integrity_log.
        Returns audit report for legal submission.
        """
        start = time.monotonic()
        GENESIS = "0" * 64

        blocks = await self.get_chain_range(tenant_id, from_block, to_block)
        if not blocks:
            return {
                "tenant_id": tenant_id, "blocks_verified": 0,
                "integrity_passed": True, "broken_at_block": None,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "message": "Empty chain"
            }

        broken_at = None
        # A partial range that doesn't start at the true genesis block can
        # only verify internal linkage within the range -- the first
        # block's own previous_block_hash is trusted as the range's
        # starting point rather than assumed to be GENESIS.
        prev_hash = GENESIS if blocks[0]["block_number"] == 0 else blocks[0]["previous_block_hash"]
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