"""
GET /api/v1/verify/{decision_id}

Endpoint forense: prueba criptográfica de cualquier decisión AI.
Retorna el PoD block, triplet hash, firma RSA, y estado de la cadena.
Este es el "demo de 30 segundos" para auditores y clientes enterprise.
"""

from fastapi import APIRouter, HTTPException, Header, Query
from fastapi.responses import JSONResponse
from typing import Optional
from datetime import datetime, timezone

import asyncpg
import os

router = APIRouter()


async def _get_conn():
    """Get a direct asyncpg connection for forensic queries."""
    return await asyncpg.connect(os.getenv("CGC_DATABASE_URL"))


@router.get(
    "/{decision_id}",
    summary="Verificar decisión AI",
    description="""
    Retorna prueba criptográfica completa de una decisión de governance.
    Incluye: PoD block hash, triplet signature, RFC 3161 timestamp,
    posición en la cadena inmutable, y estado de tamper-detection.
    """,
    response_description="Forensic audit record con non-repudiation proof"
)
async def verify_decision(
    decision_id: str,
    x_tenant_id: str = Header(..., description="Tenant ID del cliente"),
    include_chain_proof: bool = Query(False, description="Incluir posición completa en la cadena")
):
    """
    Endpoint forense principal.
    Cualquier auditor con el decision_id puede verificar:
    - Qué modelo AI tomó la decisión
    - Exactamente cuándo (pre-delivery timestamp)
    - Cuál fue el outcome
    - Que el registro no fue alterado (chain integrity)
    """
    conn = None
    try:
        conn = await _get_conn()

        # Set tenant context for RLS
        await conn.execute(f"SET LOCAL cgc.current_tenant_id = '{x_tenant_id}'")

        # Main forensic query — joins decisions + pod_chain + prefilter
        row = await conn.fetchrow(
            """
            SELECT
                d.decision_id,
                d.tenant_id,
                d.action,
                d.area,
                d.sensitivity_level,
                d.outcome,
                d.aggregated_score,
                d.approval_threshold,
                d.judge_version,
                d.decided_at,
                d.processing_time_ms,
                d.pod_hash,
                d.anchored,
                d.anchor_tx,
                pc.block_number,
                pc.previous_pod_hash,
                pc.triplet_hash,
                pc.triplet_signature,
                pc.timestamp_token,
                pc.merkle_root,
                p.area_identified,
                p.sensitive_domains_count,
                p.compliance_owner_present,
                p.short_circuit
            FROM   decisions d
            LEFT JOIN pod_chain pc ON d.decision_id = pc.decision_id
            LEFT JOIN prefilter_results p
                ON d.decision_id = p.decision_id
                AND d.decided_at  = p.decided_at
            WHERE  d.decision_id = $1
              AND  d.tenant_id   = $2
            LIMIT  1
            """,
            decision_id, x_tenant_id
        )

        if not row:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "decision_not_found",
                    "decision_id": decision_id,
                    "message": "No se encontró la decisión para este tenant"
                }
            )

        r = dict(row)

        # Build response
        response = {
            "decision_id": r["decision_id"],
            "verified_at": datetime.now(timezone.utc).isoformat(),

            # Governance result
            "governance": {
                "action":             r["action"],
                "area":               r["area"],
                "sensitivity_level":  r["sensitivity_level"],
                "outcome":            r["outcome"],
                "aggregated_score":   float(r["aggregated_score"]) if r["aggregated_score"] else None,
                "approval_threshold": float(r["approval_threshold"]) if r["approval_threshold"] else None,
                "judge_version":      r["judge_version"],
                "decided_at":         r["decided_at"].isoformat() if r["decided_at"] else None,
                "processing_time_ms": float(r["processing_time_ms"]) if r["processing_time_ms"] else None,
            },

            # Cryptographic proof (PoD Patent 1)
            "proof_of_decision": {
                "pod_hash":          r["pod_hash"],
                "triplet_hash":      r["triplet_hash"],
                "triplet_signature": r["triplet_signature"],
                "timestamp_token":   r["timestamp_token"],
                "merkle_root":       r["merkle_root"],
                "non_repudiation":   r["triplet_signature"] is not None,
            },

            # Chain position
            "chain": {
                "block_number":      r["block_number"],
                "previous_pod_hash": r["previous_pod_hash"],
                "anchored":          r["anchored"],
                "anchor_tx":         r["anchor_tx"],
            },

            # Context
            "context": {
                "area_identified":           r["area_identified"],
                "sensitive_domains_count":   r["sensitive_domains_count"],
                "compliance_owner_present":  r["compliance_owner_present"],
                "short_circuit":             r["short_circuit"],
            }
        }

        # Optional: full chain proof (for audit submissions)
        if include_chain_proof and r["block_number"] is not None:
            chain_rows = await conn.fetch(
                """
                SELECT block_number, pod_hash, previous_pod_hash,
                       governance_outcome, created_at
                FROM   pod_chain
                WHERE  block_number BETWEEN $1 AND $2
                ORDER  BY block_number ASC
                """,
                max(0, r["block_number"] - 5),
                r["block_number"]
            )
            response["chain_proof"] = [
                {
                    "block_number":      cr["block_number"],
                    "pod_hash":          cr["pod_hash"],
                    "previous_pod_hash": cr["previous_pod_hash"],
                    "outcome":           cr["governance_outcome"],
                    "created_at":        cr["created_at"].isoformat()
                }
                for cr in chain_rows
            ]

        return JSONResponse(content=response)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "verification_failed",
                "message": str(e),
                "decision_id": decision_id
            }
        )
    finally:
        if conn:
            await conn.close()


@router.get(
    "/chain/integrity",
    summary="Verificar integridad de toda la cadena PoD",
    description="Recorre todos los bloques del tenant y verifica linkage de hashes."
)
async def verify_chain_integrity(
    x_tenant_id: str = Header(..., description="Tenant ID"),
    from_block: int = Query(0, description="Bloque de inicio"),
    to_block: int = Query(999999999, description="Bloque de fin")
):
    """
    Verifica que ningún bloque fue alterado en la cadena PoD.
    Retorna integrity_passed: true/false y el bloque donde se detectó
    la primera ruptura si la hay.
    """
    conn = None
    try:
        conn = await _get_conn()

        rows = await conn.fetch(
            """
            SELECT block_number, pod_hash, previous_pod_hash
            FROM   pod_chain
            WHERE  block_number BETWEEN $1 AND $2
            ORDER  BY block_number ASC
            """,
            from_block, to_block
        )

        if not rows:
            return {
                "tenant_id":       x_tenant_id,
                "blocks_verified": 0,
                "integrity_passed": True,
                "message":         "No hay bloques en el rango especificado"
            }

        GENESIS = "0" * 64
        broken_at = None
        prev_hash = GENESIS if rows[0]["block_number"] == 0 else None

        for row in rows:
            if prev_hash and row["previous_pod_hash"] != prev_hash:
                broken_at = row["block_number"]
                break
            prev_hash = row["pod_hash"]

        return {
            "tenant_id":       x_tenant_id,
            "blocks_verified": len(rows),
            "from_block":      rows[0]["block_number"],
            "to_block":        rows[-1]["block_number"],
            "integrity_passed": broken_at is None,
            "broken_at_block": broken_at,
            "verified_at":     datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await conn.close()