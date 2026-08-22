"""
GET /api/v1/verify/{decision_id}

Forensic endpoint: cryptographic proof of any AI decision.
Returns the PoD block, triplet hash, RSA signature, and chain status.
This is the "30-second demo" for auditors and enterprise clients.

Deliberately unauthenticated by design (gated only by knowing the real
decision_id + tenant_id, not a bearer token) -- "any auditor holding the
decision_id can verify" is this endpoint's whole point, not an oversight.
"""

from fastapi import APIRouter, HTTPException, Header, Query
from fastapi.responses import JSONResponse
from typing import Optional
from datetime import datetime, timezone

from app.modules.pod.pod_repository import get_pod_repository
from app.modules.tco.tcomodule import TCO

router = APIRouter()

# Module-level singleton, constructed once at import time and reused across
# every request -- this endpoint is deliberately unauthenticated (see below),
# so it's exposed to more casual/higher-volume traffic than the authenticated
# routes, and used to instantiate a brand-new TCO() (re-copying retention
# policy dicts etc.) on every single call for no reason. Same lazy-singleton
# shape as get_pod_repository() just below.
_tco = TCO()


@router.get(
    "/{decision_id}",
    summary="Verify an AI decision",
    description="""
    Returns full cryptographic proof of a governance decision.
    Includes: PoD block hash, triplet signature, RFC 3161 timestamp,
    position in the immutable chain, and tamper-detection status.
    """,
    response_description="Forensic audit record with non-repudiation proof"
)
async def verify_decision(
    decision_id: str,
    x_tenant_id: str = Header(..., description="Client tenant ID"),
    include_chain_proof: bool = Query(False, description="Include the full chain position")
):
    """
    Main forensic endpoint.
    Any auditor holding the decision_id can verify:
    - Which AI model made the decision
    - Exactly when (pre-delivery timestamp)
    - What the outcome was
    - That the record hasn't been altered (chain integrity)

    Merges two independent, already-existing, already-correct sources --
    PoDRepository.forensic_lookup() (crypto proof + chain position, from
    cgc_pod.*) and TCO.get_decision_audit() (the governance artifact --
    action/area/sensitivity/outcome/score -- from cgc_tco.audit_trail).
    Either can be legitimately missing (e.g. a decision whose PoD seal
    failed but whose TCO log succeeded, since main.py's seal_intercept
    call is itself fail-open) -- whatever is real gets returned, nothing
    is fabricated to fill a gap.
    """
    repo = get_pod_repository()
    pod_record = await repo.forensic_lookup(decision_id, x_tenant_id)

    # TCO.get_decision_audit() looks up by decision_id alone (no tenant
    # scoping of its own) -- enforce tenant isolation here explicitly so
    # this public, unauthenticated-by-design endpoint can't be used to
    # read another tenant's governance record just by guessing a
    # decision_id and claiming a different x_tenant_id.
    tco_result = _tco.get_decision_audit(decision_id)
    tco_entry = None
    if tco_result.get("found") and tco_result["audit_entry"].get("tenant_id") == x_tenant_id:
        tco_entry = tco_result["audit_entry"]

    if pod_record is None and tco_entry is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "decision_not_found",
                "decision_id": decision_id,
                "message": "No decision found for this tenant"
            }
        )

    response = {
        "decision_id": decision_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),

        # Governance result -- real fields only, from cgc_tco.audit_trail.
        # approval_threshold/judge_version/processing_time_ms were never
        # persisted anywhere; omitted rather than returned as null in a
        # way that implies they were ever tracked.
        "governance": {
            "action":            tco_entry.get("action") if tco_entry else None,
            "area":               tco_entry.get("area") if tco_entry else None,
            "sensitivity_level":  tco_entry.get("sensitivity_level") if tco_entry else None,
            "outcome":            tco_entry.get("outcome") if tco_entry else (
                pod_record["governance"]["outcome"] if pod_record else None
            ),
            "aggregated_score":   float(tco_entry["aggregated_score"]) if tco_entry and tco_entry.get("aggregated_score") is not None else None,
            "decided_at":         tco_entry.get("timestamp") if tco_entry else None,
        } if (tco_entry or pod_record) else None,

        # Cryptographic proof (PoD Patent 1) -- from cgc_pod.*
        "proof_of_decision": {
            "triplet_hash":       pod_record["proof"]["triplet_hash"],
            "triplet_signature":  pod_record["proof"]["triplet_signature"],
            "model_identifier":   pod_record["proof"]["model_identifier"],
            "timestamp_token":    pod_record["proof"]["timestamp_token"],
            "non_repudiation":    pod_record["non_repudiation"],
        } if pod_record else None,

        # Chain position -- from cgc_pod.pod_ledger
        "chain": {
            "block_number":  pod_record["chain"]["block_number"],
            "previous_hash": pod_record["chain"]["previous_hash"],
            "block_hash":    pod_record["chain"]["block_hash"],
            "sealed_at":     pod_record["chain"]["sealed_at"],
            "tamper_detected": pod_record["chain"]["tamper_detected"],
        } if pod_record else None,
    }

    if include_chain_proof and pod_record is not None:
        block_number = pod_record["chain"]["block_number"]
        chain_rows = await repo.get_chain_range(
            x_tenant_id, max(0, block_number - 5), block_number
        )
        response["chain_proof"] = [
            {
                "block_number":      r["block_number"],
                "block_hash":        r["block_hash"],
                "previous_block_hash": r["previous_block_hash"],
                "outcome":           r["governance_outcome"],
                "sealed_at":         str(r["sealed_at"]),
                "tamper_detected":   r["tamper_detected"],
            }
            for r in chain_rows
        ]

    return JSONResponse(content=response)


@router.get(
    "/chain/integrity",
    summary="Verify the integrity of the whole PoD chain",
    description="Walks every block for the tenant and verifies hash linkage."
)
async def verify_chain_integrity(
    x_tenant_id: str = Header(..., description="Tenant ID"),
    from_block: int = Query(0, description="Starting block"),
    to_block: int = Query(999999999, description="Ending block")
):
    """
    Verifies that no block in the PoD chain has been altered.
    Returns integrity_passed: true/false and the block where the first
    break was detected, if any. Delegates to PoDRepository's own
    run_integrity_verification(), which already does this correctly
    against the real cgc_pod.pod_ledger table and already persists the
    result to cgc_pod.chain_integrity_log.

    Note: run_integrity_verification()'s from_block/to_block params were
    added in the earlier (reverted) PoD block-sequencing pass -- if that
    signature isn't present (i.e. this endpoint is deployed without
    Step 4 of the post-incident plan), this falls back to the tenant's
    full range with a TypeError guard rather than assuming it's there.
    """
    try:
        try:
            return await get_pod_repository().run_integrity_verification(
                tenant_id=x_tenant_id, from_block=from_block, to_block=to_block
            )
        except TypeError:
            return await get_pod_repository().run_integrity_verification(
                tenant_id=x_tenant_id
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
