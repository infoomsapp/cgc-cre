"""
FlowScoring - business-flow read layer over cgc_tco.audit_trail.

Phase 1 of the CGC Core reinforcement plan: a read-only aggregation over
already-sealed governance decisions. No new capture point, no write path
touched - it can never corrupt a decision it didn't influence, since it only
reads what TCO has already persisted.

Scope, decided up front (see the reinforcement plan / project memory):
  - "Tenant" is app_source (ledgiproof / ledgiproof-tax-pro) by default -
    aggregation across the whole connected app. An optional `tenant_id`
    param narrows further to one organization within that app (real org
    UUIDs, threaded from LOOP.execute_governance_cycle's own `org_id`
    parameter since it was added to TCO.log_decision). Historical rows
    logged before that column existed are NULL and simply don't contribute
    to a tenant-scoped query - not a bug, no retroactive attribution.
  - Dashboard-only for this phase - flow_score does NOT feed back into
    DECISION_WEIGHTING_MATRIX. That's a deliberate, explicit decision, not
    an oversight - see the "flow-score gating" open question in the plan.
  - "Human-review load" is reported as an informational signal only, not
    scored - the plan itself frames it ambiguously (a high rate could mean
    healthy oversight or a rubber-stamping problem depending on context),
    so it isn't silently baked into a judgment call this module can't make.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.Core.db.database import get_database

logger = logging.getLogger("cgc.flow_scoring")

# Below this many decisions in the baseline window, drift/spike numbers are
# noise, not signal - report insufficient_data instead of a false-precision score.
MIN_BASELINE_SAMPLE = 10

_EMPTY_WINDOW = {
    "total": 0, "approved": 0, "high_sensitivity": 0, "human_review": 0,
    "avg_score": None, "score_stddev": None,
}

_WINDOW_QUERY_BASE = """
    SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE outcome = 'APPROVE') AS approved,
        COUNT(*) FILTER (WHERE sensitivity_level = 'HIGH') AS high_sensitivity,
        COUNT(*) FILTER (WHERE human_review_required = TRUE) AS human_review,
        AVG(aggregated_score) AS avg_score,
        STDDEV(aggregated_score) AS score_stddev
    FROM cgc_tco.audit_trail
    WHERE app_source = %s
      AND timestamp >= %s
      AND timestamp < %s
"""


def _iso(dt: datetime) -> str:
    # Matches TCO's own write-side format (datetime.utcnow().isoformat() + "Z"),
    # since timestamp is a TEXT column compared lexicographically, not cast.
    return dt.replace(tzinfo=None).isoformat() + "Z"


def _rate(numerator: int, denominator: int) -> Optional[float]:
    return (numerator / denominator) if denominator else None


class FlowScoring:
    def __init__(self):
        self._db = get_database()

    def _window_counts(
        self, app_source: str, start: datetime, end: datetime, tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        query = _WINDOW_QUERY_BASE
        params = [app_source, _iso(start), _iso(end)]
        if tenant_id:
            query += " AND tenant_id = %s"
            params.append(tenant_id)

        with self._db.get_connection() as conn:
            if conn is None:
                return dict(_EMPTY_WINDOW)
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            row = cursor.fetchone()
        return dict(row) if row else dict(_EMPTY_WINDOW)

    def compute_flow_score(
        self,
        app_source: str,
        window_days: int = 7,
        baseline_days: int = 30,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=window_days)
        baseline_start = window_start - timedelta(days=baseline_days)

        current = self._window_counts(app_source, window_start, now, tenant_id)
        baseline = self._window_counts(app_source, baseline_start, window_start, tenant_id)

        sample_sizes = {"current_total": current["total"], "baseline_total": baseline["total"]}

        if baseline["total"] < MIN_BASELINE_SAMPLE:
            return {
                "app_source": app_source,
                "tenant_id": tenant_id,
                "window_days": window_days,
                "baseline_days": baseline_days,
                "flow_score": None,
                "signals": {},
                "sample_sizes": sample_sizes,
                "insufficient_data": True,
            }

        current_approval_rate = _rate(current["approved"], current["total"])
        baseline_approval_rate = _rate(baseline["approved"], baseline["total"])
        current_high_sens_rate = _rate(current["high_sensitivity"], current["total"])
        baseline_high_sens_rate = _rate(baseline["high_sensitivity"], baseline["total"])
        current_review_rate = _rate(current["human_review"], current["total"])
        baseline_review_rate = _rate(baseline["human_review"], baseline["total"])

        current_stddev = float(current["score_stddev"]) if current["score_stddev"] is not None else None
        baseline_stddev = float(baseline["score_stddev"]) if baseline["score_stddev"] is not None else None
        current_avg_score = float(current["avg_score"]) if current["avg_score"] is not None else None
        baseline_avg_score = float(baseline["avg_score"]) if baseline["avg_score"] is not None else None

        current_velocity = current["total"] / window_days
        baseline_velocity = baseline["total"] / baseline_days

        penalties = {}

        # Approval drift - penalty only when the rate has dropped.
        if current_approval_rate is not None and baseline_approval_rate is not None:
            drift = baseline_approval_rate - current_approval_rate
            approval_penalty = min(max(drift, 0.0) * 100, 40)
        else:
            drift = None
            approval_penalty = 0
        penalties["approval_drift"] = approval_penalty

        # Velocity spike - penalty only when current running hotter than baseline.
        velocity_ratio = (current_velocity / baseline_velocity) if baseline_velocity > 0 else None
        if velocity_ratio is not None:
            velocity_penalty = min(max(velocity_ratio - 1.0, 0.0) * 20, 25)
        else:
            velocity_penalty = 0
        penalties["velocity_spike"] = velocity_penalty

        # Sensitivity creep - penalty only when the HIGH-sensitivity share is rising.
        if current_high_sens_rate is not None and baseline_high_sens_rate is not None:
            creep = current_high_sens_rate - baseline_high_sens_rate
            sensitivity_penalty = min(max(creep, 0.0) * 100, 20)
        else:
            creep = None
            sensitivity_penalty = 0
        penalties["sensitivity_creep"] = sensitivity_penalty

        # Score volatility - penalty only when current decisions are less
        # consistent (higher stddev) than baseline. Needs at least 2 scored
        # rows in each window for STDDEV to be non-NULL - if either window
        # has 0 or 1 scored rows this stays unscored (None), not zero.
        if current_stddev is not None and baseline_stddev is not None:
            volatility_delta = current_stddev - baseline_stddev
            volatility_penalty = min(max(volatility_delta, 0.0) * 100, 15)
        else:
            volatility_delta = None
            volatility_penalty = 0
        penalties["score_volatility"] = volatility_penalty

        flow_score = max(0, round(100 - sum(penalties.values())))

        review_delta = (
            (current_review_rate - baseline_review_rate)
            if current_review_rate is not None and baseline_review_rate is not None
            else None
        )

        return {
            "app_source": app_source,
            "tenant_id": tenant_id,
            "window_days": window_days,
            "baseline_days": baseline_days,
            "flow_score": flow_score,
            "signals": {
                "approval_drift": {
                    "current_rate": current_approval_rate,
                    "baseline_rate": baseline_approval_rate,
                    "delta": drift,
                    "penalty": approval_penalty,
                },
                "velocity_spike": {
                    "current_per_day": round(current_velocity, 2),
                    "baseline_per_day": round(baseline_velocity, 2),
                    "ratio": velocity_ratio,
                    "penalty": velocity_penalty,
                },
                "sensitivity_creep": {
                    "current_rate": current_high_sens_rate,
                    "baseline_rate": baseline_high_sens_rate,
                    "delta": creep,
                    "penalty": sensitivity_penalty,
                },
                "score_volatility": {
                    "current_stddev": current_stddev,
                    "baseline_stddev": baseline_stddev,
                    "current_avg_score": current_avg_score,
                    "baseline_avg_score": baseline_avg_score,
                    "delta": volatility_delta,
                    "penalty": volatility_penalty,
                },
                "human_review_load": {
                    "current_rate": current_review_rate,
                    "baseline_rate": baseline_review_rate,
                    "delta": review_delta,
                    "note": "informational only, not scored",
                },
            },
            "sample_sizes": sample_sizes,
            "insufficient_data": False,
        }
