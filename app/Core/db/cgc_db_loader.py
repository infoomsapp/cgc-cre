"""
CGC Core — DB Config Loader
Loads all governance matrices from Supabase at runtime.
Used by ECM, PFM, SDA, PAN, TCO to replace hardcoded dicts.

Each module calls:    loader.get_ecm("BANKING")
Instead of using:     INDUSTRIAL_CALIBRATION_MATRIX["BANKING"]

Connection: reads CGC_DATABASE_URL env var (Supabase connection string).
Falls back to bundled defaults if DB is unreachable.

Olympus Mont Systems LLC © 2026
"""

import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict, Optional

try:
    from app.Core.logging import get_logger
    logger = get_logger("cgc.db_loader")
except ImportError:
    logger = logging.getLogger("cgc.db_loader")

# psycopg2 for sync DB access (modules are sync)
try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    logger.warning("[DBLoader] psycopg2 not installed — pip install psycopg2-binary")


# ============================================================================
# BUNDLED FALLBACKS
# Minimal safe defaults when DB is unreachable.
# These are NOT the full matrices — modules will log a warning and
# operate in degraded mode until DB connection is restored.
# ============================================================================

_FALLBACK_ECM = {
    "DEFAULT": {
        "base_frameworks": {
            "transparency": 0.90, "fairness": 0.90, "accountability": 0.90,
            "privacy": 0.90, "security": 0.90, "compliance": 0.90,
            "sustainability": 0.80, "human_oversight": 0.90
        },
        "sensitivity_modulation": {
            "LOW":    {"multiplier": 1.0, "threshold": 0.80},
            "MEDIUM": {"multiplier": 0.97, "threshold": 0.85},
            "HIGH":   {"multiplier": 0.94, "threshold": 0.90}
        },
        "compliance_owner_bonus": 0.02,
        "critical_frameworks": ["accountability", "compliance"],
        "description": "Fallback — DB not reachable"
    }
}

_FALLBACK_PFM = {
    "DEFAULT": {
        "default_action": {
            "baseline_risk": 25,
            "sensitivity_multiplier": 1.2,
            "critical_factors": [],
            "success_probability_baseline": 0.85,
            "failure_modes": []
        }
    }
}

_FALLBACK_SDA = {
    "DEFAULT": {
        "data_requirements": [],
        "quality_factors": {},
        "risk_mitigations": [],
        "optimization_priorities": ["compliance", "security"]
    }
}

_FALLBACK_PAN = {
    "DEFAULT": {
        "keywords": [],
        "patterns": {},
        "sensitivity_multiplier": 1.0
    }
}

_FALLBACK_TCO = {
    "DEFAULT": {
        "retention_days": 365,
        "compression_enabled": True,
        "archival_required": False,
        "blockchain_sync": False,
        "tamper_detection_level": "MEDIUM",
        "description": "Fallback default"
    }
}


# ============================================================================
# DB LOADER
# ============================================================================

class CGCDBLoader:
    """
    Loads governance configuration matrices from Supabase PostgreSQL.
    All matrices are cached after first load (LRU, per governance area).
    Cache is invalidated on reload_all() — call this after config updates.
    """

    def __init__(self):
        self._conn = None
        self._cache: Dict[str, Dict] = {}
        self._loaded = False
        self._dsn = os.getenv(
            "CGC_DATABASE_URL",
            "postgresql://cgc_user:cgc_password@localhost:5432/cgc_core"
        )

    def _get_conn(self):
        """Get or create sync psycopg2 connection."""
        if not PSYCOPG2_AVAILABLE:
            return None
        try:
            if self._conn is None or self._conn.closed:
                dsn = self._dsn.split("?")[0]
                self._conn = psycopg2.connect(
                    self._dsn,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                    connect_timeout=5
                )
                self._conn.autocommit = True
            return self._conn
        except Exception as e:
            logger.error(f"[DBLoader] Connection failed: {e}")
            return None

    def _query(self, sql: str, params=None) -> list:
        conn = self._get_conn()
        if conn is None:
            return []
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall()
        except Exception as e:
            logger.error(f"[DBLoader] Query failed: {e}")
            return []

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC LOADERS — one per module
    # ─────────────────────────────────────────────────────────────────────────

    def get_ecm(self, area: str) -> Dict:
        """
        Returns ECM calibration config for a governance area.
        Replaces: INDUSTRIAL_CALIBRATION_MATRIX[area]
        """
        key = f"ecm_{area}"
        if key in self._cache:
            return self._cache[key]

        rows = self._query(
            """
            SELECT governance_area, base_frameworks, sensitivity_modulation,
                   compliance_owner_bonus, critical_frameworks, description
            FROM   cgc_jla.ecm_calibration
            WHERE  governance_area = %s AND is_active = TRUE
            LIMIT  1
            """,
            (area,)
        )

        if rows:
            row = dict(rows[0])
            result = {
                "base_frameworks":        row["base_frameworks"],
                "sensitivity_modulation": row["sensitivity_modulation"],
                "compliance_owner_bonus": float(row["compliance_owner_bonus"]),
                "critical_frameworks":    row["critical_frameworks"],
                "description":            row.get("description", "")
            }
            self._cache[key] = result
            return result

        logger.warning(f"[DBLoader] ECM not found for area={area}, using DEFAULT fallback")
        fallback = _FALLBACK_ECM.get(area, _FALLBACK_ECM["DEFAULT"])
        self._cache[key] = fallback
        return fallback

    def get_pfm(self, area: str, action: str) -> Dict:
        """
        Returns PFM risk model for an area + action combination.
        Replaces: RISK_MODELS[area][action]
        """
        key = f"pfm_{area}_{action}"
        if key in self._cache:
            return self._cache[key]

        rows = self._query(
            """
            SELECT action_type, baseline_risk, sensitivity_multiplier,
                   critical_factors, success_probability_baseline, failure_modes
            FROM   cgc_jla.pfm_risk_models
            WHERE  governance_area = %s
              AND  (action_type = %s OR action_type = 'default_action')
              AND  is_active = TRUE
            ORDER  BY (action_type = %s) DESC
            LIMIT  1
            """,
            (area, action, action)
        )

        if rows:
            row = dict(rows[0])
            result = {
                "baseline_risk":               row["baseline_risk"],
                "sensitivity_multiplier":      float(row["sensitivity_multiplier"]),
                "critical_factors":            row["critical_factors"],
                "success_probability_baseline": float(row["success_probability_baseline"] or 0.85),
                "failure_modes":               row["failure_modes"]
            }
            self._cache[key] = result
            return result

        logger.warning(f"[DBLoader] PFM not found for area={area} action={action}, fallback")
        fallback = _FALLBACK_PFM.get(area, _FALLBACK_PFM["DEFAULT"])
        default_action = next(iter(fallback.values()))
        self._cache[key] = default_action
        return default_action

    def get_sda(self, area: str) -> Dict:
        """
        Returns SDA best practices for an area.
        Replaces: AREA_BEST_PRACTICES[area]
        """
        key = f"sda_{area}"
        if key in self._cache:
            return self._cache[key]

        rows = self._query(
            """
            SELECT data_requirements, quality_factors,
                   risk_mitigations, optimization_priorities
            FROM   cgc_jla.sda_best_practices
            WHERE  governance_area = %s AND is_active = TRUE
            LIMIT  1
            """,
            (area,)
        )

        if rows:
            row = dict(rows[0])
            result = {
                "data_requirements":       row["data_requirements"],
                "quality_factors":         row["quality_factors"],
                "risk_mitigations":        row["risk_mitigations"],
                "optimization_priorities": row["optimization_priorities"]
            }
            self._cache[key] = result
            return result

        logger.warning(f"[DBLoader] SDA not found for area={area}, using DEFAULT fallback")
        self._cache[key] = _FALLBACK_SDA.get(area, _FALLBACK_SDA["DEFAULT"])
        return self._cache[key]

    def get_pan(self, area: str) -> Dict:
        """
        Returns PAN domain patterns for an area.
        Replaces: DOMAIN_PATTERNS[area]
        """
        key = f"pan_{area}"
        if key in self._cache:
            return self._cache[key]

        rows = self._query(
            """
            SELECT keywords, patterns, sensitivity_multiplier
            FROM   cgc_jla.pan_domain_patterns
            WHERE  governance_area = %s AND is_active = TRUE
            LIMIT  1
            """,
            (area,)
        )

        if rows:
            row = dict(rows[0])
            result = {
                "keywords":               row["keywords"],
                "patterns":               row["patterns"],
                "sensitivity_multiplier": float(row["sensitivity_multiplier"])
            }
            self._cache[key] = result
            return result

        logger.warning(f"[DBLoader] PAN not found for area={area}, using DEFAULT fallback")
        self._cache[key] = _FALLBACK_PAN.get(area, _FALLBACK_PAN["DEFAULT"])
        return self._cache[key]

    def get_tco(self, area: str) -> Dict:
        """
        Returns TCO retention policy for an area.
        Replaces: AUDIT_RETENTION_POLICIES[area]
        """
        key = f"tco_{area}"
        if key in self._cache:
            return self._cache[key]

        rows = self._query(
            """
            SELECT retention_days, compression_enabled, archival_required,
                   blockchain_sync, tamper_detection_level, description
            FROM   cgc_jla.tco_retention_policies
            WHERE  governance_area = %s AND is_active = TRUE
            LIMIT  1
            """,
            (area,)
        )

        if rows:
            row = dict(rows[0])
            result = dict(row)
            self._cache[key] = result
            return result

        logger.warning(f"[DBLoader] TCO not found for area={area}, using DEFAULT fallback")
        self._cache[key] = _FALLBACK_TCO.get(area, _FALLBACK_TCO["DEFAULT"])
        return self._cache[key]

    def reload_all(self) -> None:
        """
        Clear the cache — forces fresh DB reads on next access.
        Call this after updating config in Supabase without redeploying.
        """
        self._cache.clear()
        logger.info("[DBLoader] Cache cleared — matrices will reload from DB on next access")

    def health_check(self) -> Dict:
        """Returns DB connectivity status for health endpoint."""
        conn = self._get_conn()
        if conn is None:
            return {"status": "DEGRADED", "db": "unreachable", "fallback": "active"}
        try:
            rows = self._query("SELECT COUNT(*) AS c FROM cgc_jla.ecm_calibration")
            count = rows[0]["c"] if rows else 0
            return {"status": "OK", "db": "connected", "ecm_rows": count}
        except Exception as e:
            return {"status": "DEGRADED", "db": str(e), "fallback": "active"}


# ============================================================================
# SINGLETON
# ============================================================================

_loader_instance: Optional[CGCDBLoader] = None

def get_db_loader() -> CGCDBLoader:
    """
    Get the singleton CGCDBLoader.
    Import and call this in any module instead of using the hardcoded dict.

    Example:
        from app.Core.db.cgc_db_loader import get_db_loader
        loader = get_db_loader()
        config = loader.get_ecm("BANKING")
    """
    global _loader_instance
    if _loader_instance is None:
        _loader_instance = CGCDBLoader()
    return _loader_instance