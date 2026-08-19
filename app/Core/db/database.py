"""
CGC CORE Database Layer
PostgreSQL + JSON fallback (dev only)
Production-ready with governance tables
OlympusMont Systems LLC  2025
"""

import os
import json
import time
import logging
import hashlib
from typing import Dict, Optional, List, Any
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
import threading
import re
# PostgreSQL
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor, Json
    from psycopg2 import pool
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

logger = logging.getLogger("cgc.database")


class DatabaseError(Exception):
    """Custom database errors."""


class Database:
    """ database interface for CGC CORE governance data."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Database, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.postgres_url = os.getenv('DATABASE_URL')
        self.use_postgres = False
        self.data_dir = 'data'
        self.json_lock = threading.Lock()
        
        self._init_connection()
        self._create_tables()
        self._create_jla_schema()

        logger.info(f"Database initialized: {'PostgreSQL' if self.use_postgres else 'JSON (dev)'}")

    def _init_connection(self):
        """Initialize PostgreSQL connection pool or JSON fallback."""
        if self.postgres_url and POSTGRES_AVAILABLE:
            try:
                # Connection pool for production
                self.pool = pool.ThreadedConnectionPool(
                    1, 20, self.postgres_url,
                    connection_factory=psycopg2.extras.RealDictConnection
                )
                self.use_postgres = True
                logger.info("PostgreSQL connection pool active")
                return
            except Exception as e:
                logger.warning(f"PostgreSQL failed, using JSON: {e}")
        
        # JSON fallback (development only)
        self.use_postgres = False
        os.makedirs(self.data_dir, exist_ok=True)
        self._init_json_files()
        logger.warning("JSON fallback active (DEVELOPMENT ONLY)")

    def _init_json_files(self):
        """Initialize JSON files for fallback mode."""
        files = {
            'users.json': {},
            'sessions.json': {},
            'tenants.json': {},
            'prefilter_results.json': [],
            'module_results.json': [],
            'loop_decisions.json': [],
            'feedback.json': [],
            'audit_traces.json': [],
            'error_reports.json': []
        }
        for filename, default in files.items():
            filepath = os.path.join(self.data_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    json.dump(default, f, indent=2)

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        if self.use_postgres:
            conn = self.pool.getconn()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                self.pool.putconn(conn)
        else:
            yield None

    def _create_tables(self):
        """Create all CGC governance tables."""
        if not self.use_postgres:
            return
            
        with self.get_connection() as conn:
            cur = conn.cursor()
            
            # Identity & Access tables
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) PRIMARY KEY,
                    password_hash VARCHAR(255) NOT NULL,
                    name VARCHAR(255),
                    role VARCHAR(50) DEFAULT 'user',
                    tenant_id VARCHAR(255),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    last_login TIMESTAMP WITH TIME ZONE
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id VARCHAR(255) PRIMARY KEY,
                    org_name VARCHAR(255) NOT NULL,
                    plan VARCHAR(50) DEFAULT 'basic',
                    api_key VARCHAR(255),
                    status VARCHAR(50) DEFAULT 'active',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(255) PRIMARY KEY,
                    email VARCHAR(255) NOT NULL REFERENCES users(email),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    expires_at TIMESTAMP WITH TIME ZONE
                )
            """)
            
            # CGC GOVERNANCE TABLES
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_prefilter_results (
                    decision_id VARCHAR(255) PRIMARY KEY,
                    correlation_id VARCHAR(255),
                    area VARCHAR(50),
                    outcome VARCHAR(20),
                    sensitive_count INT DEFAULT 0,
                    agent_id VARCHAR(255),
                    metrics JSONB,
                    latency_ms FLOAT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_module_results (
                    id BIGSERIAL PRIMARY KEY,
                    decision_id VARCHAR(255) REFERENCES cgc_prefilter_results(decision_id),
                    module_name VARCHAR(20),
                    scores JSONB,
                    approved BOOLEAN,
                    latency_ms FLOAT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_loop_decisions (
                    decision_id VARCHAR(255) PRIMARY KEY,
                    prefilter_result JSONB,
                    module_scores JSONB,
                    final_outcome VARCHAR(20),
                    risk_level VARCHAR(20),
                    ethical_score FLOAT,
                    policy_version VARCHAR(50),
                    signed_artifact_hash VARCHAR(128),
                    confidence FLOAT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_feedback (
                    id BIGSERIAL PRIMARY KEY,
                    decision_id VARCHAR(255),
                    source_type VARCHAR(20),
                    feedback_type VARCHAR(50),
                    feedback_data JSONB,
                    processed BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_audit_traces (
                    id BIGSERIAL PRIMARY KEY,
                    decision_id VARCHAR(255) REFERENCES cgc_prefilter_results(decision_id),
                    block_hash VARCHAR(128),
                    block_number BIGINT,
                    immutable BOOLEAN DEFAULT TRUE,
                    verified BOOLEAN DEFAULT TRUE,
                    merkle_root VARCHAR(128),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            # APPLICATION MONITORING (LedgiProof + LedgiProof Tax Pro client error reports —
            # separate concern from the governance/decision tables above: this is plain
            # crash telemetry, not a governed decision)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_error_reports (
                    fingerprint  VARCHAR(32) PRIMARY KEY,
                    app_source   VARCHAR(50) NOT NULL,
                    environment  VARCHAR(20) DEFAULT 'production',
                    severity     VARCHAR(20) DEFAULT 'error',
                    message      TEXT NOT NULL,
                    stack        TEXT,
                    url          TEXT,
                    user_agent   TEXT,
                    context      JSONB,
                    count        INT DEFAULT 1,
                    resolved     BOOLEAN DEFAULT FALSE,
                    first_seen   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    last_seen    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)

            conn.commit()
            logger.info("All CGC governance tables created/verified")

    def _create_jla_schema(self):
        """
        Governance calibration matrices (ECM/PFM/SDA/PAN/SCM), read at runtime
        by CGCDBLoader (app/Core/db/cgc_db_loader.py) instead of the hardcoded
        dicts it falls back to when this schema is unreachable. This schema
        never existed in any database before -- CGC_DATABASE_URL was never
        set, so every module silently ran on the single generic DEFAULT
        fallback (confirmed by boot logs: "PFM v3.0.0 initialized with 1
        risk models", same for PAN/SDA). Seeded here with the EXACT SAME
        values as those Python fallback constants (a mechanical port, not
        new calibration judgment) so behavior is unchanged today; real
        per-area tuning (BANKING, HEALTHCARE, etc.) can now be added via
        this schema without a redeploy.
        """
        if not self.use_postgres:
            return

        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("CREATE SCHEMA IF NOT EXISTS cgc_jla")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.ecm_calibration (
                    id                      SERIAL PRIMARY KEY,
                    governance_area         VARCHAR(50) NOT NULL UNIQUE,
                    base_frameworks         JSONB NOT NULL,
                    sensitivity_modulation  JSONB NOT NULL,
                    compliance_owner_bonus  NUMERIC NOT NULL,
                    critical_frameworks     JSONB NOT NULL,
                    description             TEXT,
                    is_active               BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.pfm_risk_models (
                    id                            SERIAL PRIMARY KEY,
                    governance_area               VARCHAR(50) NOT NULL,
                    action_type                    VARCHAR(50) NOT NULL,
                    baseline_risk                  INT NOT NULL,
                    sensitivity_multiplier         NUMERIC NOT NULL,
                    critical_factors               JSONB NOT NULL DEFAULT '[]',
                    success_probability_baseline   NUMERIC,
                    failure_modes                  JSONB NOT NULL DEFAULT '[]',
                    is_active                      BOOLEAN NOT NULL DEFAULT TRUE,
                    UNIQUE (governance_area, action_type)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.sda_best_practices (
                    id                        SERIAL PRIMARY KEY,
                    governance_area           VARCHAR(50) NOT NULL UNIQUE,
                    data_requirements         JSONB NOT NULL DEFAULT '[]',
                    quality_factors           JSONB NOT NULL DEFAULT '{}',
                    risk_mitigations          JSONB NOT NULL DEFAULT '[]',
                    optimization_priorities   JSONB NOT NULL DEFAULT '[]',
                    is_active                 BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.pan_domain_patterns (
                    id                       SERIAL PRIMARY KEY,
                    governance_area          VARCHAR(50) NOT NULL UNIQUE,
                    keywords                 JSONB NOT NULL DEFAULT '[]',
                    patterns                 JSONB NOT NULL DEFAULT '{}',
                    sensitivity_multiplier   NUMERIC NOT NULL DEFAULT 1.0,
                    is_active                BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.tco_retention_policies (
                    id                       SERIAL PRIMARY KEY,
                    governance_area          VARCHAR(50) NOT NULL UNIQUE,
                    retention_days           INT NOT NULL DEFAULT 365,
                    compression_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
                    archival_required        BOOLEAN NOT NULL DEFAULT FALSE,
                    blockchain_sync          BOOLEAN NOT NULL DEFAULT FALSE,
                    tamper_detection_level   VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
                    description              TEXT,
                    is_active                BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.scm_security_policies (
                    id                             SERIAL PRIMARY KEY,
                    governance_area                VARCHAR(50) NOT NULL UNIQUE,
                    encryption_required             BOOLEAN NOT NULL DEFAULT TRUE,
                    signing_required                BOOLEAN NOT NULL DEFAULT TRUE,
                    fingerprint_required             BOOLEAN NOT NULL DEFAULT FALSE,
                    min_key_rotation_days            INT NOT NULL DEFAULT 90,
                    audit_log_required               BOOLEAN NOT NULL DEFAULT TRUE,
                    chain_validation_strict          BOOLEAN NOT NULL DEFAULT FALSE,
                    hash_algorithm                   VARCHAR(20) NOT NULL DEFAULT 'sha256',
                    signing_algorithm                VARCHAR(30) NOT NULL DEFAULT 'rsa_pss_2048',
                    double_encryption_threshold      INT NOT NULL DEFAULT 5,
                    audit_retention_years            INT NOT NULL DEFAULT 2,
                    description                      TEXT,
                    is_active                        BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.scm_sensitivity_config (
                    id                             SERIAL PRIMARY KEY,
                    sensitivity_level              VARCHAR(20) NOT NULL UNIQUE,
                    additional_encryption          BOOLEAN NOT NULL,
                    compression_enabled            BOOLEAN NOT NULL,
                    include_metadata               BOOLEAN NOT NULL,
                    ttl_hours                      INT NOT NULL,
                    require_compliance_owner_sig   BOOLEAN NOT NULL,
                    is_active                      BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cgc_jla.scm_compliance_standards (
                    id          SERIAL PRIMARY KEY,
                    standard    VARCHAR(50) NOT NULL UNIQUE,
                    is_active   BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)

            # Seed DEFAULT rows -- exact port of cgc_db_loader.py's
            # _FALLBACK_* dicts and scmmodule.py's inline fallback dicts.
            cur.execute("""
                INSERT INTO cgc_jla.ecm_calibration
                    (governance_area, base_frameworks, sensitivity_modulation,
                     compliance_owner_bonus, critical_frameworks, description)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (governance_area) DO NOTHING
            """, (
                "DEFAULT",
                Json({
                    "transparency": 0.90, "fairness": 0.90, "accountability": 0.90,
                    "privacy": 0.90, "security": 0.90, "compliance": 0.90,
                    "sustainability": 0.80, "human_oversight": 0.90
                }),
                Json({
                    "LOW":    {"multiplier": 1.0, "threshold": 0.80},
                    "MEDIUM": {"multiplier": 0.97, "threshold": 0.85},
                    "HIGH":   {"multiplier": 0.94, "threshold": 0.90}
                }),
                0.02,
                Json(["accountability", "compliance"]),
                "Default calibration (seeded from code fallback)"
            ))

            cur.execute("""
                INSERT INTO cgc_jla.pfm_risk_models
                    (governance_area, action_type, baseline_risk, sensitivity_multiplier,
                     critical_factors, success_probability_baseline, failure_modes)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (governance_area, action_type) DO NOTHING
            """, ("DEFAULT", "default_action", 25, 1.2, Json([]), 0.85, Json([])))

            cur.execute("""
                INSERT INTO cgc_jla.sda_best_practices
                    (governance_area, data_requirements, quality_factors,
                     risk_mitigations, optimization_priorities)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (governance_area) DO NOTHING
            """, ("DEFAULT", Json([]), Json({}), Json([]), Json(["compliance", "security"])))

            cur.execute("""
                INSERT INTO cgc_jla.pan_domain_patterns
                    (governance_area, keywords, patterns, sensitivity_multiplier)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (governance_area) DO NOTHING
            """, ("DEFAULT", Json([]), Json({}), 1.0))

            cur.execute("""
                INSERT INTO cgc_jla.tco_retention_policies
                    (governance_area, retention_days, compression_enabled,
                     archival_required, blockchain_sync, tamper_detection_level, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (governance_area) DO NOTHING
            """, ("DEFAULT", 365, True, False, False, "MEDIUM",
                  "Default retention policy (seeded from code fallback)"))

            cur.execute("""
                INSERT INTO cgc_jla.scm_security_policies
                    (governance_area, encryption_required, signing_required,
                     fingerprint_required, min_key_rotation_days, audit_log_required,
                     chain_validation_strict, hash_algorithm, signing_algorithm,
                     double_encryption_threshold, audit_retention_years, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (governance_area) DO NOTHING
            """, ("DEFAULT", True, True, False, 90, True, False,
                  "sha256", "rsa_pss_2048", 5, 2,
                  "Fallback default policy (seeded from code fallback)"))

            sensitivity_rows = [
                ("LOW",    False, True,  False, 24, False),
                ("MEDIUM", False, False, True,  12, False),
                ("HIGH",   True,  False, True,  6,  True),
            ]
            for level, add_enc, compression, metadata, ttl, req_sig in sensitivity_rows:
                cur.execute("""
                    INSERT INTO cgc_jla.scm_sensitivity_config
                        (sensitivity_level, additional_encryption, compression_enabled,
                         include_metadata, ttl_hours, require_compliance_owner_sig)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (sensitivity_level) DO NOTHING
                """, (level, add_enc, compression, metadata, ttl, req_sig))

            standards = ["FIPS-140-2", "SOC2-Type2", "ISO27001", "HIPAA",
                         "PCI-DSS-v3.2.1", "EU-GDPR", "EU-AI-Act"]
            for standard in standards:
                cur.execute("""
                    INSERT INTO cgc_jla.scm_compliance_standards (standard)
                    VALUES (%s)
                    ON CONFLICT (standard) DO NOTHING
                """, (standard,))

            conn.commit()
            logger.info("cgc_jla governance calibration schema created/verified + seeded")

    # ======================================================================
    # IDENTITY & ACCESS (para AuthSystem)
    # ======================================================================
    
    def get_user(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                    row = cur.fetchone()
                    return dict(row) if row else None
        else:
            with self.json_lock:
                users = self._read_json('users.json')
                return users.get(email)
    
    def save_user(self, email: str, user_data: Dict[str, Any]) -> bool:
        """Create or update user."""
        required = {'password_hash'}
        if not all(k in user_data for k in required):
            raise DatabaseError(f"Missing required fields: {required}")
            
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (email, password_hash, name, role, tenant_id, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (email) DO UPDATE SET
                        password_hash = EXCLUDED.password_hash,
                        name = EXCLUDED.name,
                        role = EXCLUDED.role,
                        tenant_id = EXCLUDED.tenant_id,
                        last_login = NOW()
                    """, (
                        email, user_data['password_hash'],
                        user_data.get('name'), user_data.get('role', 'user'),
                        user_data.get('tenant_id'), user_data.get('created_at')
                    ))
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                users = self._read_json('users.json')
                users[email] = user_data
                self._write_json('users.json', users)
                return True
    
    def update_user_login(self, email: str) -> bool:
        """Update last_login timestamp."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET last_login = NOW() WHERE email = %s",
                        (email,)
                    )
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                users = self._read_json('users.json')
                if email in users:
                    users[email]['last_login'] = datetime.now(timezone.utc).isoformat()
                    self._write_json('users.json', users)
                    return True
                return False

    # ======================================================================
    # CGC GOVERNANCE OPERATIONS
    # ======================================================================

    def save_prefilter_result(self, decision_id: str, result: Dict[str, Any]) -> bool:
        """Save PreFilter evaluation result."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO cgc_prefilter_results 
                        (decision_id, correlation_id, area, outcome, sensitive_count, 
                         agent_id, metrics, latency_ms)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (decision_id) DO NOTHING
                    """, (
                        decision_id,
                        result.get('correlation_id'),
                        result.get('area'),
                        result.get('outcome'),
                        result.get('sensitive_count', 0),
                        result.get('agent_id'),
                        json.dumps(result.get('metrics', {})),
                        result.get('latency_ms', 0.0)
                    ))
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                results = self._read_json_list('prefilter_results.json')
                results.append({**result, 'decision_id': decision_id})
                self._write_json_list('prefilter_results.json', results[-1000:])  # Keep last 1000
                return True

    def save_module_result(self, decision_id: str, module: str, result: Dict[str, Any]) -> bool:
        """Save individual module result (PAN, ECM, PFM, SDA)."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO cgc_module_results 
                        (decision_id, module_name, scores, approved, latency_ms)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        decision_id, module,
                        json.dumps(result.get('scores', {})),
                        result.get('approved', False),
                        result.get('latency_ms', 0.0)
                    ))
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                results = self._read_json_list('module_results.json')
                results.append({
                    'decision_id': decision_id,
                    'module': module,
                    **result
                })
                self._write_json_list('module_results.json', results[-5000:])
                return True

    def save_loop_decision(self, decision_id: str, final_result: Dict[str, Any]) -> bool:
        """Save final governance decision."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO cgc_loop_decisions 
                        (decision_id, prefilter_result, module_scores, final_outcome,
                         risk_level, ethical_score, policy_version, signed_artifact_hash, confidence)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (decision_id) DO UPDATE SET
                        final_outcome = EXCLUDED.final_outcome,
                        signed_artifact_hash = EXCLUDED.signed_artifact_hash
                    """, (
                        decision_id,
                        json.dumps(final_result.get('prefilter_result', {})),
                        json.dumps(final_result.get('module_scores', {})),
                        final_result.get('outcome'),
                        final_result.get('risk_level'),
                        final_result.get('ethical_score'),
                        final_result.get('policy_version'),
                        final_result.get('signed_artifact_hash'),
                        final_result.get('confidence', 0.0)
                    ))
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                decisions = self._read_json('loop_decisions.json')
                decisions[decision_id] = final_result
                self._write_json('loop_decisions.json', decisions)
                return True

    def save_feedback(self, decision_id: str, source_type: str, feedback: Dict[str, Any]) -> bool:
        """Save feedback for CGC_LOOP learning."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO cgc_feedback 
                        (decision_id, source_type, feedback_type, feedback_data)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        decision_id, source_type,
                        feedback.get('type'),
                        json.dumps(feedback)
                    ))
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                feedbacks = self._read_json_list('feedback.json')
                feedbacks.append({
                    'decision_id': decision_id,
                    'source_type': source_type,
                    **feedback
                })
                self._write_json_list('feedback.json', feedbacks[-10000:])
                return True

    def save_audit_trace(self, decision_id: str, trace_data: Dict[str, Any]) -> bool:
        """Save immutable audit trace."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO cgc_audit_traces 
                        (decision_id, block_hash, block_number, merkle_root)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        decision_id,
                        trace_data.get('block_hash'),
                        trace_data.get('block_number'),
                        trace_data.get('merkle_root')
                    ))
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                traces = self._read_json_list('audit_traces.json')
                traces.append({**trace_data, 'decision_id': decision_id})
                self._write_json_list('audit_traces.json', traces[-5000:])
                return True

    # ======================================================================
    # APPLICATION MONITORING (client error reports — LedgiProof / LTP)
    # ======================================================================

    @staticmethod
    def _error_fingerprint(app_source: str, message: str, stack: Optional[str]) -> str:
        """Stable dedup key: same app + same error site collapses to one row
        with a running count, instead of one row per occurrence."""
        top_frame = ''
        for line in (stack or '').splitlines():
            line = line.strip()
            if line:
                top_frame = line
                break
        raw = f"{app_source}|{(message or '')[:200]}|{top_frame[:200]}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]

    def save_error_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Upsert a client error report by fingerprint. Returns
        {fingerprint, first_seen, count} so the caller (the /monitor/error
        endpoint) knows whether this is a brand-new error worth alerting on."""
        fingerprint = self._error_fingerprint(
            report.get('app_source', 'unknown'), report.get('message', ''), report.get('stack')
        )

        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        INSERT INTO cgc_error_reports
                            (fingerprint, app_source, environment, severity, message, stack, url, user_agent, context)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (fingerprint) DO UPDATE SET
                            count      = cgc_error_reports.count + 1,
                            last_seen  = NOW(),
                            resolved   = FALSE,
                            url        = EXCLUDED.url,
                            user_agent = EXCLUDED.user_agent,
                            context    = EXCLUDED.context
                        RETURNING count, (xmax = 0) AS first_seen
                    """, (
                        fingerprint,
                        report.get('app_source'),
                        report.get('environment', 'production'),
                        report.get('severity', 'error'),
                        report.get('message', ''),
                        report.get('stack'),
                        report.get('url'),
                        report.get('user_agent'),
                        json.dumps(report.get('context') or {})
                    ))
                    row = cur.fetchone()
                    return {'fingerprint': fingerprint, 'first_seen': bool(row['first_seen']), 'count': row['count']}
        else:
            with self.json_lock:
                reports = self._read_json_list('error_reports.json')
                now = datetime.now(timezone.utc).isoformat()
                for r in reports:
                    if r.get('fingerprint') == fingerprint:
                        r['count'] = r.get('count', 1) + 1
                        r['last_seen'] = now
                        r['resolved'] = False
                        r['url'] = report.get('url')
                        r['user_agent'] = report.get('user_agent')
                        r['context'] = report.get('context') or {}
                        self._write_json_list('error_reports.json', reports)
                        return {'fingerprint': fingerprint, 'first_seen': False, 'count': r['count']}
                new_row = {
                    'fingerprint':  fingerprint,
                    'app_source':   report.get('app_source'),
                    'environment':  report.get('environment', 'production'),
                    'severity':     report.get('severity', 'error'),
                    'message':      report.get('message', ''),
                    'stack':        report.get('stack'),
                    'url':          report.get('url'),
                    'user_agent':   report.get('user_agent'),
                    'context':      report.get('context') or {},
                    'count':        1,
                    'resolved':     False,
                    'first_seen_at': now,
                    'last_seen':    now
                }
                reports.append(new_row)
                self._write_json_list('error_reports.json', reports[-5000:])
                return {'fingerprint': fingerprint, 'first_seen': True, 'count': 1}

    def get_error_reports(
        self, app_source: Optional[str] = None, resolved: Optional[bool] = None,
        since_days: Optional[int] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        if self.use_postgres:
            clauses, params = [], []
            if app_source is not None:
                clauses.append("app_source = %s"); params.append(app_source)
            if resolved is not None:
                clauses.append("resolved = %s"); params.append(resolved)
            if since_days is not None:
                clauses.append("last_seen > %s"); params.append(datetime.now(timezone.utc) - timedelta(days=since_days))
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            params.append(limit)
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(f"""
                        SELECT * FROM cgc_error_reports {where}
                        ORDER BY last_seen DESC LIMIT %s
                    """, params)
                    return [dict(row) for row in cur.fetchall()]
        else:
            reports = self._read_json_list('error_reports.json')
            if app_source is not None:
                reports = [r for r in reports if r.get('app_source') == app_source]
            if resolved is not None:
                reports = [r for r in reports if r.get('resolved', False) == resolved]
            if since_days is not None:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
                reports = [r for r in reports if r.get('last_seen', '') > cutoff]
            reports.sort(key=lambda r: r.get('last_seen', ''), reverse=True)
            return reports[:limit]

    def get_error_stats(self, days: int = 7) -> Dict[str, Any]:
        reports = self.get_error_reports(since_days=days, limit=100000)
        by_app: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for r in reports:
            by_app[r.get('app_source', 'unknown')] = by_app.get(r.get('app_source', 'unknown'), 0) + r.get('count', 1)
            by_severity[r.get('severity', 'error')] = by_severity.get(r.get('severity', 'error'), 0) + r.get('count', 1)
        top = sorted(reports, key=lambda r: r.get('count', 1), reverse=True)[:10]
        return {
            'window_days':   days,
            'total_reports': len(reports),
            'total_occurrences': sum(r.get('count', 1) for r in reports),
            'unresolved':    sum(1 for r in reports if not r.get('resolved', False)),
            'by_app_source': by_app,
            'by_severity':   by_severity,
            'top_errors': [
                {
                    'fingerprint': r.get('fingerprint'),
                    'app_source':  r.get('app_source'),
                    'message':     r.get('message'),
                    'severity':    r.get('severity'),
                    'count':       r.get('count', 1),
                    'last_seen':   r.get('last_seen'),
                } for r in top
            ]
        }

    def resolve_error_report(self, fingerprint: str) -> bool:
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE cgc_error_reports SET resolved = TRUE WHERE fingerprint = %s",
                        (fingerprint,)
                    )
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                reports = self._read_json_list('error_reports.json')
                found = False
                for r in reports:
                    if r.get('fingerprint') == fingerprint:
                        r['resolved'] = True
                        found = True
                if found:
                    self._write_json_list('error_reports.json', reports)
                return found

    def delete_error_report(self, fingerprint: str) -> bool:
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM cgc_error_reports WHERE fingerprint = %s",
                        (fingerprint,)
                    )
                    return cur.rowcount > 0
        else:
            with self.json_lock:
                reports = self._read_json_list('error_reports.json')
                remaining = [r for r in reports if r.get('fingerprint') != fingerprint]
                found = len(remaining) != len(reports)
                if found:
                    self._write_json_list('error_reports.json', remaining)
                return found

    def delete_error_reports(self, fingerprints: List[str]) -> int:
        """Bulk variant of delete_error_report — same semantics, one round trip.
        Reusable primitive: any future cleanup (pentest noise, stale test data,
        a client's own "clear all" action) goes through this instead of a
        client-side loop of single deletes."""
        if not fingerprints:
            return 0
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM cgc_error_reports WHERE fingerprint = ANY(%s)",
                        (fingerprints,)
                    )
                    return cur.rowcount
        else:
            with self.json_lock:
                reports = self._read_json_list('error_reports.json')
                wanted = set(fingerprints)
                remaining = [r for r in reports if r.get('fingerprint') not in wanted]
                deleted = len(reports) - len(remaining)
                if deleted:
                    self._write_json_list('error_reports.json', remaining)
                return deleted

    # ======================================================================
    # ANALYTICS & LEARNING QUERIES
    # ======================================================================

    def get_pfm_history(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get prediction history for PFM learning."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT * FROM cgc_module_results 
                        WHERE module_name = 'PFM'
                        ORDER BY created_at DESC 
                        LIMIT %s
                    """, (limit,))
                    return [dict(row) for row in cur.fetchall()]
        else:
            with self.json_lock:
                results = self._read_json_list('module_results.json')
                return [r for r in results if r.get('module') == 'PFM'][-limit:]

    def get_decision_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get governance decision statistics."""
        if self.use_postgres:
            with self.get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                    cur.execute("""
                        SELECT 
                            final_outcome, COUNT(*) as count,
                            AVG(ethical_score) as avg_ethics,
                            AVG(risk_level::int) as avg_risk
                        FROM cgc_loop_decisions 
                        WHERE created_at > %s
                        GROUP BY final_outcome
                    """, (cutoff,))
                    return dict(cur.fetchall())
        else:
            return {"error": "Stats not available in JSON mode"}

    # ======================================================================
    # JSON FALLBACK HELPERS (dev only)
    # ======================================================================

    def _read_json(self, filename: str) -> Dict[str, Any]:
        filepath = os.path.join(self.data_dir, filename)
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return {}

    def _write_json(self, filename: str, data: Dict[str, Any]):
        filepath = os.path.join(self.data_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def _read_json_list(self, filename: str) -> List[Dict[str, Any]]:
        filepath = os.path.join(self.data_dir, filename)
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except:
            return []

    def _write_json_list(self, filename: str, data: List[Dict[str, Any]]):
        filepath = os.path.join(self.data_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def close(self):
        """Close database connections."""
        if hasattr(self, 'pool') and self.pool:
            self.pool.closeall()
            logger.info("Database pool closed")


# Singleton access
def get_database() -> Database:
    """Get the singleton Database instance."""
    if Database._instance is None:
        Database._instance = Database()
    return Database._instance

