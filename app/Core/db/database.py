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
from typing import Dict, Optional, List, Any
from datetime import datetime, timezone
from contextlib import contextmanager
import threading

# PostgreSQL
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
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
            'audit_traces.json': []
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
            
            conn.commit()
            logger.info("All CGC governance tables created/verified")

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

