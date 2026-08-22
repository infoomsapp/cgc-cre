"""
Authentication & Security System
Olympus Mont Systems LLC - CGC CORE
Hardened and integrated with CGC governance concepts.
"""

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import os

try:
    import bcrypt
    import jwt
    CRYPTO_AVAILABLE = True
except ImportError as e:
    CRYPTO_AVAILABLE = False
    raise ImportError(
        "Secure crypto dependencies missing. "
        "Install with: pip install bcrypt pyjwt"
    ) from e

from app.Core.db.database import get_database
from app.modules.guard.login_guard import record_login_attempt, check_login_lockout, detect_credential_stuffing
from app.modules.guard.enforcement import is_hard_mode

logger = logging.getLogger("cgc.auth")


class AuthError(Exception):
    """Generic authentication/authorization error."""


class AuthSystem:
    """
    Enterprise-grade authentication system for CGC CORE.

    Dual-mode storage, decided once at construction (self._db.use_postgres),
    same flag Database itself uses: real Postgres (cgc_auth schema) when
    DATABASE_URL is configured, JSON files under data_dir as the fallback
    for local dev without a database. Every dict this class returns has the
    same shape either way -- timestamps are always ISO8601 strings, never a
    raw datetime, so callers never need to know which backend served them.
    """

    def __init__(
        self,
        data_dir: str = os.getenv("CGC_AUTH_DATA_DIR", "./data"),
        jwt_secret: Optional[str] = None,
        allowed_algorithms: Optional[List[str]] = None,
    ) -> None:
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, "users.json")
        self.sessions_file = os.path.join(data_dir, "sessions.json")
        self.blocked_file = os.path.join(data_dir, "blocked.json")

        self._db = get_database()

        # JWT secret MUST be provided in production
        env_secret = os.getenv("JWT_SECRET")
        self.jwt_secret = jwt_secret or env_secret
        if not self.jwt_secret:
            # For dev only: generate ephemeral secret
            self.jwt_secret = self._generate_secret()
            print(" JWT_SECRET not set. Using ephemeral secret (dev only).")

        self.jwt_algorithms = allowed_algorithms or ["HS256"]

        # Service-to-service API key (first-party callers such as LedgiProof).
        # When CGC_SERVICE_API_KEY is set, a caller presenting exactly this key
        # authenticates as the 'service' principal without a user session/JWT.
        # Leave unset to disable service-key auth entirely.
        self.service_api_key = os.getenv("CGC_SERVICE_API_KEY")

        # JSON fallback storage -- only actually touched when self._db.use_postgres is False.
        os.makedirs(data_dir, exist_ok=True)
        self._init_storage()

    # ======================================================================
    # JSON FALLBACK STORAGE (local dev without DATABASE_URL)
    # ======================================================================

    def _init_storage(self) -> None:
        if not os.path.exists(self.users_file):
            self._save_users_json({})
        if not os.path.exists(self.sessions_file):
            self._save_sessions_json({})
        if not os.path.exists(self.blocked_file):
            self._save_blocked_json({"ips": [], "emails": []})

    def _load_users_json(self) -> Dict:
        try:
            with open(self.users_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_users_json(self, users: Dict) -> None:
        """Fallback-only (self._db.use_postgres is False) -- see database.py's
        _write_json_list docstring for why this needs its own guard: a warm
        instance that ever falls back to JSON on Vercel's read-only
        filesystem must degrade gracefully, not crash every write."""
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            with open(self.users_file, "w") as f:
                json.dump(users, f, indent=2)
        except Exception as e:
            logger.warning(f"[auth] JSON fallback write failed for users.json (non-fatal): {e}")

    def _load_sessions_json(self) -> Dict:
        try:
            with open(self.sessions_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_sessions_json(self, sessions: Dict) -> None:
        """Same fix as _save_users_json -- see that method's docstring."""
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            with open(self.sessions_file, "w") as f:
                json.dump(sessions, f, indent=2)
        except Exception as e:
            logger.warning(f"[auth] JSON fallback write failed for sessions.json (non-fatal): {e}")

    def _load_blocked_json(self) -> Dict:
        try:
            with open(self.blocked_file, "r") as f:
                return json.load(f)
        except Exception:
            return {"ips": [], "emails": []}

    def _save_blocked_json(self, blocked: Dict) -> None:
        """Same fix as _save_users_json -- see that method's docstring."""
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            with open(self.blocked_file, "w") as f:
                json.dump(blocked, f, indent=2)
        except Exception as e:
            logger.warning(f"[auth] JSON fallback write failed for blocked.json (non-fatal): {e}")

    def _json_is_ip_blocked(self, ip: str, blocked: Dict) -> bool:
        return any(entry.get("ip") == ip for entry in blocked.get("ips", []))

    def _json_is_email_blocked(self, email: str, blocked: Dict) -> bool:
        return any(entry.get("email") == email for entry in blocked.get("emails", []))

    # ======================================================================
    # STORAGE PRIMITIVES -- dispatched on self._db.use_postgres
    # ======================================================================

    def _get_user(self, email: str) -> Optional[Dict]:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return None
                cur = conn.cursor()
                cur.execute("SELECT * FROM cgc_auth.users WHERE email = %s", (email,))
                row = cur.fetchone()
                return dict(row) if row else None
        return self._load_users_json().get(email)

    def _insert_user(self, email: str, password_hash: str, role: str, created_by: str, created_at: str) -> bool:
        """Returns True if inserted, False if the email already existed (atomic either way)."""
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return False
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO cgc_auth.users (email, password_hash, role, created_at, created_by) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (email) DO NOTHING RETURNING email",
                    (email, password_hash, role, created_at, created_by)
                )
                inserted = cur.fetchone() is not None
                conn.commit()
                return inserted

        users = self._load_users_json()
        if email in users:
            return False
        users[email] = {
            "email": email, "password_hash": password_hash, "role": role,
            "created_at": created_at, "created_by": created_by, "active": True,
            "last_login": None, "login_count": 0,
        }
        self._save_users_json(users)
        return True

    def _update_user(self, email: str, **fields) -> None:
        if not fields:
            return
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return
                cur = conn.cursor()
                set_clause = ", ".join(f"{k} = %s" for k in fields)
                cur.execute(
                    f"UPDATE cgc_auth.users SET {set_clause} WHERE email = %s",
                    (*fields.values(), email)
                )
                conn.commit()
            return

        users = self._load_users_json()
        if email in users:
            users[email].update(fields)
            self._save_users_json(users)

    def _list_users(self) -> List[Dict]:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return []
                cur = conn.cursor()
                cur.execute("SELECT * FROM cgc_auth.users ORDER BY created_at ASC")
                return [dict(r) for r in cur.fetchall()]
        return list(self._load_users_json().values())

    def _get_session(self, token: str) -> Optional[Dict]:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return None
                cur = conn.cursor()
                cur.execute("SELECT * FROM cgc_auth.sessions WHERE token = %s", (token,))
                row = cur.fetchone()
                return dict(row) if row else None
        return self._load_sessions_json().get(token)

    def _insert_session(self, token: str, email: str, role: str, expires_at: str, ip: Optional[str]) -> None:
        created_at = datetime.now(timezone.utc).isoformat()
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO cgc_auth.sessions (token, email, role, created_at, expires_at, ip) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (token, email, role, created_at, expires_at, ip)
                )
                conn.commit()
            return

        sessions = self._load_sessions_json()
        sessions[token] = {"email": email, "role": role, "created_at": created_at, "expires_at": expires_at, "ip": ip}
        self._save_sessions_json(sessions)

    def _delete_session(self, token: str) -> None:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return
                cur = conn.cursor()
                cur.execute("DELETE FROM cgc_auth.sessions WHERE token = %s", (token,))
                conn.commit()
            return

        sessions = self._load_sessions_json()
        if token in sessions:
            del sessions[token]
            self._save_sessions_json(sessions)

    def _count_sessions(self) -> int:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return 0
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) AS c FROM cgc_auth.sessions")
                row = cur.fetchone()
                return row["c"] if row else 0
        return len(self._load_sessions_json())

    def _is_ip_blocked(self, ip: str) -> bool:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return False
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM cgc_auth.blocklist WHERE ip = %s LIMIT 1", (ip,))
                return cur.fetchone() is not None
        return self._json_is_ip_blocked(ip, self._load_blocked_json())

    def _is_email_blocked(self, email: str) -> bool:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return False
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM cgc_auth.blocklist WHERE email = %s LIMIT 1", (email,))
                return cur.fetchone() is not None
        return self._json_is_email_blocked(email, self._load_blocked_json())

    def _insert_block(self, ip: Optional[str], email: Optional[str], reason: str) -> None:
        blocked_at = datetime.now(timezone.utc).isoformat()
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO cgc_auth.blocklist (ip, email, reason, blocked_at) VALUES (%s, %s, %s, %s)",
                    (ip, email, reason, blocked_at)
                )
                conn.commit()
            return

        blocked = self._load_blocked_json()
        blocked.setdefault("ips", [])
        blocked.setdefault("emails", [])
        if ip:
            blocked["ips"].append({"ip": ip, "reason": reason, "blocked_at": blocked_at})
        if email:
            blocked["emails"].append({"email": email, "reason": reason, "blocked_at": blocked_at})
        self._save_blocked_json(blocked)

    def _count_blocked(self) -> Dict[str, int]:
        if self._db.use_postgres:
            with self._db.get_connection() as conn:
                if conn is None:
                    return {"ips": 0, "emails": 0}
                cur = conn.cursor()
                cur.execute(
                    "SELECT COUNT(*) FILTER (WHERE ip IS NOT NULL) AS ips, "
                    "COUNT(*) FILTER (WHERE email IS NOT NULL) AS emails FROM cgc_auth.blocklist"
                )
                row = cur.fetchone()
                return {"ips": row["ips"], "emails": row["emails"]} if row else {"ips": 0, "emails": 0}
        blocked = self._load_blocked_json()
        return {"ips": len(blocked.get("ips", [])), "emails": len(blocked.get("emails", []))}

    # ======================================================================
    # PASSWORD HASHING
    # ======================================================================

    def _hash_password(self, password: str) -> str:
        """Hash password with bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except ValueError:
            # In case hashed is not a bcrypt hash
            return False

    # ======================================================================
    # BLOCK / RATE LIMIT
    # ======================================================================

    def is_blocked(self, ip: str = None, email: str = None) -> bool:
        """Check if IP or email is blocked."""
        if ip and self._is_ip_blocked(ip):
            return True
        if email and self._is_email_blocked(email):
            return True
        return False

    def block_user(self, ip: str = None, email: str = None, reason: str = "") -> None:
        """Block IP or email."""
        self._insert_block(ip, email, reason)
        logger.info(f"[auth] blocked: {ip or email} - {reason}")

    # ======================================================================
    # USER MANAGEMENT
    # ======================================================================

    def create_user(
        self,
        email: str,
        password: str,
        role: str = "user",
        created_by: str = "system",
    ) -> Dict:
        """
        Create new user.

        Roles: admin, governance_admin, auditor, user, viewer
        """
        if len(password) < 12:
            return {"success": False, "error": "Password must be 12+ characters"}

        password_hash = self._hash_password(password)
        created_at = datetime.now(timezone.utc).isoformat()

        inserted = self._insert_user(email, password_hash, role, created_by, created_at)
        if not inserted:
            return {"success": False, "error": "User already exists"}

        logger.info(f"[auth] user created: {email} ({role})")

        return {
            "success": True,
            "user": {
                "email": email,
                "role": role,
                "created_at": created_at,
            },
        }

    # ======================================================================
    # AUTH / SESSIONS
    # ======================================================================

    def _create_token(self, email: str, role: str) -> str:
        """Create JWT token."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": email,
            "role": role,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(days=7),
            "jti": secrets.token_hex(12),
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithms[0])
        # pyjwt >= 2 returns str, older may return bytes
        if isinstance(token, bytes):
            token = token.decode()
        return token

    def login(self, email: str, password: str, ip: str = None) -> Dict:
        """Login user and create session."""

        if self.is_blocked(ip=ip, email=email):
            return {
                "success": False,
                "error": "Access denied",
                "blocked": True,
            }

        # Distributed (Postgres-backed) lockout -- unrelated to this pass,
        # untouched: already durable since Phase 2.
        if not check_login_lockout(ip):
            return {
                "success": False,
                "error": "Too many attempts. Try again later.",
                "rate_limited": True,
            }

        def _fail(reason: str) -> Dict:
            record_login_attempt(ip, email, success=False)
            # Soft-flag by default -- logs a warning if the pattern fires,
            # never blocks anything beyond the lockout check above.
            # GUARD_HARD_MODE_STUFFING=true promotes this to an actual
            # auto-block of the IP -- off by default until real
            # false-positive rate has actually been observed; see
            # app/modules/guard/enforcement.py.
            flag = detect_credential_stuffing(ip)
            if flag and ip and is_hard_mode("stuffing"):
                self.block_user(ip=ip, reason="credential_stuffing_auto_block")
                logger.warning(f"[auth] BLOCKED (hard mode) IP {ip} for credential-stuffing shape: {flag}")
            return {"success": False, "error": reason}

        user = self._get_user(email)

        if user is None:
            return _fail("Invalid credentials")

        if not user.get("active", True):
            return _fail("Account disabled")

        if not self._verify_password(password, user["password_hash"]):
            return _fail("Invalid credentials")

        record_login_attempt(ip, email, success=True)

        new_login_count = (user.get("login_count") or 0) + 1
        self._update_user(email, last_login=datetime.now(timezone.utc).isoformat(), login_count=new_login_count)

        token = self._create_token(email, user["role"])
        expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        self._insert_session(token, email, user["role"], expires_at, ip)

        logger.info(f"[auth] login successful: {email}")

        return {
            "success": True,
            "token": token,
            "user": {
                "email": email,
                "role": user["role"],
            },
        }

    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify token and return user info, or None if invalid/expired."""
        # Service-to-service auth: a first-party static API key (LedgiProof, etc.).
        # Constant-time compare; no session or JWT required. Opt-in via env.
        if self.service_api_key and secrets.compare_digest(str(token), self.service_api_key):
            return {"email": "service@ledgiproof", "role": "service"}

        session = self._get_session(token)
        if session is None:
            return None

        try:
            jwt.decode(
                token,
                self.jwt_secret,
                algorithms=self.jwt_algorithms,
            )
        except jwt.ExpiredSignatureError:
            self._delete_session(token)
            return None
        except jwt.InvalidTokenError:
            return None

        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            self._delete_session(token)
            return None

        return {
            "email": session["email"],
            "role": session["role"],
        }

    def logout(self, token: str) -> None:
        """Logout user (invalidate session)."""
        self._delete_session(token)
        logger.info("[auth] logout successful")

    # ======================================================================
    # PASSWORD RESET
    # ======================================================================

    def reset_password(self, email: str) -> Dict:
        """Generate password reset token."""
        user = self._get_user(email)

        if user is None:
            return {"success": True, "message": "If email exists, reset link sent"}

        reset_token = secrets.token_urlsafe(32)
        reset_expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        self._update_user(email, reset_token=reset_token, reset_expires=reset_expires)

        logger.info(f"[auth] reset token generated for {email}")

        return {
            "success": True,
            "message": "If email exists, reset link sent",
            "reset_token": reset_token,
        }

    def change_password(
        self,
        email: str,
        new_password: str,
        reset_token: str = None,
    ) -> Dict:
        """Change user password."""
        user = self._get_user(email)

        if user is None:
            return {"success": False, "error": "User not found"}

        if reset_token:
            if user.get("reset_token") != reset_token:
                return {"success": False, "error": "Invalid reset token"}

            expires = datetime.fromisoformat(user["reset_expires"])
            if datetime.now(timezone.utc) > expires:
                return {"success": False, "error": "Reset token expired"}

        if len(new_password) < 12:
            return {"success": False, "error": "Password must be 12+ characters"}

        self._update_user(
            email,
            password_hash=self._hash_password(new_password),
            reset_token=None,
            reset_expires=None,
        )

        logger.info(f"[auth] password changed: {email}")

        return {"success": True, "message": "Password updated"}

    # ======================================================================
    # AUTHORIZATION FOR CGC CORE
    # ======================================================================

    def authorize(self, token: str, action: str) -> bool:
        """
        Authorize a given action in CGC CORE based on user role.

        Example actions:
        - "VIEW_AUDIT_LOGS"
        - "CHANGE_POLICIES"
        - "APPROVE_POLICY_CHANGE"
        - "TRIGGER_ROLLBACK"
        - "VIEW_CORE_METRICS"
        """
        user_info = self.verify_token(token)
        if not user_info:
            raise AuthError("Invalid or expired token")

        role = user_info["role"]

        # Simple policy mapping: extend as needed
        role_permissions = {
            "admin": {
                "VIEW_AUDIT_LOGS",
                "CHANGE_POLICIES",
                "APPROVE_POLICY_CHANGE",
                "TRIGGER_ROLLBACK",
                "VIEW_CORE_METRICS",
            },
            "governance_admin": {
                "VIEW_AUDIT_LOGS",
                "CHANGE_POLICIES",
                "APPROVE_POLICY_CHANGE",
                "TRIGGER_ROLLBACK",
                "VIEW_CORE_METRICS",
            },
            "auditor": {
                "VIEW_AUDIT_LOGS",
                "VIEW_CORE_METRICS",
            },
            "user": {
                "VIEW_CORE_METRICS",
            },
            "viewer": set(),
        }

        allowed_actions = role_permissions.get(role, set())
        if action not in allowed_actions:
            raise AuthError(f"Action '{action}' not allowed for role '{role}'")

        return True

    # ======================================================================
    # ADMIN UTILITIES
    # ======================================================================

    def list_users(self) -> Dict:
        """
        List users. Was list_users(requester_token) with an internal
        self.authorize(...) re-check -- but the only real caller,
        main.py's GET /admin/users, already gates on Depends(require_admin)
        before this ever runs, so the internal re-check was always
        redundant with the endpoint's own dependency, and the mismatched
        signature (main.py calls this with zero args) meant every real
        call raised TypeError. Authorization is the endpoint's job now,
        consistently with every other route in this file.
        """
        users = self._list_users()
        user_list = [
            {
                "email": u["email"],
                "role": u["role"],
                "active": u.get("active", True),
                "created_at": u["created_at"],
                "last_login": u.get("last_login"),
                "login_count": u.get("login_count", 0),
            }
            for u in users
        ]

        return {
            "success": True,
            "users": user_list,
            "total": len(user_list),
        }

    def get_stats(self) -> Dict:
        """Get system stats."""
        users = self._list_users()
        blocked = self._count_blocked()

        return {
            "total_users": len(users),
            "active_sessions": self._count_sessions(),
            "blocked_ips": blocked["ips"],
            "blocked_emails": blocked["emails"],
            "roles": {
                "admin": len([u for u in users if u["role"] == "admin"]),
                "governance_admin": len([u for u in users if u["role"] == "governance_admin"]),
                "auditor": len([u for u in users if u["role"] == "auditor"]),
                "user": len([u for u in users if u["role"] == "user"]),
                "viewer": len([u for u in users if u["role"] == "viewer"]),
            },
        }
