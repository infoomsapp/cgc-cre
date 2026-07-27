"""
Authentication & Security System
Olympus Mont Systems LLC - CGC CORE
Hardened and integrated with CGC governance concepts.
"""

import json
import hashlib
import secrets
import time
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


class AuthError(Exception):
    """Generic authentication/authorization error."""


class AuthSystem:
    """Enterprise-grade authentication system for CGC CORE."""

    def __init__(
        self,
        data_dir: str = "./data",
        jwt_secret: Optional[str] = None,
        allowed_algorithms: Optional[List[str]] = None,
    ) -> None:
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, "users.json")
        self.sessions_file = os.path.join(data_dir, "sessions.json")
        self.blocked_file = os.path.join(data_dir, "blocked.json")

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

        # Rate limiting
        self.login_attempts: Dict[str, List[float]] = {}  # IP -> [timestamps]
        self.max_attempts = 5
        self.lockout_duration = 900  # 15 minutes

        # Initialize storage
        os.makedirs(data_dir, exist_ok=True)
        self._init_storage()

    # ======================================================================
    # INTERNAL HELPERS
    # ======================================================================

    def _generate_secret(self) -> str:
        """Generate secure JWT secret."""
        return secrets.token_urlsafe(32)

    def _init_storage(self) -> None:
        """Initialize storage files."""
        if not os.path.exists(self.users_file):
            self._save_users({})
        if not os.path.exists(self.sessions_file):
            self._save_sessions({})
        if not os.path.exists(self.blocked_file):
            self._save_blocked({"ips": [], "emails": []})

    def _load_users(self) -> Dict:
        """Load users from file."""
        try:
            with open(self.users_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_users(self, users: Dict) -> None:
        """Save users to file."""
        with open(self.users_file, "w") as f:
            json.dump(users, f, indent=2)

    def _load_sessions(self) -> Dict:
        """Load sessions from file."""
        try:
            with open(self.sessions_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_sessions(self, sessions: Dict) -> None:
        """Save sessions to file."""
        with open(self.sessions_file, "w") as f:
            json.dump(sessions, f, indent=2)

    def _load_blocked(self) -> Dict:
        """Load blocked IPs/users."""
        try:
            with open(self.blocked_file, "r") as f:
                return json.load(f)
        except Exception:
            return {"ips": [], "emails": []}

    def _save_blocked(self, blocked: Dict) -> None:
        """Save blocked list."""
        with open(self.blocked_file, "w") as f:
            json.dump(blocked, f, indent=2)

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

    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP is rate limited."""
        now = time.time()
        attempts = self.login_attempts.get(ip, [])

        # Clean old attempts
        attempts = [t for t in attempts if now - t < self.lockout_duration]
        self.login_attempts[ip] = attempts

        if len(attempts) >= self.max_attempts:
            return False
        return True

    def _record_attempt(self, ip: str) -> None:
        """Record login attempt."""
        if ip not in self.login_attempts:
            self.login_attempts[ip] = []
        self.login_attempts[ip].append(time.time())

    def _is_ip_blocked(self, ip: str, blocked: Dict) -> bool:
        """Check if IP is in blocked list."""
        for entry in blocked.get("ips", []):
            if entry.get("ip") == ip:
                return True
        return False

    def _is_email_blocked(self, email: str, blocked: Dict) -> bool:
        """Check if email is in blocked list."""
        for entry in blocked.get("emails", []):
            if entry.get("email") == email:
                return True
        return False

    # ======================================================================
    # BLOCK / RATE LIMIT
    # ======================================================================

    def is_blocked(self, ip: str = None, email: str = None) -> bool:
        """Check if IP or email is blocked."""
        blocked = self._load_blocked()

        if ip and self._is_ip_blocked(ip, blocked):
            return True
        if email and self._is_email_blocked(email, blocked):
            return True
        return False

    def block_user(self, ip: str = None, email: str = None, reason: str = "") -> None:
        """Block IP or email."""
        blocked = self._load_blocked()
        blocked.setdefault("ips", [])
        blocked.setdefault("emails", [])

        now_iso = datetime.now(timezone.utc).isoformat()

        if ip:
            blocked["ips"].append(
                {
                    "ip": ip,
                    "reason": reason,
                    "blocked_at": now_iso,
                }
            )

        if email:
            blocked["emails"].append(
                {
                    "email": email,
                    "reason": reason,
                    "blocked_at": now_iso,
                }
            )

        self._save_blocked(blocked)
        print(f" Blocked: {ip or email} - {reason}")

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
        users = self._load_users()

        if email in users:
            return {"success": False, "error": "User already exists"}

        if len(password) < 12:
            return {"success": False, "error": "Password must be 12+ characters"}

        user = {
            "email": email,
            "password_hash": self._hash_password(password),
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": created_by,
            "active": True,
            "last_login": None,
            "login_count": 0,
        }

        users[email] = user
        self._save_users(users)

        print(f" User created: {email} ({role})")

        return {
            "success": True,
            "user": {
                "email": email,
                "role": role,
                "created_at": user["created_at"],
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

        if ip and not self._check_rate_limit(ip):
            return {
                "success": False,
                "error": "Too many attempts. Try again later.",
                "rate_limited": True,
            }

        if ip:
            self._record_attempt(ip)

        users = self._load_users()

        if email not in users:
            return {"success": False, "error": "Invalid credentials"}

        user = users[email]

        if not user.get("active", True):
            return {"success": False, "error": "Account disabled"}

        if not self._verify_password(password, user["password_hash"]):
            return {"success": False, "error": "Invalid credentials"}

        user["last_login"] = datetime.now(timezone.utc).isoformat()
        user["login_count"] = user.get("login_count", 0) + 1
        users[email] = user
        self._save_users(users)

        token = self._create_token(email, user["role"])

        sessions = self._load_sessions()
        sessions[token] = {
            "email": email,
            "role": user["role"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            "ip": ip,
        }
        self._save_sessions(sessions)

        # Here you can send an event to TCO (audit) that an admin/user logged in.

        print(f" Login successful: {email}")

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

        sessions = self._load_sessions()

        if token not in sessions:
            return None

        session = sessions[token]

        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=self.jwt_algorithms,
            )
        except jwt.ExpiredSignatureError:
            del sessions[token]
            self._save_sessions(sessions)
            return None
        except jwt.InvalidTokenError:
            return None

        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            del sessions[token]
            self._save_sessions(sessions)
            return None

        return {
            "email": session["email"],
            "role": session["role"],
        }

    def logout(self, token: str) -> None:
        """Logout user (invalidate session)."""
        sessions = self._load_sessions()
        if token in sessions:
            del sessions[token]
            self._save_sessions(sessions)
            print(" Logout successful")

    # ======================================================================
    # PASSWORD RESET
    # ======================================================================

    def reset_password(self, email: str) -> Dict:
        """Generate password reset token."""
        users = self._load_users()

        if email not in users:
            return {"success": True, "message": "If email exists, reset link sent"}

        reset_token = secrets.token_urlsafe(32)

        users[email]["reset_token"] = reset_token
        users[email]["reset_expires"] = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()

        self._save_users(users)

        print(f" Reset token for {email}: {reset_token}")

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
        users = self._load_users()

        if email not in users:
            return {"success": False, "error": "User not found"}

        user = users[email]

        if reset_token:
            if user.get("reset_token") != reset_token:
                return {"success": False, "error": "Invalid reset token"}

            expires = datetime.fromisoformat(user["reset_expires"])
            if datetime.now(timezone.utc) > expires:
                return {"success": False, "error": "Reset token expired"}

        if len(new_password) < 12:
            return {"success": False, "error": "Password must be 12+ characters"}

        user["password_hash"] = self._hash_password(new_password)
        user["reset_token"] = None
        user["reset_expires"] = None

        users[email] = user
        self._save_users(users)

        print(f" Password changed: {email}")

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

    def list_users(self, requester_token: str) -> Dict:
        """List users (admin/governance_admin only)."""
        self.authorize(requester_token, "VIEW_CORE_METRICS")

        users = self._load_users()
        user_list = []
        for email, user in users.items():
            user_list.append(
                {
                    "email": email,
                    "role": user["role"],
                    "active": user.get("active", True),
                    "created_at": user["created_at"],
                    "last_login": user.get("last_login"),
                    "login_count": user.get("login_count", 0),
                }
            )

        return {
            "success": True,
            "users": user_list,
            "total": len(user_list),
        }

    def get_stats(self) -> Dict:
        """Get system stats."""
        users = self._load_users()
        sessions = self._load_sessions()
        blocked = self._load_blocked()

        return {
            "total_users": len(users),
            "active_sessions": len(sessions),
            "blocked_ips": len(blocked.get("ips", [])),
            "blocked_emails": len(blocked.get("emails", [])),
            "roles": {
                "admin": len([u for u in users.values() if u["role"] == "admin"]),
                "governance_admin": len(
                    [u for u in users.values() if u["role"] == "governance_admin"]
                ),
                "auditor": len([u for u in users.values() if u["role"] == "auditor"]),
                "user": len([u for u in users.values() if u["role"] == "user"]),
                "viewer": len([u for u in users.values() if u["role"] == "viewer"]),
            },
        }

