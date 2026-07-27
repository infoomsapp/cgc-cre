"""
Configuration Module

Central configuration for CGC CORE :
- Environment & app
- Logging & database
- LLM providers
- Prefilter
- Governance Core modules (SCM, TCO, PolicyManager, Auth)
"""

import sys
import os
from pathlib import Path
from typing import Optional, Literal, List

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr, ValidationError



class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # ENVIRONMENT & APP
    # ------------------------------------------------------------------
    ENV: Literal["development", "production", "test"] = Field(
        default="development",
        alias="ENVIRONMENT",
    )

    HOST: str = "0.0.0.0"
    PORT: int = 8080

    COMPANY_NAME: str = "OlympusMont Systems LLC"
    PRODUCT_NAME: str = "DisciplineAI Assistant (TM)"
    TAGLINE: str = "AI Efficiency, Software development and Automation Consulting"

    CORE_ENGINE: str = "CGC CORE (TM)"
    VERSION: str = "1.0.0"

    # ------------------------------------------------------------------
    # LOGGING
    # ------------------------------------------------------------------
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    LOG_FILE: str = "./logs/app.log"

    # ------------------------------------------------------------------
    # DATABASE
    # ------------------------------------------------------------------
    DATABASE_URL: Optional[str] = None
    DATABASE_PATH: str = "./data/production.db"

    # ------------------------------------------------------------------
    # LLM / PROVIDER KEYS
    # ------------------------------------------------------------------
    OPENAI_API_KEY: Optional[SecretStr] = None  # Optional: not all flows require it

    # ------------------------------------------------------------------
    # PREFILTER CONFIG
    # ------------------------------------------------------------------
    PREFILTER_ENABLED: bool = True
    PREFILTER_MAX_SENSITIVE_DOMAINS: int = 5
    PREFILTER_BLOCKED_DOMAINS: List[str] = Field(
        default_factory=lambda: ["ILLEGAL", "RESTRICTED"]
    )
    PREFILTER_SHORTCIRCUIT_ALLOWED: bool = False
    PREFILTER_CACHE_ENABLED: bool = True
    PREFILTER_CACHE_TTL_SECONDS: int = 300
    PREFILTER_DEFAULT_AREA: str = "DEFAULT"
    PREFILTER_RULESETS_PATH: Optional[str] = None  # e.g. "./config/prefilter_rulesets.yaml"

    # ------------------------------------------------------------------
    # SCM / CRYPTO CONFIG
    # ------------------------------------------------------------------
    SCM_REQUIRE_STRONG_ENCRYPTION: bool = True
    SCM_MIN_KEY_LENGTH_BITS: int = 256
    SCM_KMS_ENDPOINT: Optional[str] = None
    SCM_FIPS_MODE: bool = False

    # ------------------------------------------------------------------
    # POLICY MANAGER / CGC LOOP CONFIG
    # ------------------------------------------------------------------
    POLICY_STORE_PATH: str = "./data/policies.json"
    POLICY_AUTO_APPLY_PROPOSALS: bool = False
    POLICY_REVIEW_INTERVAL_DAYS: int = 14
    POLICY_MAX_ROLLBACK_DEPTH: int = 20

    # ------------------------------------------------------------------
    # TCO (TRACEABILITY & AUDIT) CONFIG
    # ------------------------------------------------------------------
    TCO_STORAGE_PATH: str = "./data/audit_log"
    TCO_RETENTION_DAYS: int = 365
    TCO_USE_MERKLE: bool = True
    TCO_ANCHOR_EXTERNAL: bool = False  # e.g. external timestamping / blockchain

    # ------------------------------------------------------------------
    # AUTH SYSTEM CONFIG
    # ------------------------------------------------------------------
    AUTH_DATA_DIR: str = "./data/auth"
    AUTH_JWT_EXP_DAYS: int = 7
    AUTH_MIN_PASSWORD_LENGTH: int = 12

    # ------------------------------------------------------------------
    # DERIVED / CONVENIENCE PROPERTIES
    # ------------------------------------------------------------------
    def display(self) -> None:
        print("--- Configuration Summary ---")
        print(f"Environment: {self.ENV}")
        print(f"Host / Port: {self.HOST}:{self.PORT}")
        print(f"Log Level: {self.LOG_LEVEL}")
        print(f"OpenAI Key: {'SET' if self.OPENAI_API_KEY else 'MISSING'}")
        print(f"Database (effective): {self.effective_db}")
        print(f"Log File: {self.log_file_path}")
        print(f"Prefilter Enabled: {self.PREFILTER_ENABLED}")
        print(f"Prefilter Cache: {self.PREFILTER_CACHE_ENABLED} (TTL={self.PREFILTER_CACHE_TTL_SECONDS}s)")
        print(f"TCO Storage Path: {self.tco_storage_path}")
        print(f"Policy Store Path: {self.policy_store_path}")
        print(f"Auth Data Dir: {self.auth_data_dir}")
        print("-------------------------------")

    @property
    def effective_db(self) -> str:
        return self.DATABASE_URL or str(Path(self.DATABASE_PATH).resolve())

    @property
    def log_file_path(self) -> str:
        log_path = Path(self.LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        return str(log_path.resolve())

    @property
    def tco_storage_path(self) -> str:
        path = Path(self.TCO_STORAGE_PATH)
        path.mkdir(parents=True, exist_ok=True)
        return str(path.resolve())

    @property
    def policy_store_path(self) -> str:
        path = Path(self.POLICY_STORE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path.resolve())

    @property
    def auth_data_dir(self) -> str:
        path = Path(self.AUTH_DATA_DIR)
        path.mkdir(parents=True, exist_ok=True)
        return str(path.resolve())


try:
    config = Settings()
except ValidationError as e:
    print("[ERROR] CONFIGURATION ERROR: Failed to load settings.")
    print(e)
    sys.exit(1)

# Optional: basic safety checks for production
if config.ENV == "production":
    if not os.getenv("JWT_SECRET"):
        print("[WARN] JWT_SECRET is not set in production environment.")
    if not config.OPENAI_API_KEY:
        print("[WARN] OPENAI_API_KEY is not set in production environment.")

