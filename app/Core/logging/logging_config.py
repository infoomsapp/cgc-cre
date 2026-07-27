"""
CGC CORE™ Logging System
Unified logging → cgc_audit_traces table
Production-ready with config integration
Olympus Mont Systems LLC © 2025
"""

import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler, SysLogHandler, HTTPHandler
from typing import Optional

# CGC CORE integration
from app.Core.db.database import get_database, Database
from app.Core.config import config   # ✔ correcto



class CGCLoggingHandler(logging.Handler):
    """
    CGC CORE logging handler that writes to cgc_audit_traces table.
    Provides immutable audit trail for all governance events.
    """

    def __init__(self):
        super().__init__()
        self.db: Database = get_database()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            extra = getattr(record, "extra", {}) if hasattr(record, "extra") else {}

            trace_data = {
                "block_hash": None,
                "block_number": None,
                "action": record.levelname,
                "message": record.getMessage(),
                "module": record.name,
                "decision_id": extra.get("decision_id", "N/A"),
                "user_id": extra.get("user_id", None),
                "severity": record.levelname,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self.db.save_audit_trace(
                decision_id=trace_data["decision_id"],
                trace_data=trace_data,
            )

        except Exception as e:
            print(f"[CRITICAL] CGC Logging failed: {e}")


def setup_logging() -> None:
    """
    Configure complete CGC CORE logging pipeline.
    Unified architecture: File + Console + Database + External (syslog/HTTP).
    """

    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # LOG LEVEL from config.py
    log_level = getattr(logging, config.LOG_LEVEL)
    root_logger.setLevel(log_level)

    # Formatter with governance context
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s %(decision_id)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # 1. FILE HANDLER
    try:
        os.makedirs(os.path.dirname(config.log_file_path), exist_ok=True)

        file_handler = RotatingFileHandler(
            config.log_file_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=10,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        logging.info(" File logging initialized: %s", config.log_file_path)
    except Exception as e:
        logging.error(" File handler initialization failed: %s", e)

    # 2. CONSOLE HANDLER
    if config.ENV != "production":
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        logging.debug(" Console logging enabled (development mode)")

    # 3. DATABASE HANDLER
    try:
        cgc_handler = CGCLoggingHandler()
        cgc_handler.setLevel(log_level)
        cgc_handler.setFormatter(formatter)
        root_logger.addHandler(cgc_handler)
        logging.info(" CGC Database logging → cgc_audit_traces table")
    except Exception as e:
        logging.error(" CGC Database handler failed: %s", e)

    # 4. SYSLOG
    if os.getenv("LOG_EXTERNAL", "").lower() == "syslog":
        try:
            syslog_handler = SysLogHandler(address=("localhost", 514))
            syslog_handler.setLevel(logging.WARNING)
            syslog_handler.setFormatter(formatter)
            root_logger.addHandler(syslog_handler)
            logging.info(" Syslog integration enabled (localhost:514)")
        except Exception as e:
            logging.error(" Syslog integration failed: %s", e)

    # 5. HTTP LOGGING
    elif os.getenv("LOG_EXTERNAL", "").lower() == "http":
        try:
            http_handler = HTTPHandler(
                host=os.getenv("LOG_HTTP_HOST", "logs.datadoghq.com"),
                url=os.getenv("LOG_HTTP_URL", "/api/v2/logs"),
                method="POST",
                secure=True,
            )
            http_handler.setLevel(logging.WARNING)
            http_handler.setFormatter(formatter)
            root_logger.addHandler(http_handler)
            logging.info(" HTTP logging enabled (external analytics)")
        except Exception as e:
            logging.error(" HTTP logging failed: %s", e)

    # STARTUP BANNER
    logging.info("=" * 80)
    logging.info(f"   {config.CORE_ENGINE} v{config.VERSION}")
    logging.info(f"   {config.PRODUCT_NAME}")
    logging.info(f"   Environment: {config.ENV}")
    logging.info(f"   Logging: {config.LOG_LEVEL} → {config.log_file_path}")
    logging.info(f"   Database: {'PostgreSQL' if config.DATABASE_URL else 'JSON (development)'}")
    logging.info("=" * 80)


def get_logger(name: str, decision_id: Optional[str] = None, user_id: Optional[str] = None) -> logging.Logger:
    """
    Factory for CGC CORE loggers with governance context.
    """

    logger = logging.getLogger(name)

    if decision_id or user_id:

        class CGCAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                kwargs["extra"] = kwargs.get("extra", {})
                if decision_id:
                    kwargs["extra"]["decision_id"] = decision_id
                if user_id:
                    kwargs["extra"]["user_id"] = user_id
                return msg, kwargs

        return CGCAdapter(logger, None)

    return logger