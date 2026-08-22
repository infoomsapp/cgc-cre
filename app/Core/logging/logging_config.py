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
# `from app.Core.config import config` (marked "correcto" but never actually
# verified) resolves `config` to the SUBMODULE app/Core/config/config.py,
# not to the Settings() instance defined inside it under the same name --
# app/Core/config/ has no __init__.py, so Python's import machinery binds
# the plain name to whichever it finds first when neither package nor
# submodule attribute exists yet, and here that's the submodule itself.
# config.LOG_LEVEL (and every other config.* access below) raised
# AttributeError on the module object -- confirmed live, reproducible 100%
# of the time -- which is very likely why setup_logging() was never
# actually wired into app startup: it could never have run successfully
# even if someone had tried. Importing the real instance explicitly here
# fixes it without touching the many other files that already do
# `from app.Core.config import config` and never dereference it (dead but
# harmless there, since they don't call config.anything).
from app.Core.config.config import config



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
            # A LogRecord has no nested `.extra` attribute -- `extra={...}`
            # passed to logger.info(msg, extra={...}) sets each key directly
            # as a top-level attribute on the record (e.g. record.decision_id),
            # not under record.extra. `getattr(record, "extra", {})` was
            # therefore always {}, so every audit-trace row ever written by
            # this handler had decision_id/user_id hardcoded to None
            # regardless of what callers actually passed.
            trace_data = {
                "block_hash": None,
                "block_number": None,
                "action": record.levelname,
                "message": record.getMessage(),
                "module": record.name,
                # None (not "N/A"): cgc_audit_traces.decision_id is a
                # nullable FK to cgc_prefilter_results(decision_id) --
                # Postgres skips FK validation on a real NULL, but "N/A"
                # is a real (non-existent) value, so every log line
                # without a decision_id used to violate the FK, silently
                # swallowed by this method's own broad except below.
                "decision_id": getattr(record, "decision_id", None),
                "user_id": getattr(record, "user_id", None),
                "severity": record.levelname,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self.db.save_audit_trace(
                decision_id=trace_data["decision_id"],
                trace_data=trace_data,
            )

        except Exception as e:
            print(f"[CRITICAL] CGC Logging failed: {e}")


class _DefaultContextFilter(logging.Filter):
    """
    The formatter below requires %(decision_id)s on every record, but almost
    no call site anywhere in this codebase actually passes
    extra={"decision_id": ...} -- get_logger()'s CGCAdapter only injects it
    when a caller explicitly asks for a decision-scoped logger, which is
    rare. Without this filter, formatting any plain logger.info(...)/
    logger.warning(...) call raises KeyError inside the formatter itself --
    caught internally by each handler's own emit() (so it doesn't crash the
    app), but silently replaces the real message with a
    "--- Logging error ---" traceback dump on stderr for nearly every log
    line in the app. A logging.Filter can mutate the record before it
    reaches any handler, so this fills in a safe default once, for every
    record, regardless of which logger emitted it.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "decision_id"):
            record.decision_id = "-"
        if not hasattr(record, "user_id"):
            record.user_id = "-"
        return True


def setup_logging() -> None:
    """
    Configure complete CGC CORE logging pipeline.
    Unified architecture: File + Console + Database + External (syslog/HTTP).
    """

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    # Logger-level filters (Logger.addFilter) only run on the ORIGINATING
    # logger of a record, not on ancestors a record propagates through --
    # confirmed empirically, since nearly every real log call in this app
    # goes through a per-module child logger ("cgc.loop", "cgc.database",
    # ...) that propagates up to root's handlers, not through root directly.
    # A Handler-level filter (Handler.addFilter), by contrast, IS checked
    # for every record that reaches that handler regardless of which logger
    # it originated from -- so this needs to be added to each handler below,
    # not to root_logger itself.
    context_filter = _DefaultContextFilter()

    # LOG LEVEL from config.py
    log_level = getattr(logging, config.LOG_LEVEL)
    root_logger.setLevel(log_level)

    # Formatter with governance context
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s %(decision_id)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # 1. DATABASE HANDLER -- deliberately added FIRST, before any handler
    # carrying context_filter. A logging.Filter mutates the shared
    # LogRecord object IN PLACE, and the same record instance is passed to
    # every handler for one log call, in root_logger.handlers order --
    # confirmed live: even with context_filter attached only to
    # file_handler/console_handler (never to cgc_handler itself), those
    # earlier handlers' filters were already stamping decision_id="-" onto
    # the record before CGCLoggingHandler.emit() ever got a turn, so it
    # kept reading "-" instead of the true absence, and the FK insert kept
    # failing -- attaching the filter to fewer handlers wasn't enough, only
    # handler ORDER fixes it. Placing this handler first means it always
    # sees the record before anything has touched it.
    try:
        cgc_handler = CGCLoggingHandler()
        cgc_handler.setLevel(log_level)
        cgc_handler.setFormatter(formatter)
        # No context_filter here: CGCLoggingHandler.emit() never calls
        # self.format(), so it doesn't need the KeyError workaround, and it
        # must never see decision_id="-" -- a real missing decision_id must
        # read back as None (a safe SQL NULL against cgc_audit_traces'
        # nullable FK), not a placeholder string that violates that FK on
        # every insert (the same "N/A" sentinel-vs-NULL mistake already
        # fixed once in this exact handler).
        root_logger.addHandler(cgc_handler)
        logging.info(" CGC Database logging → cgc_audit_traces table")
    except Exception as e:
        logging.error(" CGC Database handler failed: %s", e)

    # 2. FILE HANDLER
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
        file_handler.addFilter(context_filter)
        root_logger.addHandler(file_handler)
        logging.info(" File logging initialized: %s", config.log_file_path)
    except Exception as e:
        logging.error(" File handler initialization failed: %s", e)

    # 3. CONSOLE HANDLER
    if config.ENV != "production":
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(context_filter)
        root_logger.addHandler(console_handler)
        logging.debug(" Console logging enabled (development mode)")

    # 4. SYSLOG
    if os.getenv("LOG_EXTERNAL", "").lower() == "syslog":
        try:
            syslog_handler = SysLogHandler(address=("localhost", 514))
            syslog_handler.setLevel(logging.WARNING)
            syslog_handler.setFormatter(formatter)
            syslog_handler.addFilter(context_filter)
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
            http_handler.addFilter(context_filter)
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