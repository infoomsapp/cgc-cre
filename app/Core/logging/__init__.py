"""
CGC CORE™ Logging Subsystem
Provides unified logging pipeline:
- File logging
- Console logging
- Database audit logging
- External syslog/HTTP integrations
"""

from .logging_config import setup_logging, get_logger, CGCLoggingHandler

__all__ = [
    "setup_logging",
    "get_logger",
    "CGCLoggingHandler",
]
