"""
CGC Core — Logging Configuration
Wrapper sobre logging estándar de Python.
Permite que los módulos importen get_logger sin importar el contexto.

Olympus Mont Systems LLC © 2026
"""

import logging
import os
from typing import Optional


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.
    Compatible with all CGC Core modules that do:
        from app.Core.logging import get_logger
        logger = get_logger("cgc.module_name")
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = "%(asctime)s [%(name)s] [%(levelname)s] %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)

    log_level = level or os.getenv("SCM_LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    return logger