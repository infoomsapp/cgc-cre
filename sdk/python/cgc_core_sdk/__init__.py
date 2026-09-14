from .client import CGCCoreClient, DEFAULT_BASE_URL
from .exceptions import CGCCoreAPIError, CGCCoreAuthError, CGCCoreError

__all__ = [
    "CGCCoreClient",
    "DEFAULT_BASE_URL",
    "CGCCoreError",
    "CGCCoreAPIError",
    "CGCCoreAuthError",
]

__version__ = "0.1.0"
