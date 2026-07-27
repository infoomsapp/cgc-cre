"""
CGC CORE™ Integrations Package
Olympus Mont Systems LLC

This package contains external system connectors used by the CGC CORE,
including SharePoint, Microsoft Graph, and future enterprise integrations.
"""

from .sharepoint_connector import SharePointConnector

__all__ = [
    "SharePointConnector",
]