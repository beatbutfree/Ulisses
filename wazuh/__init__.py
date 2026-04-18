"""Wazuh Indexer package.

Public surface::

    from wazuh import WazuhIndexerClient, ParsedResponse, parse_hits, strip_empty
"""

from wazuh.client import DEFAULT_INDEX, WazuhIndexerClient
from wazuh.parser import ParsedResponse, parse_hits, strip_empty

__all__ = [
    "WazuhIndexerClient",
    "ParsedResponse",
    "parse_hits",
    "strip_empty",
    "DEFAULT_INDEX",
]
