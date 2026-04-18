"""Wazuh Indexer client.

Thin wrapper around the OpenSearch Python SDK that targets the Wazuh Indexer
(OpenSearch on port 9200).  Handles connection setup, SSL, and basic-auth.
All alert/event data lives here — the Wazuh manager REST API (port 55000) is
for cluster management and is *not* used by the agent.
"""

import os
from typing import Any
from urllib.parse import urlparse

import urllib3
from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError as OSConnectionError
from opensearchpy.exceptions import TransportError

from dotenv import load_dotenv

from wazuh.parser import ParsedResponse, parse_hits


DEFAULT_INDEX = "wazuh-archives-*"


class WazuhIndexerClient:
    """OpenSearch client scoped to the Wazuh Indexer.

    Creates and owns a single ``opensearchpy.OpenSearch`` connection.
    Use ``from_env()`` to instantiate from ``.env`` / environment variables.

    Args:
        url:        Full base URL of the OpenSearch endpoint,
                    e.g. ``https://10.0.0.1:9200``.
        user:       Basic-auth username.
        password:   Basic-auth password.
        verify_ssl: Whether to verify TLS certificates.  Set ``False`` for
                    self-signed certificates (Wazuh default).
    """

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        verify_ssl: bool = False,
    ) -> None:
        parsed = urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 9200)
        use_ssl = parsed.scheme == "https"

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_auth=(user, password),
            use_ssl=use_ssl,
            verify_certs=verify_ssl,
            ssl_show_warn=verify_ssl,
        )

    @classmethod
    def from_env(cls) -> "WazuhIndexerClient":
        """Instantiate from environment variables (loads ``.env`` automatically).

        Required variables::

            WAZUH_INDEXER_URL    — e.g. https://10.0.0.1:9200
            WAZUH_API_USER       — OpenSearch username
            WAZUH_API_PASSWORD   — OpenSearch password

        Returns:
            A configured ``WazuhIndexerClient``.

        Raises:
            KeyError: If any required environment variable is missing.
        """
        load_dotenv()
        return cls(
            url=os.environ["WAZUH_INDEXER_URL"],
            user=os.environ["WAZUH_API_USER"],
            password=os.environ["WAZUH_API_PASSWORD"],
        )

    def ping(self) -> bool:
        """Return ``True`` if the indexer is reachable, ``False`` otherwise."""
        try:
            return bool(self._client.ping())
        except (OSConnectionError, TransportError):
            return False

    def execute_query(
        self,
        query: dict[str, Any],
        index: str = DEFAULT_INDEX,
        size: int = 100,
    ) -> dict[str, Any]:
        """Run an OpenSearch DSL query and return the raw response.

        The ``size`` parameter caps how many hits are returned per request.
        For large result sets, callers are responsible for pagination (e.g.
        using ``search_after`` in the query body).

        Args:
            query: A valid OpenSearch query dict (DSL ``query`` key and any
                   aggregations, sorts, or filters).
            index: Index pattern to search.  Defaults to ``wazuh-archives-*``.
            size:  Maximum number of hits to return.  Defaults to 100.

        Returns:
            The raw OpenSearch response dict.

        Raises:
            TransportError: On HTTP-level errors (4xx / 5xx) from OpenSearch.
            OSConnectionError: When the indexer is unreachable.
        """
        return self._client.search(body=query, index=index, size=size)  # type: ignore[no-any-return]

    def query(
        self,
        query: dict[str, Any],
        index: str = DEFAULT_INDEX,
        size: int = 100,
        keep_full_log: bool = False,
    ) -> ParsedResponse:
        """Execute a query and return a cleaned ``ParsedResponse``.

        Convenience method that chains ``execute_query`` → ``parse_hits``.
        Use ``execute_query`` directly when you need the raw envelope (e.g.
        for aggregations or scroll cursors).

        Args:
            query:         OpenSearch DSL query dict.
            index:         Index pattern.  Defaults to ``wazuh-archives-*``.
            size:          Max hits.  Defaults to 100.
            keep_full_log: Pass ``True`` to preserve the raw ``full_log``
                           string in each hit.  Defaults to ``False``.

        Returns:
            A ``ParsedResponse`` with cleaned ``_source`` dicts.
        """
        raw = self.execute_query(query, index=index, size=size)
        return parse_hits(raw, keep_full_log=keep_full_log)
