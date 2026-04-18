"""OpenSearch response parser for Wazuh Indexer results.

Extracts ``_source`` from each hit, strips sparse/null fields to reduce
token cost when passing data to the LLM, and returns a typed ``ParsedResponse``.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedResponse:
    """Cleaned result of a single OpenSearch query execution.

    ``hits`` contains one dict per document, each being the cleaned ``_source``
    with null/empty values removed.  ``total`` is the full match count reported
    by OpenSearch (may exceed ``len(hits)`` when the query used a size cap).
    """

    hits: list[dict[str, Any]]
    total: int
    took_ms: int

    def is_empty(self) -> bool:
        """Return True when the query matched no documents."""
        return len(self.hits) == 0


def strip_empty(obj: Any) -> Any:
    """Recursively remove null and empty values from a nested structure.

    Removes:
    - ``None``
    - empty strings ``""``
    - empty dicts ``{}``
    - empty lists ``[]``

    All other values (including ``0``, ``False``, and ``"0"``) are preserved.

    Args:
        obj: Any JSON-compatible value (dict, list, scalar).

    Returns:
        The cleaned value, or ``None`` if the top-level object is itself empty
        after cleaning (callers should handle this case).
    """
    if isinstance(obj, dict):
        cleaned = {k: strip_empty(v) for k, v in obj.items()}
        return {
            k: v
            for k, v in cleaned.items()
            if v is not None and v != "" and v != {} and v != []
        }
    if isinstance(obj, list):
        cleaned = [strip_empty(item) for item in obj]
        return [
            item
            for item in cleaned
            if item is not None and item != "" and item != {} and item != []
        ]
    return obj


def parse_hits(
    response: dict[str, Any],
    keep_full_log: bool = False,
) -> ParsedResponse:
    """Parse a raw OpenSearch search response into a ``ParsedResponse``.

    Extracts ``_source`` from every hit, optionally drops the ``full_log``
    field (a raw-string duplicate of the structured ``data`` sub-tree), and
    strips all null/empty values to minimise token cost when the result is
    later serialised for the LLM.

    Args:
        response:      Raw dict returned by ``opensearchpy.OpenSearch.search``.
        keep_full_log: When ``False`` (default) the ``full_log`` key is removed
                       from each source document before cleaning.

    Returns:
        A ``ParsedResponse`` with cleaned hits, total match count, and query
        execution time in milliseconds.
    """
    raw_hits: list[dict[str, Any]] = response.get("hits", {}).get("hits", [])
    total: int = response.get("hits", {}).get("total", {}).get("value", 0)
    took_ms: int = response.get("took", 0)

    hits: list[dict[str, Any]] = []
    for hit in raw_hits:
        source: dict[str, Any] = dict(hit.get("_source", {}))
        if not keep_full_log:
            source.pop("full_log", None)
        hits.append(strip_empty(source))

    return ParsedResponse(hits=hits, total=total, took_ms=took_ms)
