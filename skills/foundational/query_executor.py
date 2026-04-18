"""QueryExecutorSkill — runs a DSL JSON string against the Wazuh Indexer.

Validates the incoming DSL JSON string, executes it via ``WazuhIndexerClient``,
and returns cleaned hits **and** raw aggregations in ``SkillResult.data``.

Pass ``size=0`` in context for aggregation-only queries (analysis skills).

This skill is **not** registered in ``SkillRegistry`` — it requires constructor
injection and is wired up directly by the agent loop in Step 5.
"""

import json
from typing import Any

from opensearchpy.exceptions import ConnectionError as OSConnectionError
from opensearchpy.exceptions import TransportError

from skills.base import InputType, Skill, SkillResult
from wazuh.client import DEFAULT_INDEX, WazuhIndexerClient
from wazuh.parser import parse_hits


class QueryExecutorSkill(Skill):
    """Execute a validated OpenSearch DSL JSON string and return results.

    ``value`` — DSL JSON string produced by ``QueryBuilderSkill``.

    Optional context keys:

    - ``"index"``        (str)  — override the default ``wazuh-archives-*`` index.
    - ``"size"``         (int)  — max hits to return; use ``0`` for aggregation
                                  queries (default 100).
    - ``"keep_full_log"`` (bool) — retain raw ``full_log`` strings in hits
                                   (default ``False``).

    On success ``SkillResult.data`` contains::

        {
            "hits":         [ ... ],   # cleaned _source dicts (empty when size=0)
            "total":        <int>,     # total matching documents
            "took_ms":      <int>,
            "aggregations": { ... }    # raw OpenSearch aggregation result (may be {})
        }
    """

    name: str = "query_executor"
    description: str = (
        "Validates and executes an OpenSearch DSL JSON string against the "
        "Wazuh Indexer, returning cleaned hits and aggregations."
    )
    input_type: InputType = InputType.QUERY_DSL

    def __init__(self, client: WazuhIndexerClient) -> None:
        """
        Args:
            client: A configured ``WazuhIndexerClient``.  Use
                    ``WazuhIndexerClient.from_env()`` in production or inject
                    a mock in tests.
        """
        self._client = client

    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        """Validate ``value`` as DSL JSON and execute against the indexer.

        Args:
            value:   DSL JSON string to execute.
            context: Optional overrides — ``"index"``, ``"size"``,
                     ``"keep_full_log"``.

        Returns:
            Successful ``SkillResult`` with hits + aggregations, or a failed
            result on invalid JSON or indexer errors.
        """
        # --- Validate DSL JSON -----------------------------------------------
        try:
            dsl = json.loads(value)
        except json.JSONDecodeError as exc:
            return SkillResult.fail(f"Invalid DSL — not valid JSON: {exc}")

        if not isinstance(dsl, dict):
            return SkillResult.fail(
                f"Invalid DSL — expected a JSON object, got {type(dsl).__name__}."
            )

        # --- Execute ---------------------------------------------------------
        index: str = context.get("index", DEFAULT_INDEX)
        size: int = int(context.get("size", 100))
        keep_full_log: bool = bool(context.get("keep_full_log", False))

        try:
            raw = self._client.execute_query(dsl, index=index, size=size)
        except OSConnectionError as exc:
            return SkillResult.fail(f"Indexer unreachable: {exc}")
        except TransportError as exc:
            return SkillResult.fail(f"Query execution failed: {exc}")

        parsed = parse_hits(raw, keep_full_log=keep_full_log)
        aggregations: dict[str, Any] = raw.get("aggregations", {})

        # --- Summarise -------------------------------------------------------
        if parsed.total == 0:
            summary = "Query returned no results."
        else:
            summary = (
                f"Query matched {parsed.total} document(s), "
                f"{len(parsed.hits)} returned, in {parsed.took_ms} ms."
            )

        return SkillResult(
            data={
                "hits": parsed.hits,
                "total": parsed.total,
                "took_ms": parsed.took_ms,
                "aggregations": aggregations,
            },
            summary=summary,
            success=True,
        )
