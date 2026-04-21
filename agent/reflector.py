"""ReflectorAgent — post-run knowledge-store update.

Runs as the last node in the pipeline. Consumes:

- ``skill_log``       — buffer populated by ``ChromaQuerySkill`` and
                        ``QueryCrafterSkill`` during the analyst loop.
- ``evaluator_doc``   — XML assessment containing the verdict + confidence.

Behaviour:

- ``chroma_retrieved`` records → increment ``times_used`` (always) and
  ``times_successful`` (when the query returned a non-zero result AND the
  evaluator verdict was ``true_positive``).
- ``query_crafted`` records   → decide whether to promote to ChromaDB.
  A promotion requires: successful execution AND a non-zero ``result_count``
  AND either a ``true_positive`` verdict OR (``inconclusive`` with
  confidence ≥ 0.6). When promoted, the reflector asks the LLM to generate
  ``description`` + ``goal`` for the new document.

The reflector never modifies the final report — it runs purely for side
effects on the knowledge base.
"""

from __future__ import annotations

import os
import re
from typing import Any

import anthropic

from store.chroma_client import ChromaQueryStore, StoredQuery

_MODEL_ENV = "ANTHROPIC_MODEL"
_DEFAULT_MODEL = "claude-sonnet-4-6"

_PROMOTE_CONFIDENCE_THRESHOLD = 0.6

_DESCRIBE_SYSTEM = """\
You write concise, semantically searchable metadata for a new OpenSearch
DSL template that is about to be stored in a knowledge base.

Produce EXACTLY ONE tool call to `describe_query`:
- `description` — one sentence: what the query finds and when to use it.
- `goal`        — one short paragraph: the investigative intent, including
                  which fields/conditions it relies on.
"""

_DESCRIBE_TOOL: dict[str, Any] = {
    "name": "describe_query",
    "description": "Produce description + goal for a new ChromaDB document.",
    "input_schema": {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "goal": {"type": "string"},
        },
        "required": ["description", "goal"],
    },
}


def _parse_verdict(evaluator_doc: str) -> tuple[str, float]:
    """Extract ``(verdict, confidence)`` from the evaluator's XML.

    Returns ``("unknown", 0.0)`` when parsing fails — the reflector treats
    that as low-confidence and conservatively skips promotion.
    """
    verdict_match = re.search(r"<verdict>\s*(.*?)\s*</verdict>", evaluator_doc, re.DOTALL)
    confidence_match = re.search(
        r"<confidence>\s*([0-9.]+)\s*</confidence>", evaluator_doc, re.DOTALL
    )
    verdict = verdict_match.group(1).strip() if verdict_match else "unknown"
    try:
        confidence = float(confidence_match.group(1)) if confidence_match else 0.0
    except ValueError:
        confidence = 0.0
    return verdict, confidence


class ReflectorAgent:
    """Updates the ChromaDB knowledge base based on what happened in a run."""

    def __init__(
        self,
        client: anthropic.Anthropic,
        store: ChromaQueryStore,
        model: str | None = None,
    ) -> None:
        """
        Args:
            client: Anthropic SDK client for description generation.
            store:  Destination ``ChromaQueryStore``.
            model:  Optional override, defaults to ``$ANTHROPIC_MODEL`` or
                    ``claude-sonnet-4-6``.
        """
        self._client = client
        self._store = store
        self._model = model or os.getenv(_MODEL_ENV, _DEFAULT_MODEL)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def run(
        self,
        skill_log: list[dict[str, Any]],
        evaluator_doc: str,
    ) -> dict[str, Any]:
        """Apply reflector decisions based on the run's log + verdict.

        Returns a summary dict describing the side effects, useful for
        structured logging and tests.
        """
        verdict, confidence = _parse_verdict(evaluator_doc)

        counters_touched = 0
        promoted: list[str] = []
        skipped_crafted: int = 0

        for record in skill_log:
            kind = record.get("kind")

            if kind == "chroma_retrieved":
                query_id = record.get("query_id") or ""
                if not query_id:
                    continue
                useful = (
                    record.get("success", False)
                    and record.get("result_count", 0) > 0
                    and verdict == "true_positive"
                )
                self._store.increment_counters(query_id=query_id, success=useful)
                counters_touched += 1
                continue

            if kind == "query_crafted":
                if self._should_promote(record, verdict, confidence):
                    new_id = self._promote(record)
                    if new_id is not None:
                        promoted.append(new_id)
                else:
                    skipped_crafted += 1

        return {
            "verdict": verdict,
            "confidence": confidence,
            "counters_touched": counters_touched,
            "promoted_ids": promoted,
            "skipped_crafted": skipped_crafted,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _should_promote(
        self,
        record: dict[str, Any],
        verdict: str,
        confidence: float,
    ) -> bool:
        if not record.get("success", False):
            return False
        if record.get("result_count", 0) <= 0:
            return False
        if verdict == "true_positive":
            return True
        if verdict == "inconclusive" and confidence >= _PROMOTE_CONFIDENCE_THRESHOLD:
            return True
        return False

    def _describe(self, record: dict[str, Any]) -> tuple[str, str]:
        """LLM round-trip → ``(description, goal)`` for a new stored query."""
        user = (
            f"<input_type>{record.get('input_type', '')}</input_type>\n"
            f"<security_component>{record.get('security_component', '')}</security_component>\n"
            f"<original_goal>{record.get('goal', '')}</original_goal>\n"
            f"<extra_context>{record.get('extra_context', '')}</extra_context>\n"
            f"<dsl>{record.get('crafted_dsl', '')}</dsl>"
        )
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=_DESCRIBE_SYSTEM,
            tools=[_DESCRIBE_TOOL],
            tool_choice={"type": "tool", "name": "describe_query"},
            messages=[{"role": "user", "content": user}],
        )
        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "describe_query":
                return (
                    block.input.get("description", "") or record.get("goal", ""),
                    block.input.get("goal", "") or record.get("goal", ""),
                )
        return record.get("goal", ""), record.get("goal", "")

    def _promote(self, record: dict[str, Any]) -> str | None:
        try:
            description, goal = self._describe(record)
        except Exception:
            # Describe failure should not crash the pipeline — fall back to
            # the analyst's original goal as both fields.
            description = record.get("goal", "")
            goal = record.get("goal", "")

        stored = StoredQuery(
            description=description,
            query=record.get("crafted_dsl", ""),
            parameters=list(record.get("parameters", [])),
            security_component=record.get("security_component", ""),
            sec_comp_extra=record.get("sec_comp_extra", ""),
            input_type=record.get("input_type", ""),
            goal=goal,
        )
        self._store.add(stored)
        return stored.id
