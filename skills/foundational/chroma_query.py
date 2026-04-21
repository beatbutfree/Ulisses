"""ChromaQuerySkill — retrieves a stored DSL template from ChromaDB and runs it.

Invoked by the analyst when the battle-tested analysis skills have not fully
answered its goal. The skill:

1. Hard-filters ChromaDB by ``security_component`` and ``input_type``.
2. Performs a semantic search over stored ``description + goal`` text using
   the caller-supplied ``goal``.
3. Passes the top candidates to an internal LLM which either (a) selects one
   verbatim, (b) substitutes placeholders with the caller's ``value`` and
   any extra context, or (c) returns ``no_match`` signalling the analyst
   should fall back to the ``QueryCrafterSkill``.
4. Executes the resulting DSL via ``QueryExecutorSkill``.

Every invocation appends a ``chroma_retrieved`` record to
``context["skill_log"]`` so the ``ReflectorAgent`` can update usage
counters post-run.
"""

from __future__ import annotations

import json
import os
from typing import Any

import anthropic

from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_executor import QueryExecutorSkill
from store.chroma_client import ChromaQueryStore, StoredQuery


_TOP_K = 3

_SYSTEM_PROMPT = """\
You pick the best-fit OpenSearch DSL template for an investigation goal.

You receive up to N candidate templates retrieved from a knowledge base, plus
a description of the investigator's goal, the observable value, and optional
extra context.

Produce EXACTLY ONE tool call to `select_template`:
- `action = "use_as_is"`   — one candidate already fits; return its ID and the
                             fully-substituted DSL (no {{placeholders}} left).
- `action = "modify"`      — a candidate is close; return its ID and the
                             modified DSL with placeholders substituted and
                             structure tweaked as needed.
- `action = "no_match"`    — no candidate is a reasonable fit; the analyst
                             should fall back to the query_crafter skill.

The returned DSL MUST be a syntactically valid OpenSearch query body.
Never wrap it in markdown fences.
"""

_SELECT_TEMPLATE_TOOL: dict[str, Any] = {
    "name": "select_template",
    "description": "Select, modify, or reject candidate templates.",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["use_as_is", "modify", "no_match"],
            },
            "query_id": {
                "type": "string",
                "description": "Chosen candidate ID — required unless action is 'no_match'.",
            },
            "dsl": {
                "type": "string",
                "description": (
                    "Final DSL JSON body, placeholders already substituted. "
                    "Required unless action is 'no_match'."
                ),
            },
            "reason": {
                "type": "string",
                "description": "Short rationale; required when action is 'no_match'.",
            },
        },
        "required": ["action"],
    },
}


def _format_candidates(candidates: list[StoredQuery]) -> str:
    if not candidates:
        return "(none)"
    blocks = []
    for c in candidates:
        blocks.append(
            f"<candidate id=\"{c.id}\">\n"
            f"  <description>{c.description}</description>\n"
            f"  <goal>{c.goal}</goal>\n"
            f"  <parameters>{','.join(c.parameters)}</parameters>\n"
            f"  <query>{c.query}</query>\n"
            f"  <times_used>{c.times_used}</times_used>\n"
            f"  <times_successful>{c.times_successful}</times_successful>\n"
            f"</candidate>"
        )
    return "\n".join(blocks)


class ChromaQuerySkill(Skill):
    """Generic skill: retrieves and runs a stored query from ChromaDB.

    Tool parameters (read from ``context["tool_input"]``)::

        goal:               natural-language description
        input_type:         ip_address | username | rule_id | event_id
        security_component: "wazuh"
        value:              concrete observable value

    ``SkillResult.data`` on success::

        {
            "matched":       True,
            "query_id":      "<ChromaDB document ID>",
            "was_modified":  <bool>,
            "executed_dsl":  "<DSL JSON string>",
            "hits": [...],
            "total": <int>,
            "result_count": <int>,
            "aggregations": {...}
        }

    When no candidate fits, ``data`` is::

        {"matched": False, "reason": "<LLM rationale>"}

    — the analyst should then call ``query_crafter``.
    """

    name: str = "chroma_query"
    description: str = (
        "Semantically retrieve a stored DSL template from ChromaDB and run "
        "it. Filters by security_component + input_type before embedding "
        "search. Call this before falling back to query_crafter."
    )
    input_type: InputType = InputType.META
    is_generic: bool = True
    tool_input_schema: dict[str, Any] | None = {
        "type": "object",
        "properties": {
            "goal": {
                "type": "string",
                "description": "Natural-language description of what to find.",
            },
            "input_type": {
                "type": "string",
                "enum": ["ip_address", "username", "rule_id", "event_id"],
            },
            "security_component": {
                "type": "string",
                "description": "Target platform, e.g. 'wazuh'.",
            },
            "value": {
                "type": "string",
                "description": "Concrete observable value (can be empty).",
            },
        },
        "required": ["goal", "input_type", "security_component"],
    }

    def __init__(
        self,
        client: anthropic.Anthropic,
        store: ChromaQueryStore,
        executor: QueryExecutorSkill,
        model: str | None = None,
        top_k: int = _TOP_K,
    ) -> None:
        self._client = client
        self._store = store
        self._executor = executor
        self._model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        self._top_k = top_k

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _evaluate(
        self,
        goal: str,
        value: str,
        candidates: list[StoredQuery],
    ) -> dict[str, Any]:
        """Single LLM round-trip returning the ``select_template`` tool input."""
        user = (
            f"<goal>{goal}</goal>\n"
            f"<value>{value}</value>\n"
            f"<candidates>\n{_format_candidates(candidates)}\n</candidates>"
        )
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            tools=[_SELECT_TEMPLATE_TOOL],
            tool_choice={"type": "tool", "name": "select_template"},
            messages=[{"role": "user", "content": user}],
        )
        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "select_template":
                return dict(block.input)
        raise RuntimeError("Chroma evaluator did not call select_template.")

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------
    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        tool_input: dict[str, Any] = context.get("tool_input", {})
        goal: str = tool_input.get("goal", "")
        input_type: str = tool_input.get("input_type", "")
        security_component: str = tool_input.get("security_component", "")
        observable_value: str = tool_input.get("value", value)

        if not goal or not input_type or not security_component:
            return SkillResult.fail(
                "chroma_query requires non-empty 'goal', 'input_type', "
                "and 'security_component'."
            )

        skill_log: list[dict[str, Any]] = context.get("skill_log", [])

        candidates = self._store.search(
            goal=goal,
            security_component=security_component,
            input_type=input_type,
            k=self._top_k,
        )

        if not candidates:
            skill_log.append(
                {
                    "kind": "chroma_retrieved",
                    "skill_name": self.name,
                    "goal": goal,
                    "input_type": input_type,
                    "security_component": security_component,
                    "value": observable_value,
                    "query_id": "",
                    "was_modified": False,
                    "result_count": 0,
                    "success": False,
                    "error": "no_candidates_in_store",
                }
            )
            return SkillResult(
                data={"matched": False, "reason": "no candidates in ChromaDB"},
                summary="ChromaDB has no stored queries matching the filters.",
                success=True,
            )

        try:
            decision = self._evaluate(goal, observable_value, candidates)
        except Exception as exc:
            return SkillResult.fail(f"Chroma evaluator error: {exc}")

        action = decision.get("action", "no_match")
        query_id = decision.get("query_id", "")
        dsl = decision.get("dsl", "")
        reason = decision.get("reason", "")

        if action == "no_match" or not dsl:
            skill_log.append(
                {
                    "kind": "chroma_retrieved",
                    "skill_name": self.name,
                    "goal": goal,
                    "input_type": input_type,
                    "security_component": security_component,
                    "value": observable_value,
                    "query_id": query_id,
                    "was_modified": False,
                    "result_count": 0,
                    "success": False,
                    "error": reason or "no_match",
                }
            )
            return SkillResult(
                data={"matched": False, "reason": reason or "no candidate fit"},
                summary=f"No stored template fit: {reason or 'no_match'}.",
                success=True,
            )

        was_modified = action == "modify"
        exec_result = self._executor.execute(value=dsl, context={"size": 100})

        result_count = (
            int(exec_result.data.get("total", 0)) if exec_result.success else 0
        )

        skill_log.append(
            {
                "kind": "chroma_retrieved",
                "skill_name": self.name,
                "goal": goal,
                "input_type": input_type,
                "security_component": security_component,
                "value": observable_value,
                "query_id": query_id,
                "was_modified": was_modified,
                "result_count": result_count,
                "success": exec_result.success,
                "error": "" if exec_result.success else exec_result.summary,
            }
        )

        if not exec_result.success:
            return SkillResult(
                data={
                    "matched": True,
                    "query_id": query_id,
                    "was_modified": was_modified,
                    "executed_dsl": dsl,
                    "error": exec_result.summary,
                },
                summary=f"Retrieved template failed to execute: {exec_result.summary}",
                success=False,
            )

        return SkillResult(
            data={
                "matched": True,
                "query_id": query_id,
                "was_modified": was_modified,
                "executed_dsl": dsl,
                "hits": exec_result.data.get("hits", []),
                "total": result_count,
                "result_count": result_count,
                "aggregations": exec_result.data.get("aggregations", {}),
            },
            summary=(
                f"Retrieved template {query_id} "
                f"({'modified' if was_modified else 'as-is'}) returned "
                f"{result_count} document(s)."
            ),
            success=True,
        )
