"""QueryCrafterSkill — synthesises a novel OpenSearch DSL on demand.

The analyst calls this skill when neither a battle-tested analysis skill nor
ChromaDB retrieval produced useful results. An internal LLM call generates a
DSL query tailored to the supplied ``goal``, ``input_type``, ``security_component``
and ``extra_context``. The query is then validated **by executing it** against
the security component: HTTP failure ⇒ invalid syntax (retry once); zero
results ⇒ valid query with no matches, which is information, not failure.

Every invocation appends a ``query_crafted`` record to
``context["skill_log"]`` so the ``ReflectorAgent`` can later evaluate whether
to promote the crafted DSL to ChromaDB.
"""

from __future__ import annotations

import json
from typing import Any

import anthropic

from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_executor import QueryExecutorSkill

_MAX_VALIDATION_ATTEMPTS = 2   # first try + one retry with error feedback

_SYSTEM_PROMPT = """\
You are an OpenSearch DSL specialist.

Given a natural-language goal, an observable type, a security component
(default: "wazuh") and optional extra context, produce ONE OpenSearch DSL JSON
object that answers the goal.

Hard rules:
- Output ONE and ONLY ONE tool call to `emit_query` — no prose.
- The DSL must be a valid OpenSearch query body (object with `query`, and
  optionally `aggs`, `size`, `sort`).
- Do NOT wrap the DSL in markdown fences.
- If you are retrying after a previous syntax error, fix the issue —
  the exact error message is attached to the user message.
"""

_EMIT_QUERY_TOOL: dict[str, Any] = {
    "name": "emit_query",
    "description": "Emit the crafted OpenSearch DSL. Call exactly once.",
    "input_schema": {
        "type": "object",
        "properties": {
            "dsl": {
                "type": "string",
                "description": "Complete DSL JSON body as a string.",
            },
            "parameters": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Placeholder names appearing in the DSL as "
                    "`{{name}}` — empty list if the DSL is fully concrete."
                ),
            },
        },
        "required": ["dsl", "parameters"],
    },
}


class QueryCrafterSkill(Skill):
    """Generic skill that crafts, validates, and executes a novel DSL query.

    Tool parameters (read from ``context["tool_input"]``)::

        goal:               natural-language description of what to find
        input_type:         ip_address | username | rule_id | event_id
        security_component: "wazuh"  (future: elastic | splunk)
        value:              concrete observable value (may be empty)
        extra_context:      free prose — cluster names, time bounds, etc.

    Returns ``SkillResult`` whose ``data`` contains::

        {
            "hits": [...],
            "total": <int>,
            "result_count": <int>,
            "aggregations": {...},
            "crafted_dsl": "<DSL JSON string>",
            "parameters": [...],
            "attempts": <int>,
        }

    ``result_count == 0`` is a valid, successful outcome.
    """

    name: str = "query_crafter"
    description: str = (
        "Craft a NEW OpenSearch DSL query on demand when existing skills and "
        "ChromaDB retrieval have not answered the investigative goal. The "
        "skill validates the query by executing it and returns the results."
    )
    input_type: InputType = InputType.META
    is_generic: bool = True
    tool_input_schema: dict[str, Any] | None = {
        "type": "object",
        "properties": {
            "goal": {
                "type": "string",
                "description": (
                    "Natural-language description of what the query should "
                    "find. Be specific about fields, time windows, filters."
                ),
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
            "extra_context": {
                "type": "string",
                "description": (
                    "Free-form context useful to the LLM crafter: decoder "
                    "name, relevant fields, time bounds, prior findings."
                ),
            },
        },
        "required": ["goal", "input_type", "security_component"],
    }

    def __init__(
        self,
        client: anthropic.Anthropic,
        executor: QueryExecutorSkill,
        model: str | None = None,
    ) -> None:
        """
        Args:
            client:   Anthropic SDK client used to craft the DSL.
            executor: ``QueryExecutorSkill`` used both to validate and to run
                      the crafted DSL.
            model:    Override the model ID; defaults to ``$ANTHROPIC_MODEL``
                      or ``claude-sonnet-4-6``.
        """
        import os

        self._client = client
        self._executor = executor
        self._model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _craft(self, user_message: str) -> tuple[str, list[str]]:
        """Single LLM round-trip → ``(dsl_string, parameter_names)``."""
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            tools=[_EMIT_QUERY_TOOL],
            tool_choice={"type": "tool", "name": "emit_query"},
            messages=[{"role": "user", "content": user_message}],
        )
        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "emit_query":
                dsl = block.input.get("dsl", "")
                params = block.input.get("parameters", [])
                return dsl, list(params)
        raise RuntimeError("Crafter model did not call emit_query.")

    def _user_message(
        self,
        goal: str,
        input_type: str,
        security_component: str,
        value: str,
        extra_context: str,
        previous_error: str | None,
    ) -> str:
        lines = [
            f"<goal>{goal}</goal>",
            f"<input_type>{input_type}</input_type>",
            f"<security_component>{security_component}</security_component>",
            f"<value>{value}</value>",
            f"<extra_context>{extra_context}</extra_context>",
        ]
        if previous_error:
            lines.append(f"<previous_syntax_error>{previous_error}</previous_syntax_error>")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Public _run
    # ------------------------------------------------------------------
    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        tool_input: dict[str, Any] = context.get("tool_input", {})
        goal: str = tool_input.get("goal", "")
        input_type: str = tool_input.get("input_type", "")
        security_component: str = tool_input.get("security_component", "")
        observable_value: str = tool_input.get("value", value)
        extra_context: str = tool_input.get("extra_context", "")

        if not goal or not input_type or not security_component:
            return SkillResult.fail(
                "query_crafter requires non-empty 'goal', 'input_type', "
                "and 'security_component'."
            )

        skill_log: list[dict[str, Any]] = context.get("skill_log", [])

        crafted_dsl = ""
        parameters: list[str] = []
        last_error: str | None = None
        exec_result: SkillResult | None = None

        for attempt in range(1, _MAX_VALIDATION_ATTEMPTS + 1):
            try:
                crafted_dsl, parameters = self._craft(
                    self._user_message(
                        goal, input_type, security_component,
                        observable_value, extra_context, last_error,
                    )
                )
            except Exception as exc:
                last_error = f"crafter_llm_error: {exc}"
                continue

            # Reject templates that still contain placeholders — we cannot
            # execute them without substitution and the crafter is expected
            # to produce a concrete query for this observable.
            if "{{" in crafted_dsl:
                last_error = (
                    "DSL contains unresolved {{placeholders}} — produce a "
                    "concrete query using the supplied <value>."
                )
                continue

            exec_result = self._executor.execute(value=crafted_dsl, context={"size": 100})
            if exec_result.success:
                last_error = None
                break
            last_error = exec_result.summary

        data: dict[str, Any] = {
            "crafted_dsl": crafted_dsl,
            "parameters": parameters,
            "attempts": attempt,
        }

        if exec_result is not None and exec_result.success:
            result_count = int(exec_result.data.get("total", 0))
            data.update(
                {
                    "hits": exec_result.data.get("hits", []),
                    "total": result_count,
                    "result_count": result_count,
                    "aggregations": exec_result.data.get("aggregations", {}),
                }
            )
            record_success = True
            summary = (
                f"Crafted DSL returned {result_count} document(s) "
                f"after {attempt} attempt(s)."
            )
        else:
            result_count = 0
            data["error"] = last_error or "crafter failed"
            record_success = False
            summary = (
                f"Query crafter failed after {attempt} attempt(s): "
                f"{last_error or 'unknown error'}."
            )

        skill_log.append(
            {
                "kind": "query_crafted",
                "skill_name": self.name,
                "goal": goal,
                "input_type": input_type,
                "security_component": security_component,
                "sec_comp_extra": tool_input.get("sec_comp_extra", ""),
                "value": observable_value,
                "crafted_dsl": crafted_dsl,
                "parameters": parameters,
                "extra_context": extra_context,
                "result_count": result_count,
                "success": record_success,
                "error": last_error or "",
            }
        )

        return SkillResult(
            data=data,
            summary=summary,
            success=record_success,
        )
