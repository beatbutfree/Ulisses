"""QueryBuilderSkill — assembles a ready-to-execute DSL JSON string.

Retrieves a named template from an ``InMemoryTemplateStore`` (Step 6: ChromaDB),
substitutes ``{{placeholder}}`` values from ``context["params"]``, and returns
the completed DSL JSON string in ``SkillResult.data["query"]``.

This skill is **not** registered in ``SkillRegistry`` — it requires constructor
injection and is wired up directly by the agent loop in Step 5.
"""

import json
import re
from typing import Any

from skills.base import InputType, Skill, SkillResult
from skills.foundational.template_store import InMemoryTemplateStore, QueryTemplate


def _substitute(template: str, params: dict[str, Any]) -> str:
    """Replace ``{{key}}`` placeholders with their JSON-encoded values.

    Each placeholder is replaced with ``json.dumps(params[key])``, so:
    - strings produce quoted values  → ``"10.0.0.1"``
    - numbers produce bare literals → ``100``
    - lists/dicts produce valid JSON  → ``["a","b"]``

    The template author omits surrounding quotes around placeholders::

        "src_ip": {{src_ip}}      →  "src_ip": "10.0.0.1"
        "threshold": {{threshold}} →  "threshold": 100

    Args:
        template: DSL template string with ``{{name}}`` placeholders.
        params:   Mapping of placeholder names to Python values.

    Returns:
        The fully substituted string.

    Raises:
        KeyError: If a placeholder in the template has no entry in ``params``.
    """
    def _replacer(match: re.Match) -> str:  # type: ignore[type-arg]
        return json.dumps(params[match.group(1)], separators=(",", ":"))

    return re.sub(r"\{\{(\w+)\}\}", _replacer, template)


class QueryBuilderSkill(Skill):
    """Build a ready-to-execute OpenSearch DSL string from a named template.

    ``value``            — template name (exact match against the store).
    ``context["params"]`` — ``dict[str, Any]`` of placeholder substitutions.

    On success ``SkillResult.data`` contains::

        {
            "query":        "<DSL JSON string>",
            "template_name": "<name>",
            "params_used":  { ... }
        }

    The ``"query"`` value is passed directly as ``value`` to
    ``QueryExecutorSkill``.
    """

    name: str = "query_builder"
    description: str = (
        "Builds an OpenSearch DSL query string from a named template "
        "and a parameter map."
    )
    input_type: InputType = InputType.TEMPLATE_NAME

    def __init__(self, store: InMemoryTemplateStore) -> None:
        """
        Args:
            store: Template store to retrieve ``QueryTemplate`` objects from.
                   Pass an ``InMemoryTemplateStore`` for Steps 3–5; swap for
                   a ChromaDB-backed store in Step 6.
        """
        self._store = store

    @property
    def store(self) -> InMemoryTemplateStore:
        """Expose the template store so analysis skills can register templates."""
        return self._store

    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        """Build a DSL JSON string for template ``value``.

        Args:
            value:   Exact name of the template to use.
            context: Must contain ``"params"`` key with a ``dict[str, Any]``
                     of placeholder substitutions.  Extra keys are ignored.

        Returns:
            Successful ``SkillResult`` with ``data["query"]`` set, or a
            failed result if the template is missing or params are incomplete.
        """
        template: QueryTemplate | None = self._store.get(value)
        if template is None:
            return SkillResult.fail(f"Template '{value}' not found in store.")

        params: dict[str, Any] = context.get("params", {})
        missing = [p for p in template.params if p not in params]
        if missing:
            return SkillResult.fail(
                f"Template '{value}' requires params {template.params}; "
                f"missing: {missing}."
            )

        try:
            dsl_str = _substitute(template.template, params)
        except Exception as exc:
            return SkillResult.fail(f"Template substitution failed: {exc}")

        params_used = {k: params[k] for k in template.params}
        return SkillResult(
            data={
                "query": dsl_str,
                "template_name": template.name,
                "params_used": params_used,
            },
            summary=(
                f"Built DSL query from template '{template.name}' "
                f"with {len(template.params)} param(s)."
            ),
            success=True,
        )
