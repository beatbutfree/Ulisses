"""AnalystAgent — investigates a Wazuh alert using the skill registry.

Runs an Anthropic tool-use loop. Each registered analysis skill is exposed
as a tool. The agent decides which skills to invoke, in what order, and
when the picture is complete enough to stop.

Output is an XML findings document consumed by the EvaluatorAgent.
"""

import json
import os
from typing import Any

import anthropic

from skills.registry import SkillRegistry

_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

_MAX_ITERATIONS = 10

# input_type values that belong to skills exposed to the analyst.
# META covers generic skills (chroma_query, query_crafter) which additionally
# bypass the decoder-prefix filter via ``is_generic=True``.
_ANALYSIS_INPUT_TYPES = {"ip_address", "username", "rule_id", "event_id", "meta"}

_SYSTEM_TEMPLATE = """\
You are a Tier-1 SOC analyst investigating a Wazuh security alert.
You have access to the skills listed below. Use them to investigate the
alert, looping until you have a complete picture of the incident.

Investigation order (follow strictly):
1. Run the battle-tested, decoder-specific skills for every observable in
   the alert.
2. If your picture is still incomplete, call `chroma_query` — it retrieves
   and runs a semantically similar stored query from the knowledge base.
   Supply a precise `goal`, the `input_type`, the `security_component`
   (e.g. "wazuh") and the concrete `value`. It may return `matched: false`
   — treat that as "no stored template fits".
3. If `chroma_query` returned no match, call `query_crafter`. It generates
   and executes a brand-new DSL query tailored to your goal. Include
   detailed `extra_context` (decoder name, relevant fields, time bounds,
   what you already tried).

Rules:
- Invoke skills by calling the corresponding tool.
- Only investigate observables that are present in the alert.
- If a skill returns empty results, record the absence and move on — do not retry.
- A query returning zero documents is a valid answer ("no such activity").
- Stop when you have enough information to brief a senior analyst.
- Do NOT make a TP/FP verdict — that belongs to the evaluator.

Available skills (decoder: {decoder_name}):
{skill_descriptions}

When finished, output your findings as XML blocks only — no prose outside them:

<finding>
  <observable>[value investigated]</observable>
  <skill_used>[skill name]</skill_used>
  <severity_signal>info | low | medium | high | critical</severity_signal>
  <notes>
    [free prose — anything you want to record, no formatting pressure]
  </notes>
</finding>

Use <open_question> for things you could not resolve:

<open_question>
  <topic>[topic]</topic>
  <notes>[what you tried and why it could not be answered]</notes>
</open_question>
"""


def _decoder_prefix(decoder_name: str) -> str:
    """Extract the leading word of a decoder name for skill filtering.

    ``windows_eventchannel`` → ``windows``, ``wazuh`` → ``wazuh``.
    """
    return decoder_name.split("_")[0]


def _is_exposed(skill: Any, prefix: str) -> bool:
    """True when the skill should appear in the analyst's tool list.

    Generic skills (``is_generic=True``) are exposed for every decoder;
    observable-specific skills are exposed only when their name begins
    with the decoder prefix.
    """
    if str(skill.input_type.value) not in _ANALYSIS_INPUT_TYPES:
        return False
    # Use identity check so MagicMock's auto-attribute doesn't accidentally
    # make every mocked skill look generic.
    if getattr(skill, "is_generic", False) is True:
        return True
    return skill.name.startswith(prefix)


def _build_tools(registry: SkillRegistry, decoder_name: str) -> list[dict[str, Any]]:
    """Build Anthropic tool definitions from skills eligible for this decoder."""
    prefix = _decoder_prefix(decoder_name)
    tools = []
    for skill in registry.all():
        if not _is_exposed(skill, prefix):
            continue

        # Generic skills carry their own multi-parameter input schema;
        # decoder-specific skills expose a single ``value`` field.
        custom_schema = getattr(skill, "tool_input_schema", None)
        if custom_schema is not None:
            input_schema = custom_schema
        else:
            input_schema = {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": (
                            f"The {skill.input_type.value} to investigate."
                        ),
                    }
                },
                "required": ["value"],
            }

        tools.append(
            {
                "name": skill.name,
                "description": skill.description,
                "input_schema": input_schema,
            }
        )
    return tools


def _build_system(registry: SkillRegistry, decoder_name: str) -> str:
    """Build the analyst system prompt with skill descriptions injected."""
    prefix = _decoder_prefix(decoder_name)
    lines = [
        f"- {skill.name}: {skill.description}"
        for skill in registry.all()
        if _is_exposed(skill, prefix)
    ]
    descriptions = "\n".join(lines) if lines else "(none registered for this decoder)"
    return _SYSTEM_TEMPLATE.format(
        decoder_name=decoder_name,
        skill_descriptions=descriptions,
    )


def _extract_last_text(messages: list[dict[str, Any]]) -> str:
    """Return concatenated text from the last assistant message in ``messages``."""
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            content = msg.get("content", [])
            return "".join(
                block.text for block in content if hasattr(block, "text")
            )
    return ""


class AnalystAgent:
    """Agentic tool-use loop that investigates a Wazuh alert.

    Skills are exposed as Anthropic tools. Loops until the model stops
    calling tools or ``_MAX_ITERATIONS`` is reached.
    """

    def __init__(self, client: anthropic.Anthropic, registry: SkillRegistry) -> None:
        """
        Args:
            client:   Configured Anthropic SDK client.
            registry: Populated ``SkillRegistry`` with analysis skills wired up.
        """
        self._client = client
        self._registry = registry

    def run(
        self,
        alert: dict[str, Any],
        soar_prompt: str = "",
        skill_log: list[dict[str, Any]] | None = None,
    ) -> str:
        """Investigate the alert and return a findings XML document.

        Args:
            alert:       Raw Wazuh alert dict.
            soar_prompt: Optional SOAR context (initial triage notes, priority, etc.).
            skill_log:   Shared buffer that generic skills append execution
                         records to for the reflector. The caller owns the
                         list so the graph node can forward it downstream.
                         A fresh list is created when ``None``.

        Returns:
            XML string with ``<finding>`` and ``<open_question>`` blocks.
        """
        if skill_log is None:
            skill_log = []
        decoder_name: str = alert.get("decoder", {}).get("name", "unknown")
        tools = _build_tools(self._registry, decoder_name)
        system = _build_system(self._registry, decoder_name)

        initial_user: str = (
            (f"<soar_context>\n{soar_prompt}\n</soar_context>\n\n" if soar_prompt else "")
            + f"<alert>\n{json.dumps(alert, indent=2)}\n</alert>\n\n"
            + "Begin your investigation."
        )

        messages: list[dict[str, Any]] = [{"role": "user", "content": initial_user}]

        for _ in range(_MAX_ITERATIONS):
            kwargs: dict[str, Any] = {
                "model": _MODEL,
                "max_tokens": 4096,
                "system": system,
                "messages": messages,
            }
            if tools:
                kwargs["tools"] = tools

            # Pass a shallow copy so call_args captures the state at call time
            response = self._client.messages.create(**{**kwargs, "messages": list(messages)})
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                break

            # Run each tool call and feed results back
            tool_results: list[dict[str, Any]] = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                skill = self._registry.get(block.name)
                if skill is None:
                    result_text = json.dumps(
                        {"error": f"Skill '{block.name}' not found in registry."}
                    )
                else:
                    skill_result = skill.execute(
                        value=block.input.get("value", ""),
                        context={
                            "alert": alert,
                            "skill_log": skill_log,
                            "tool_input": dict(block.input),
                        },
                    )
                    result_text = json.dumps(skill_result.to_dict(), indent=2)

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    }
                )

            messages.append({"role": "user", "content": tool_results})

        findings = _extract_last_text(messages)
        if not findings.strip():
            return (
                "<open_question>"
                "<topic>investigation_failed</topic>"
                "<notes>Analyst produced no findings.</notes>"
                "</open_question>"
            )
        return findings
