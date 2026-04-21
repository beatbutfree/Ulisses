"""Tests for analyst tool exposure of generic (is_generic=True) skills.

These skills should be available regardless of decoder prefix and carry
their own multi-parameter ``tool_input_schema``.
"""

from unittest.mock import MagicMock

from agent.analyst import _build_tools, _build_system
from skills.base import InputType
from skills.registry import SkillRegistry


def _mock_skill(
    name: str,
    input_type: InputType,
    is_generic: bool = False,
    tool_input_schema: dict | None = None,
) -> MagicMock:
    skill = MagicMock()
    skill.name = name
    skill.input_type = input_type
    skill.description = f"Description of {name}."
    skill.is_generic = is_generic
    skill.tool_input_schema = tool_input_schema
    return skill


def _fresh_registry(*skills) -> SkillRegistry:
    SkillRegistry._instance = None
    registry = SkillRegistry()
    for skill in skills:
        registry.register(skill)
    return registry


def test_generic_skill_exposed_for_any_decoder() -> None:
    generic = _mock_skill(
        "chroma_query",
        InputType.META,
        is_generic=True,
        tool_input_schema={"type": "object", "properties": {"goal": {"type": "string"}}},
    )
    registry = _fresh_registry(generic)

    # Windows alert — generic skill still appears
    tools = _build_tools(registry, "windows_eventchannel")
    names = [t["name"] for t in tools]
    assert "chroma_query" in names

    # Entirely different decoder — still appears
    tools = _build_tools(registry, "iptables")
    names = [t["name"] for t in tools]
    assert "chroma_query" in names


def test_generic_skill_uses_custom_tool_input_schema() -> None:
    custom_schema = {
        "type": "object",
        "properties": {
            "goal": {"type": "string"},
            "input_type": {"type": "string"},
        },
        "required": ["goal", "input_type"],
    }
    generic = _mock_skill(
        "query_crafter",
        InputType.META,
        is_generic=True,
        tool_input_schema=custom_schema,
    )
    registry = _fresh_registry(generic)

    tools = _build_tools(registry, "windows_eventchannel")
    crafter = next(t for t in tools if t["name"] == "query_crafter")
    assert crafter["input_schema"] == custom_schema


def test_non_generic_skill_still_filtered_by_decoder() -> None:
    win_skill = _mock_skill("windows_ip_lookup", InputType.IP_ADDRESS, is_generic=False)
    wazuh_skill = _mock_skill("wazuh_rule_lookup", InputType.RULE_ID, is_generic=False)
    registry = _fresh_registry(win_skill, wazuh_skill)

    tools = _build_tools(registry, "windows_eventchannel")
    names = [t["name"] for t in tools]
    assert "windows_ip_lookup" in names
    assert "wazuh_rule_lookup" not in names


def test_generic_skills_appear_in_system_prompt() -> None:
    generic = _mock_skill(
        "chroma_query",
        InputType.META,
        is_generic=True,
        tool_input_schema={"type": "object"},
    )
    registry = _fresh_registry(generic)

    system = _build_system(registry, "windows_eventchannel")
    assert "chroma_query" in system


def test_foundational_non_generic_skills_excluded() -> None:
    # Foundational-typed, non-generic skill (like QueryBuilder) must NOT appear
    # as an analyst tool.
    foundational = _mock_skill(
        "query_builder", InputType.TEMPLATE_NAME, is_generic=False
    )
    registry = _fresh_registry(foundational)

    tools = _build_tools(registry, "windows_eventchannel")
    assert [t["name"] for t in tools] == []
