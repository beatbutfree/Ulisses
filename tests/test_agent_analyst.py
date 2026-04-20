"""Tests for agent.analyst — AnalystAgent."""

import json
from unittest.mock import MagicMock, call

import pytest

from agent.analyst import AnalystAgent, _build_tools, _build_system, _decoder_prefix
from skills.base import InputType, SkillResult
from skills.registry import SkillRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALERT = {
    "decoder": {"name": "windows_eventchannel"},
    "rule": {"id": "60106", "level": 10, "description": "Multiple Windows logon failures."},
    "data": {"win": {"eventdata": {"ipAddress": "10.0.0.5", "targetUserName": "jdoe"}}},
    "@timestamp": "2026-01-01T12:00:00Z",
}

_FINDINGS_XML = (
    "<finding>"
    "<observable>10.0.0.5</observable>"
    "<skill_used>windows_ip_lookup</skill_used>"
    "<severity_signal>high</severity_signal>"
    "<notes>500 failed logons.</notes>"
    "</finding>"
)


def _mock_skill(name: str, input_type: InputType) -> MagicMock:
    skill = MagicMock()
    skill.name = name
    skill.input_type = input_type
    skill.description = f"Description of {name}."
    skill.execute.return_value = SkillResult(
        data={"event_count": 500},
        summary="500 events found.",
        success=True,
    )
    return skill


def _make_registry(*skills) -> SkillRegistry:
    # Reset singleton so each test gets a clean slate
    SkillRegistry._instance = None
    registry = SkillRegistry()
    for skill in skills:
        registry.register(skill)
    return registry


def _text_block(text: str) -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _tool_use_block(name: str, value: str, block_id: str = "tu_1") -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.name = name
    block.id = block_id
    block.input = {"value": value}
    return block


def _response(content: list, stop_reason: str = "end_turn") -> MagicMock:
    resp = MagicMock()
    resp.content = content
    resp.stop_reason = stop_reason
    return resp


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


def test_decoder_prefix_windows():
    assert _decoder_prefix("windows_eventchannel") == "windows"


def test_decoder_prefix_single_word():
    assert _decoder_prefix("wazuh") == "wazuh"


def test_build_tools_filters_by_decoder():
    ip_skill = _mock_skill("windows_ip_lookup", InputType.IP_ADDRESS)
    wazuh_skill = _mock_skill("wazuh_rule_lookup", InputType.RULE_ID)
    registry = _make_registry(ip_skill, wazuh_skill)

    tools = _build_tools(registry, "windows_eventchannel")
    names = [t["name"] for t in tools]

    assert "windows_ip_lookup" in names
    assert "wazuh_rule_lookup" not in names


def test_build_tools_excludes_foundational():
    analysis_skill = _mock_skill("windows_ip_lookup", InputType.IP_ADDRESS)
    foundational_skill = _mock_skill("query_builder", InputType.TEMPLATE_NAME)
    registry = _make_registry(analysis_skill, foundational_skill)

    tools = _build_tools(registry, "windows_eventchannel")
    names = [t["name"] for t in tools]

    assert "windows_ip_lookup" in names
    assert "query_builder" not in names


def test_build_system_injects_skill_descriptions():
    skill = _mock_skill("windows_ip_lookup", InputType.IP_ADDRESS)
    registry = _make_registry(skill)

    system = _build_system(registry, "windows_eventchannel")

    assert "windows_ip_lookup" in system
    assert "Description of windows_ip_lookup" in system


def test_build_system_unknown_decoder_shows_none_message():
    registry = _make_registry()
    system = _build_system(registry, "iptables")
    assert "none registered" in system


# ---------------------------------------------------------------------------
# AnalystAgent integration tests (mocked Anthropic client)
# ---------------------------------------------------------------------------


def test_analyst_single_turn_no_tools():
    """Model answers on first turn with no tool calls."""
    ip_skill = _mock_skill("windows_ip_lookup", InputType.IP_ADDRESS)
    registry = _make_registry(ip_skill)

    client = MagicMock()
    client.messages.create.return_value = _response(
        [_text_block(_FINDINGS_XML)], stop_reason="end_turn"
    )

    analyst = AnalystAgent(client=client, registry=registry)
    result = analyst.run(_ALERT)

    assert "<finding>" in result
    assert client.messages.create.call_count == 1


def test_analyst_tool_use_loop():
    """Model calls a tool once, then produces findings."""
    ip_skill = _mock_skill("windows_ip_lookup", InputType.IP_ADDRESS)
    registry = _make_registry(ip_skill)

    client = MagicMock()
    client.messages.create.side_effect = [
        _response(
            [_tool_use_block("windows_ip_lookup", "10.0.0.5")],
            stop_reason="tool_use",
        ),
        _response([_text_block(_FINDINGS_XML)], stop_reason="end_turn"),
    ]

    analyst = AnalystAgent(client=client, registry=registry)
    result = analyst.run(_ALERT)

    assert "<finding>" in result
    assert client.messages.create.call_count == 2
    ip_skill.execute.assert_called_once_with(value="10.0.0.5", context={"alert": _ALERT})


def test_analyst_unknown_skill_returns_error_to_model():
    """Registry miss is surfaced as a tool_result error, not an exception."""
    registry = _make_registry()  # empty

    client = MagicMock()
    client.messages.create.side_effect = [
        _response(
            [_tool_use_block("nonexistent_skill", "10.0.0.5")],
            stop_reason="tool_use",
        ),
        _response([_text_block(_FINDINGS_XML)], stop_reason="end_turn"),
    ]

    analyst = AnalystAgent(client=client, registry=registry)
    result = analyst.run(_ALERT)

    # Second call should include a tool_result with error text
    second_call_messages = client.messages.create.call_args_list[1].kwargs["messages"]
    tool_result_msg = second_call_messages[-1]
    assert tool_result_msg["role"] == "user"
    result_content = tool_result_msg["content"][0]
    assert "not found" in result_content["content"]


def test_analyst_fallback_when_no_findings():
    """Returns open_question block when model produces empty text."""
    registry = _make_registry()

    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = "   "  # whitespace only

    client = MagicMock()
    client.messages.create.return_value = _response(
        [text_block], stop_reason="end_turn"
    )

    analyst = AnalystAgent(client=client, registry=registry)
    result = analyst.run(_ALERT)

    assert "<open_question>" in result


def test_analyst_soar_prompt_included_in_first_message():
    registry = _make_registry()
    client = MagicMock()
    client.messages.create.return_value = _response(
        [_text_block(_FINDINGS_XML)], stop_reason="end_turn"
    )

    analyst = AnalystAgent(client=client, registry=registry)
    analyst.run(_ALERT, soar_prompt="Priority: HIGH. Ticket: INC-42.")

    first_call = client.messages.create.call_args
    user_content = first_call.kwargs["messages"][0]["content"]
    assert "INC-42" in user_content
