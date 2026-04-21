"""Tests for skills.foundational.query_crafter.QueryCrafterSkill."""

from unittest.mock import MagicMock

from skills.base import InputType, SkillResult
from skills.foundational.query_crafter import QueryCrafterSkill


_DSL = '{"query":{"term":{"data.win.eventdata.ipAddress":"10.0.0.5"}}}'


def _tool_use(name: str, inputs: dict) -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.name = name
    block.input = inputs
    return block


def _llm_response(dsl: str, params: list[str]) -> MagicMock:
    response = MagicMock()
    response.content = [_tool_use("emit_query", {"dsl": dsl, "parameters": params})]
    return response


def _executor_success(total: int = 12) -> MagicMock:
    mock = MagicMock()
    mock.execute.return_value = SkillResult(
        data={"hits": [], "total": total, "took_ms": 5, "aggregations": {}},
        summary=f"{total} hits",
        success=True,
    )
    return mock


def _context() -> dict:
    return {
        "alert": {"decoder": {"name": "windows_eventchannel"}},
        "skill_log": [],
        "tool_input": {
            "goal": "Find repeated failed logons from this IP",
            "input_type": "ip_address",
            "security_component": "wazuh",
            "value": "10.0.0.5",
            "extra_context": "decoder=windows_eventchannel",
        },
    }


def test_crafter_marks_generic_meta() -> None:
    assert QueryCrafterSkill.is_generic is True
    assert QueryCrafterSkill.input_type == InputType.META


def test_crafter_executes_and_returns_results() -> None:
    client = MagicMock()
    client.messages.create.return_value = _llm_response(_DSL, [])
    executor = _executor_success(total=12)

    skill = QueryCrafterSkill(client=client, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success
    assert result.data["result_count"] == 12
    assert result.data["crafted_dsl"] == _DSL
    assert result.data["attempts"] == 1
    executor.execute.assert_called_once()


def test_crafter_logs_record_for_reflector() -> None:
    client = MagicMock()
    client.messages.create.return_value = _llm_response(_DSL, [])
    executor = _executor_success(total=0)

    skill = QueryCrafterSkill(client=client, executor=executor)
    ctx = _context()
    skill.execute(value="10.0.0.5", context=ctx)

    assert len(ctx["skill_log"]) == 1
    record = ctx["skill_log"][0]
    assert record["kind"] == "query_crafted"
    assert record["crafted_dsl"] == _DSL
    assert record["result_count"] == 0
    assert record["success"] is True  # zero results is still successful execution


def test_crafter_rejects_placeholders_and_retries() -> None:
    client = MagicMock()
    client.messages.create.side_effect = [
        _llm_response('{"query":{"term":{"ip":"{{ip}}"}}}', ["ip"]),  # has placeholder
        _llm_response(_DSL, []),                                       # concrete
    ]
    executor = _executor_success(total=3)

    skill = QueryCrafterSkill(client=client, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success
    assert result.data["attempts"] == 2
    assert client.messages.create.call_count == 2


def test_crafter_retries_on_execution_failure() -> None:
    client = MagicMock()
    client.messages.create.side_effect = [
        _llm_response("{bad json}", []),
        _llm_response(_DSL, []),
    ]
    executor = MagicMock()
    executor.execute.side_effect = [
        SkillResult.fail("Invalid DSL — not valid JSON"),
        SkillResult(
            data={"hits": [], "total": 7, "took_ms": 1, "aggregations": {}},
            summary="7 hits",
            success=True,
        ),
    ]

    skill = QueryCrafterSkill(client=client, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success
    assert result.data["attempts"] == 2
    assert executor.execute.call_count == 2


def test_crafter_gives_up_after_max_attempts() -> None:
    client = MagicMock()
    client.messages.create.return_value = _llm_response("{bad}", [])
    executor = MagicMock()
    executor.execute.return_value = SkillResult.fail("invalid dsl")

    skill = QueryCrafterSkill(client=client, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success is False
    record = ctx["skill_log"][0]
    assert record["success"] is False
    assert record["kind"] == "query_crafted"


def test_crafter_rejects_missing_tool_input() -> None:
    client = MagicMock()
    executor = MagicMock()
    skill = QueryCrafterSkill(client=client, executor=executor)

    # Missing goal entirely
    result = skill.execute(value="", context={"skill_log": [], "tool_input": {}})
    assert result.success is False
    assert "goal" in result.summary
