"""Tests for skills.foundational.chroma_query.ChromaQuerySkill."""

from unittest.mock import MagicMock

from skills.base import InputType, SkillResult
from skills.foundational.chroma_query import ChromaQuerySkill
from store.chroma_client import StoredQuery


_DSL = '{"query":{"term":{"data.win.eventdata.ipAddress":"10.0.0.5"}}}'


def _candidate(doc_id: str = "q1") -> StoredQuery:
    return StoredQuery(
        id=doc_id,
        description="Failed logon spikes by IP.",
        query='{"query":{"term":{"data.win.eventdata.ipAddress":"{{ip}}"}}}',
        parameters=["ip"],
        security_component="wazuh",
        sec_comp_extra="windows_eventchannel",
        input_type="ip_address",
        goal="Brute force detection",
        times_used=5,
        times_successful=4,
    )


def _tool_use(name: str, inputs: dict) -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.name = name
    block.input = inputs
    return block


def _llm_decision(**inputs) -> MagicMock:
    response = MagicMock()
    response.content = [_tool_use("select_template", inputs)]
    return response


def _executor_success(total: int = 8) -> MagicMock:
    mock = MagicMock()
    mock.execute.return_value = SkillResult(
        data={"hits": [], "total": total, "took_ms": 2, "aggregations": {}},
        summary=f"{total} hits",
        success=True,
    )
    return mock


def _context() -> dict:
    return {
        "alert": {"decoder": {"name": "windows_eventchannel"}},
        "skill_log": [],
        "tool_input": {
            "goal": "Find repeated failed logons",
            "input_type": "ip_address",
            "security_component": "wazuh",
            "value": "10.0.0.5",
        },
    }


def test_chroma_query_marks_generic_meta() -> None:
    assert ChromaQuerySkill.is_generic is True
    assert ChromaQuerySkill.input_type == InputType.META


def test_returns_no_match_when_store_empty() -> None:
    store = MagicMock()
    store.search.return_value = []
    client = MagicMock()
    executor = MagicMock()

    skill = ChromaQuerySkill(client=client, store=store, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success
    assert result.data == {"matched": False, "reason": "no candidates in ChromaDB"}
    assert ctx["skill_log"][0]["kind"] == "chroma_retrieved"
    assert ctx["skill_log"][0]["success"] is False
    client.messages.create.assert_not_called()
    executor.execute.assert_not_called()


def test_use_as_is_executes_and_logs_hit() -> None:
    store = MagicMock()
    store.search.return_value = [_candidate("q1")]
    client = MagicMock()
    client.messages.create.return_value = _llm_decision(
        action="use_as_is", query_id="q1", dsl=_DSL
    )
    executor = _executor_success(total=8)

    skill = ChromaQuerySkill(client=client, store=store, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success
    assert result.data["matched"] is True
    assert result.data["query_id"] == "q1"
    assert result.data["was_modified"] is False
    assert result.data["result_count"] == 8

    record = ctx["skill_log"][0]
    assert record["query_id"] == "q1"
    assert record["was_modified"] is False
    assert record["result_count"] == 8


def test_modify_marks_was_modified_true() -> None:
    store = MagicMock()
    store.search.return_value = [_candidate("q1")]
    client = MagicMock()
    client.messages.create.return_value = _llm_decision(
        action="modify", query_id="q1", dsl=_DSL
    )
    executor = _executor_success(total=2)

    skill = ChromaQuerySkill(client=client, store=store, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.data["was_modified"] is True
    assert ctx["skill_log"][0]["was_modified"] is True


def test_no_match_returns_unmatched_data() -> None:
    store = MagicMock()
    store.search.return_value = [_candidate("q1")]
    client = MagicMock()
    client.messages.create.return_value = _llm_decision(
        action="no_match", reason="none fit"
    )
    executor = MagicMock()

    skill = ChromaQuerySkill(client=client, store=store, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success
    assert result.data == {"matched": False, "reason": "none fit"}
    executor.execute.assert_not_called()
    assert ctx["skill_log"][0]["error"] == "none fit"


def test_metadata_filters_passed_to_store() -> None:
    store = MagicMock()
    store.search.return_value = []
    client = MagicMock()
    executor = MagicMock()

    skill = ChromaQuerySkill(client=client, store=store, executor=executor)
    skill.execute(value="10.0.0.5", context=_context())

    store.search.assert_called_once()
    kwargs = store.search.call_args.kwargs
    assert kwargs["security_component"] == "wazuh"
    assert kwargs["input_type"] == "ip_address"


def test_execution_failure_is_surfaced() -> None:
    store = MagicMock()
    store.search.return_value = [_candidate("q1")]
    client = MagicMock()
    client.messages.create.return_value = _llm_decision(
        action="use_as_is", query_id="q1", dsl=_DSL
    )
    executor = MagicMock()
    executor.execute.return_value = SkillResult.fail("Indexer unreachable")

    skill = ChromaQuerySkill(client=client, store=store, executor=executor)
    ctx = _context()
    result = skill.execute(value="10.0.0.5", context=ctx)

    assert result.success is False
    assert "Indexer unreachable" in result.summary
    assert ctx["skill_log"][0]["success"] is False
