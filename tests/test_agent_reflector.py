"""Tests for agent.reflector — ReflectorAgent."""

from unittest.mock import MagicMock

from agent.reflector import ReflectorAgent, _parse_verdict


_EVAL_TP = (
    "<assessment>"
    "<verdict>true_positive</verdict>"
    "<confidence>0.9</confidence>"
    "</assessment>"
)

_EVAL_FP = (
    "<assessment>"
    "<verdict>false_positive</verdict>"
    "<confidence>0.2</confidence>"
    "</assessment>"
)

_EVAL_INCONCLUSIVE_HIGH = (
    "<assessment>"
    "<verdict>inconclusive</verdict>"
    "<confidence>0.8</confidence>"
    "</assessment>"
)

_EVAL_INCONCLUSIVE_LOW = (
    "<assessment>"
    "<verdict>inconclusive</verdict>"
    "<confidence>0.3</confidence>"
    "</assessment>"
)


def _tool_use(inputs: dict) -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.name = "describe_query"
    block.input = inputs
    return block


def _describe_response(description: str, goal: str) -> MagicMock:
    response = MagicMock()
    response.content = [_tool_use({"description": description, "goal": goal})]
    return response


# ---------------------------------------------------------------------------
# _parse_verdict
# ---------------------------------------------------------------------------


def test_parse_verdict_extracts_fields() -> None:
    assert _parse_verdict(_EVAL_TP) == ("true_positive", 0.9)
    assert _parse_verdict(_EVAL_FP) == ("false_positive", 0.2)


def test_parse_verdict_fallback_on_missing() -> None:
    assert _parse_verdict("no tags here") == ("unknown", 0.0)


# ---------------------------------------------------------------------------
# chroma_retrieved counter updates
# ---------------------------------------------------------------------------


def test_counters_increment_success_when_tp_and_results() -> None:
    store = MagicMock()
    client = MagicMock()
    reflector = ReflectorAgent(client=client, store=store)

    log = [{
        "kind": "chroma_retrieved",
        "query_id": "q1",
        "success": True,
        "result_count": 5,
    }]
    summary = reflector.run(skill_log=log, evaluator_doc=_EVAL_TP)

    store.increment_counters.assert_called_once_with(query_id="q1", success=True)
    assert summary["counters_touched"] == 1


def test_counters_increment_used_not_successful_on_fp() -> None:
    store = MagicMock()
    client = MagicMock()
    reflector = ReflectorAgent(client=client, store=store)

    log = [{
        "kind": "chroma_retrieved",
        "query_id": "q1",
        "success": True,
        "result_count": 5,
    }]
    reflector.run(skill_log=log, evaluator_doc=_EVAL_FP)

    store.increment_counters.assert_called_once_with(query_id="q1", success=False)


def test_counters_skipped_when_query_id_empty() -> None:
    store = MagicMock()
    client = MagicMock()
    reflector = ReflectorAgent(client=client, store=store)

    log = [{"kind": "chroma_retrieved", "query_id": "", "success": False}]
    reflector.run(skill_log=log, evaluator_doc=_EVAL_TP)

    store.increment_counters.assert_not_called()


# ---------------------------------------------------------------------------
# query_crafted promotion
# ---------------------------------------------------------------------------


def _crafted(success: bool = True, result_count: int = 10) -> dict:
    return {
        "kind": "query_crafted",
        "crafted_dsl": '{"query":{"match_all":{}}}',
        "parameters": [],
        "security_component": "wazuh",
        "sec_comp_extra": "windows_eventchannel",
        "input_type": "ip_address",
        "goal": "find something",
        "extra_context": "decoder=windows_eventchannel",
        "result_count": result_count,
        "success": success,
    }


def test_promote_on_tp_with_results() -> None:
    store = MagicMock()
    client = MagicMock()
    client.messages.create.return_value = _describe_response("desc", "goal")
    reflector = ReflectorAgent(client=client, store=store)

    summary = reflector.run(skill_log=[_crafted()], evaluator_doc=_EVAL_TP)

    assert len(summary["promoted_ids"]) == 1
    store.add.assert_called_once()


def test_promote_on_inconclusive_high_confidence() -> None:
    store = MagicMock()
    client = MagicMock()
    client.messages.create.return_value = _describe_response("desc", "goal")
    reflector = ReflectorAgent(client=client, store=store)

    summary = reflector.run(
        skill_log=[_crafted()], evaluator_doc=_EVAL_INCONCLUSIVE_HIGH
    )

    assert len(summary["promoted_ids"]) == 1


def test_skip_promote_on_inconclusive_low_confidence() -> None:
    store = MagicMock()
    client = MagicMock()
    reflector = ReflectorAgent(client=client, store=store)

    summary = reflector.run(
        skill_log=[_crafted()], evaluator_doc=_EVAL_INCONCLUSIVE_LOW
    )

    assert summary["promoted_ids"] == []
    assert summary["skipped_crafted"] == 1
    store.add.assert_not_called()


def test_skip_promote_on_false_positive() -> None:
    store = MagicMock()
    client = MagicMock()
    reflector = ReflectorAgent(client=client, store=store)

    summary = reflector.run(skill_log=[_crafted()], evaluator_doc=_EVAL_FP)

    assert summary["promoted_ids"] == []
    store.add.assert_not_called()


def test_skip_promote_on_zero_results() -> None:
    store = MagicMock()
    client = MagicMock()
    reflector = ReflectorAgent(client=client, store=store)

    summary = reflector.run(
        skill_log=[_crafted(result_count=0)], evaluator_doc=_EVAL_TP
    )

    assert summary["promoted_ids"] == []
    store.add.assert_not_called()


def test_promotion_survives_describe_failure() -> None:
    store = MagicMock()
    client = MagicMock()
    client.messages.create.side_effect = RuntimeError("llm down")
    reflector = ReflectorAgent(client=client, store=store)

    summary = reflector.run(skill_log=[_crafted()], evaluator_doc=_EVAL_TP)

    # Describe fails but promotion still happens with fallback description
    assert len(summary["promoted_ids"]) == 1
    store.add.assert_called_once()
