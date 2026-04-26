"""Tests for skills.analysis.opnsense_host_behavior_lookup."""

from unittest.mock import MagicMock

from skills.analysis.opnsense_host_behavior_lookup import (
    OpnsenseHostBehaviorLookupSkill,
    _TEMPLATE_NAME,
)
from skills.base import InputType, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore


def _make_skill() -> tuple[OpnsenseHostBehaviorLookupSkill, QueryBuilderSkill, MagicMock]:
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store)
    mock_exec = MagicMock(spec=QueryExecutorSkill)
    skill = OpnsenseHostBehaviorLookupSkill(builder=builder, executor=mock_exec)
    return skill, builder, mock_exec


def _exec_ok(aggs: dict | None = None, total: int = 8) -> SkillResult:
    return SkillResult(
        data={"hits": [], "total": total, "took_ms": 4, "aggregations": aggs or {}},
        summary="ok",
        success=True,
    )


_SAMPLE_AGGS = {
    "contacted_ips": {
        "buckets": [
            {"key": "10.0.0.5", "doc_count": 6},
            {"key": "10.0.0.9", "doc_count": 2},
        ]
    },
    "first_seen": {"value": 1705305600000, "value_as_string": "2024-01-15T08:00:00.000Z"},
    "last_seen": {"value": 1705307400000, "value_as_string": "2024-01-15T08:30:00.000Z"},
}


def test_attributes():
    skill, builder, _ = _make_skill()
    assert skill.name == "opnsense_host_behavior_lookup"
    assert skill.input_type == InputType.IP_ADDRESS
    assert builder.store.get(_TEMPLATE_NAME) is not None


def test_success_parses_contacted_hosts():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=8)

    result = skill.execute("192.168.1.10", context={})

    assert result.success is True
    assert result.data["event_count"] == 8
    assert result.data["distinct_contacted_hosts"] == 2
    assert result.data["contacted_ips"][0] == {"key": "10.0.0.5", "count": 6}
    assert result.data["first_seen"] == "2024-01-15T08:00:00.000Z"
    assert result.data["last_seen"] == "2024-01-15T08:30:00.000Z"
    assert "192.168.1.10" in result.summary


def test_executor_called_with_size_zero():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok()

    skill.execute("192.168.1.10", context={})
    call_ctx = mock_exec.execute.call_args[1]["context"]
    assert call_ctx["size"] == 0


def test_no_results_summary():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok({}, total=0)

    result = skill.execute("192.168.1.10", context={})
    assert result.success is True
    assert "No OPNSense traffic events" in result.summary
    assert result.data["contacted_ips"] == []


def test_executor_failure_propagated():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = SkillResult(data={}, summary="timeout", success=False)

    result = skill.execute("192.168.1.10", context={})
    assert result.success is False
    assert "timeout" in result.summary
