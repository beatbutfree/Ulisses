"""Tests for skills.analysis.opnsense_pair_port_timeline_lookup."""

from unittest.mock import MagicMock

from skills.analysis.opnsense_pair_port_timeline_lookup import (
    OpnsensePairPortTimelineLookupSkill,
    _TEMPLATE_NAME,
)
from skills.base import InputType, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore


def _make_skill() -> tuple[OpnsensePairPortTimelineLookupSkill, QueryBuilderSkill, MagicMock]:
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store)
    mock_exec = MagicMock(spec=QueryExecutorSkill)
    skill = OpnsensePairPortTimelineLookupSkill(builder=builder, executor=mock_exec)
    return skill, builder, mock_exec


def _exec_ok(aggs: dict | None = None, total: int = 9) -> SkillResult:
    return SkillResult(
        data={"hits": [], "total": total, "took_ms": 6, "aggregations": aggs or {}},
        summary="ok",
        success=True,
    )


_SAMPLE_AGGS = {
    "by_port": {
        "buckets": [
            {
                "key": 443,
                "doc_count": 7,
                "per_minute": {
                    "buckets": [
                        {"key_as_string": "2024-01-15T08:00:00.000Z", "doc_count": 3},
                        {"key_as_string": "2024-01-15T08:01:00.000Z", "doc_count": 4},
                    ]
                },
            },
            {
                "key": 22,
                "doc_count": 2,
                "per_minute": {
                    "buckets": [
                        {"key_as_string": "2024-01-15T08:00:00.000Z", "doc_count": 2}
                    ]
                },
            },
        ]
    }
}


def test_attributes_and_template_registration():
    skill, builder, _ = _make_skill()
    assert skill.name == "opnsense_pair_port_timeline_lookup"
    assert skill.input_type == InputType.IP_ADDRESS
    assert builder.store.get(_TEMPLATE_NAME) is not None
    assert skill.tool_input_schema is not None
    assert set(skill.tool_input_schema["required"]) == {"src_ip", "dst_ip"}


def test_success_with_tool_input_schema_fields():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=9)

    result = skill.execute(
        "",
        context={"tool_input": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.5"}},
    )

    assert result.success is True
    assert result.data["src_ip"] == "192.168.1.10"
    assert result.data["dst_ip"] == "10.0.0.5"
    assert result.data["event_count"] == 9
    assert result.data["distinct_port_count"] == 2
    assert result.data["by_port"][0]["port"] == 443
    assert result.data["by_port"][0]["per_minute"][0]["count"] == 3


def test_fallback_accepts_value_src_dst_csv():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=9)

    result = skill.execute("192.168.1.10,10.0.0.5", context={})

    assert result.success is True
    assert result.data["src_ip"] == "192.168.1.10"
    assert result.data["dst_ip"] == "10.0.0.5"


def test_missing_parameters_returns_fail():
    skill, _, _ = _make_skill()

    result = skill.execute("", context={})

    assert result.success is False
    assert "src_ip" in result.summary
    assert "dst_ip" in result.summary


def test_executor_called_with_size_zero():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)

    skill.execute(
        "",
        context={"tool_input": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.5"}},
    )
    call_ctx = mock_exec.execute.call_args[1]["context"]
    assert call_ctx["size"] == 0


def test_executor_failure_propagated():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = SkillResult(data={}, summary="down", success=False)

    result = skill.execute(
        "",
        context={"tool_input": {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.5"}},
    )

    assert result.success is False
    assert "down" in result.summary
