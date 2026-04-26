"""Tests for skills.analysis.opnsense_multiport_contact_lookup."""

from unittest.mock import MagicMock

from skills.analysis.opnsense_multiport_contact_lookup import (
    OpnsenseMultiportContactLookupSkill,
    _TEMPLATE_NAME,
)
from skills.base import InputType, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore


def _make_skill() -> tuple[OpnsenseMultiportContactLookupSkill, QueryBuilderSkill, MagicMock]:
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store)
    mock_exec = MagicMock(spec=QueryExecutorSkill)
    skill = OpnsenseMultiportContactLookupSkill(builder=builder, executor=mock_exec)
    return skill, builder, mock_exec


def _exec_ok(aggs: dict | None = None, total: int = 12) -> SkillResult:
    return SkillResult(
        data={"hits": [], "total": total, "took_ms": 5, "aggregations": aggs or {}},
        summary="ok",
        success=True,
    )


_SAMPLE_AGGS = {
    "hosts": {
        "buckets": [
            {
                "key": "10.0.0.5",
                "doc_count": 10,
                "unique_ports": {"value": 6},
                "ports_sample": {
                    "buckets": [
                        {"key": 22, "doc_count": 2},
                        {"key": 80, "doc_count": 2},
                        {"key": 443, "doc_count": 2},
                    ]
                },
            }
        ]
    },
    "first_seen": {"value": 1705305600000, "value_as_string": "2024-01-15T08:00:00.000Z"},
    "last_seen": {"value": 1705309200000, "value_as_string": "2024-01-15T09:00:00.000Z"},
}


def test_attributes():
    skill, builder, _ = _make_skill()
    assert skill.name == "opnsense_multiport_contact_lookup"
    assert skill.input_type == InputType.IP_ADDRESS
    assert builder.store.get(_TEMPLATE_NAME) is not None


def test_success_returns_qualified_hosts():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=12)

    result = skill.execute("192.168.1.10", context={})

    assert result.success is True
    assert result.data["event_count"] == 12
    assert result.data["qualified_host_count"] == 1
    host = result.data["hosts_with_5plus_ports"][0]
    assert host["host"] == "10.0.0.5"
    assert host["distinct_port_count"] == 6
    assert 443 in host["ports_sample"]


def test_executor_called_with_size_zero():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok()
    skill.execute("192.168.1.10", context={})
    call_ctx = mock_exec.execute.call_args[1]["context"]
    assert call_ctx["size"] == 0


def test_no_events_summary():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok({}, total=0)
    result = skill.execute("192.168.1.10", context={})
    assert result.success is True
    assert "No OPNSense traffic events" in result.summary


def test_events_but_no_host_with_5_ports_summary():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = _exec_ok({"hosts": {"buckets": []}}, total=7)
    result = skill.execute("192.168.1.10", context={})
    assert result.success is True
    assert "no destination host" in result.summary.lower()


def test_executor_failure_propagated():
    skill, _, mock_exec = _make_skill()
    mock_exec.execute.return_value = SkillResult(data={}, summary="transport", success=False)
    result = skill.execute("192.168.1.10", context={})
    assert result.success is False
    assert "transport" in result.summary
