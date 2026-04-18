"""Tests for skills.analysis.windows_rule_lookup — WindowsRuleLookupSkill."""

from unittest.mock import MagicMock

import pytest

from skills.analysis.windows_rule_lookup import WindowsRuleLookupSkill, _TEMPLATE_NAME
from skills.base import InputType, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_skill() -> tuple[WindowsRuleLookupSkill, QueryBuilderSkill, MagicMock]:
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store)
    mock_exec = MagicMock(spec=QueryExecutorSkill)
    skill = WindowsRuleLookupSkill(builder=builder, executor=mock_exec)
    return skill, builder, mock_exec


def _exec_ok(aggs: dict | None = None, total: int = 10) -> SkillResult:
    return SkillResult(
        data={"hits": [], "total": total, "took_ms": 2, "aggregations": aggs or {}},
        summary="ok",
        success=True,
    )


_SAMPLE_AGGS = {
    "activity_over_time": {
        "buckets": [
            {"key_as_string": "2024-01-15T10:00:00.000Z", "doc_count": 6},
            {"key_as_string": "2024-01-16T14:00:00.000Z", "doc_count": 4},
        ]
    },
    "affected_agents": {"buckets": [
        {"key": "dc01", "doc_count": 7},
        {"key": "client01", "doc_count": 3},
    ]},
    "affected_users": {"buckets": [{"key": "jdoe", "doc_count": 5}]},
    "top_src_ips": {"buckets": [{"key": "10.0.0.1", "doc_count": 4}]},
    "top_dst_ips": {"buckets": [{"key": "10.0.0.5", "doc_count": 2}]},
    "first_seen": {"value": 1705312800000, "value_as_string": "2024-01-15T10:00:00.000Z"},
    "last_seen": {"value": 1705399200000, "value_as_string": "2024-01-16T10:00:00.000Z"},
}

_ALERT_CONTEXT = {
    "alert": {"rule": {"id": "5402", "level": 3, "description": "Login success"}}
}


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------


class TestWindowsRuleLookupAttributes:
    def test_name(self):
        skill, _, _ = _make_skill()
        assert skill.name == "windows_rule_lookup"

    def test_input_type(self):
        skill, _, _ = _make_skill()
        assert skill.input_type == InputType.RULE_ID

    def test_template_registered_on_init(self):
        _, builder, _ = _make_skill()
        assert builder.store.get(_TEMPLATE_NAME) is not None


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------


class TestWindowsRuleLookupSuccess:
    def test_returns_expected_keys(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("5402", context=_ALERT_CONTEXT)

        assert result.success is True
        for key in (
            "event_count", "activity_histogram", "peak_hour", "active_days",
            "first_seen", "last_seen", "rule_level", "rule_description",
            "affected_agents", "affected_users", "top_src_ips", "top_dst_ips",
        ):
            assert key in result.data, f"Missing key: {key}"

    def test_rule_metadata_from_context(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert result.data["rule_level"] == 3
        assert result.data["rule_description"] == "Login success"

    def test_rule_metadata_none_when_no_alert_in_context(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("5402", context={})
        assert result.data["rule_level"] is None
        assert result.data["rule_description"] is None

    def test_affected_agents_parsed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        agents = result.data["affected_agents"]
        assert agents[0] == {"key": "dc01", "count": 7}

    def test_top_src_ips_parsed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert result.data["top_src_ips"][0] == {"key": "10.0.0.1", "count": 4}

    def test_active_days(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert result.data["active_days"] == 2

    def test_executor_called_with_size_zero(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok()
        skill.execute("5402", context=_ALERT_CONTEXT)
        call_ctx = mock_exec.execute.call_args[1]["context"]
        assert call_ctx["size"] == 0

    def test_summary_includes_rule_id_and_count(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=10)
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert "5402" in result.summary
        assert "10" in result.summary

    def test_source_stamped(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok()
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert result.source == "WindowsRuleLookupSkill"


# ---------------------------------------------------------------------------
# Zero-result and failure
# ---------------------------------------------------------------------------


class TestWindowsRuleLookupEdgeCases:
    def test_no_results(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok({}, total=0)
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert result.success is True
        assert result.data["affected_agents"] == []
        assert result.data["event_count"] == 0

    def test_executor_failure_propagated(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = SkillResult(
            data={}, summary="transport error", success=False
        )
        result = skill.execute("5402", context=_ALERT_CONTEXT)
        assert result.success is False
        assert "transport error" in result.summary
