"""Tests for skills.analysis.windows_username_lookup — WindowsUsernameLookupSkill."""

from unittest.mock import MagicMock

import pytest

from skills.analysis.windows_username_lookup import (
    WindowsUsernameLookupSkill,
    _TEMPLATE_NAME,
)
from skills.base import InputType, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_skill() -> tuple[WindowsUsernameLookupSkill, QueryBuilderSkill, MagicMock]:
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store)
    mock_exec = MagicMock(spec=QueryExecutorSkill)
    skill = WindowsUsernameLookupSkill(builder=builder, executor=mock_exec)
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
            {"key_as_string": "2024-01-15T07:00:00.000Z", "doc_count": 3},  # off-hours
            {"key_as_string": "2024-01-15T09:00:00.000Z", "doc_count": 10},
        ]
    },
    "logon_events": {"doc_count": 8},
    "failed_logon_events": {"doc_count": 2},
    "src_ips": {"buckets": [{"key": "10.0.0.1", "doc_count": 5}]},
    "dst_ips": {"buckets": [{"key": "192.168.1.10", "doc_count": 3}]},
    "machines_accessed": {"buckets": [{"key": "dc01", "doc_count": 6}]},
    "top_rules": {
        "buckets": [
            {
                "key": "5402",
                "doc_count": 8,
                "rule_meta": {
                    "hits": {
                        "hits": [{"_source": {"rule": {"level": 3, "description": "Login"}}}]
                    }
                },
            }
        ]
    },
    "first_seen": {"value": 1705305600000, "value_as_string": "2024-01-15T07:00:00.000Z"},
    "last_seen": {"value": 1705309200000, "value_as_string": "2024-01-15T09:00:00.000Z"},
}


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------


class TestWindowsUsernameLookupAttributes:
    def test_name(self):
        skill, _, _ = _make_skill()
        assert skill.name == "windows_username_lookup"

    def test_input_type(self):
        skill, _, _ = _make_skill()
        assert skill.input_type == InputType.USERNAME

    def test_template_registered_on_init(self):
        _, builder, _ = _make_skill()
        assert builder.store.get(_TEMPLATE_NAME) is not None


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------


class TestWindowsUsernameLookupSuccess:
    def test_returns_expected_keys(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("jdoe", context={})

        assert result.success is True
        for key in (
            "event_count", "activity_histogram", "peak_hour", "active_days",
            "first_seen", "last_seen", "logon_count", "failed_logon_count",
            "src_ips", "dst_ips", "machines_accessed",
            "off_hours_activity", "top_rules",
        ):
            assert key in result.data, f"Missing key: {key}"

    def test_logon_count(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("jdoe", context={})
        assert result.data["logon_count"] == 8

    def test_failed_logon_count(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("jdoe", context={})
        assert result.data["failed_logon_count"] == 2

    def test_off_hours_true_when_activity_before_8(self):
        # bucket at 07:00 → off-hours
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("jdoe", context={})
        assert result.data["off_hours_activity"] is True

    def test_off_hours_false_when_only_business_hours(self):
        aggs = dict(_SAMPLE_AGGS)
        aggs["activity_over_time"] = {
            "buckets": [{"key_as_string": "2024-01-15T09:00:00.000Z", "doc_count": 5}]
        }
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(aggs)
        result = skill.execute("jdoe", context={})
        assert result.data["off_hours_activity"] is False

    def test_src_ips_parsed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("jdoe", context={})
        assert result.data["src_ips"][0] == {"key": "10.0.0.1", "count": 5}

    def test_machines_accessed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("jdoe", context={})
        assert result.data["machines_accessed"][0]["key"] == "dc01"

    def test_summary_mentions_username(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=13)
        result = skill.execute("jdoe", context={})
        assert "jdoe" in result.summary

    def test_off_hours_note_in_summary(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=13)
        result = skill.execute("jdoe", context={})
        assert "off-hours" in result.summary.lower()

    def test_executor_called_with_size_zero(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok()
        skill.execute("jdoe", context={})
        call_ctx = mock_exec.execute.call_args[1]["context"]
        assert call_ctx["size"] == 0


# ---------------------------------------------------------------------------
# Zero-result and failure
# ---------------------------------------------------------------------------


class TestWindowsUsernameLookupEdgeCases:
    def test_no_results(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok({}, total=0)
        result = skill.execute("ghost", context={})
        assert result.success is True
        assert result.data["logon_count"] == 0
        assert result.data["off_hours_activity"] is False

    def test_executor_failure_propagated(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = SkillResult(
            data={}, summary="timeout", success=False
        )
        result = skill.execute("jdoe", context={})
        assert result.success is False
