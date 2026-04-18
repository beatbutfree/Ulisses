"""Tests for skills.analysis.windows_ip_lookup — WindowsIPLookupSkill."""

import json
from unittest.mock import MagicMock

import pytest

from skills.analysis.windows_ip_lookup import WindowsIPLookupSkill, _TEMPLATE_NAME
from skills.base import InputType, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_skill() -> tuple[WindowsIPLookupSkill, MagicMock, MagicMock]:
    """Return (skill, mock_builder, mock_executor)."""
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store)

    mock_executor = MagicMock(spec=QueryExecutorSkill)
    skill = WindowsIPLookupSkill(builder=builder, executor=mock_executor)
    return skill, builder, mock_executor


def _exec_ok(aggs: dict | None = None, total: int = 10) -> SkillResult:
    return SkillResult(
        data={"hits": [], "total": total, "took_ms": 3, "aggregations": aggs or {}},
        summary=f"Query matched {total} document(s), 0 returned, in 3 ms.",
        success=True,
    )


def _exec_fail(reason: str = "indexer down") -> SkillResult:
    return SkillResult(data={}, summary=reason, success=False)


_SAMPLE_AGGS = {
    "activity_over_time": {
        "buckets": [
            {"key_as_string": "2024-01-15T08:00:00.000Z", "doc_count": 5},
            {"key_as_string": "2024-01-15T08:05:00.000Z", "doc_count": 3},
            {"key_as_string": "2024-01-16T22:00:00.000Z", "doc_count": 2},
        ]
    },
    "top_rules": {
        "buckets": [
            {
                "key": "5402",
                "doc_count": 7,
                "rule_meta": {
                    "hits": {
                        "hits": [{"_source": {"rule": {"level": 3, "description": "Login success"}}}]
                    }
                },
            }
        ]
    },
    "top_users": {"buckets": [{"key": "jdoe", "doc_count": 8}]},
    "top_dst_ips": {"buckets": [{"key": "10.0.0.5", "doc_count": 4}]},
    "top_dst_ports": {
        "buckets": [
            {
                "key": 443,
                "doc_count": 6,
                "protocol": {"buckets": [{"key": "tcp"}]},
            }
        ]
    },
    "first_seen": {"value": 1705305600000, "value_as_string": "2024-01-15T08:00:00.000Z"},
    "last_seen": {"value": 1705392000000, "value_as_string": "2024-01-16T08:00:00.000Z"},
}


# ---------------------------------------------------------------------------
# Skill attributes
# ---------------------------------------------------------------------------


class TestWindowsIPLookupAttributes:
    def test_name(self):
        skill, _, _ = _make_skill()
        assert skill.name == "windows_ip_lookup"

    def test_input_type(self):
        skill, _, _ = _make_skill()
        assert skill.input_type == InputType.IP_ADDRESS

    def test_template_registered_on_init(self):
        skill, builder, _ = _make_skill()
        assert builder.store.get(_TEMPLATE_NAME) is not None


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------


class TestWindowsIPLookupSuccess:
    def test_returns_expected_keys(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)

        result = skill.execute("10.0.0.1", context={})

        assert result.success is True
        for key in (
            "event_count", "activity_histogram", "peak_hour", "active_days",
            "first_seen", "last_seen", "top_rules", "top_users",
            "top_dst_ips", "top_dst_ports",
        ):
            assert key in result.data, f"Missing key: {key}"

    def test_event_count_matches_total(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=42)
        result = skill.execute("10.0.0.1", context={})
        assert result.data["event_count"] == 42

    def test_top_rules_parsed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("10.0.0.1", context={})
        rules = result.data["top_rules"]
        assert rules[0]["id"] == "5402"
        assert rules[0]["level"] == 3
        assert rules[0]["description"] == "Login success"
        assert rules[0]["count"] == 7

    def test_top_users_parsed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("10.0.0.1", context={})
        assert result.data["top_users"][0] == {"key": "jdoe", "count": 8}

    def test_top_dst_ports_include_protocol(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("10.0.0.1", context={})
        port = result.data["top_dst_ports"][0]
        assert port["port"] == 443
        assert port["protocol"] == "tcp"
        assert port["request_count"] == 6

    def test_peak_hour_computed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("10.0.0.1", context={})
        # Buckets at 08:00 (5+3=8) and 22:00 (2) — peak should be hour 8
        assert result.data["peak_hour"] == 8

    def test_active_days_computed(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("10.0.0.1", context={})
        assert result.data["active_days"] == 2

    def test_first_last_seen(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS)
        result = skill.execute("10.0.0.1", context={})
        assert result.data["first_seen"] == "2024-01-15T08:00:00.000Z"
        assert result.data["last_seen"] == "2024-01-16T08:00:00.000Z"

    def test_executor_called_with_size_zero(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok()
        skill.execute("10.0.0.1", context={})
        call_ctx = mock_exec.execute.call_args[1]["context"]
        assert call_ctx["size"] == 0

    def test_summary_mentions_ip(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok(_SAMPLE_AGGS, total=10)
        result = skill.execute("10.0.0.1", context={})
        assert "10.0.0.1" in result.summary

    def test_source_stamped(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok()
        result = skill.execute("10.0.0.1", context={})
        assert result.source == "WindowsIPLookupSkill"


# ---------------------------------------------------------------------------
# Zero-result path
# ---------------------------------------------------------------------------


class TestWindowsIPLookupNoResults:
    def test_no_results_summary(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok({}, total=0)
        result = skill.execute("10.0.0.1", context={})
        assert result.success is True
        assert "No" in result.summary

    def test_empty_aggregates_on_no_results(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_ok({}, total=0)
        result = skill.execute("10.0.0.1", context={})
        assert result.data["top_rules"] == []
        assert result.data["activity_histogram"] == []
        assert result.data["peak_hour"] is None


# ---------------------------------------------------------------------------
# Failure propagation
# ---------------------------------------------------------------------------


class TestWindowsIPLookupFailures:
    def test_executor_failure_propagated(self):
        skill, _, mock_exec = _make_skill()
        mock_exec.execute.return_value = _exec_fail("indexer timeout")
        result = skill.execute("10.0.0.1", context={})
        assert result.success is False
        assert "indexer timeout" in result.summary

    def test_builder_failure_propagated(self):
        # Force builder to fail by removing the template from the store
        store = InMemoryTemplateStore()
        builder = QueryBuilderSkill(store)
        mock_exec = MagicMock(spec=QueryExecutorSkill)
        skill = WindowsIPLookupSkill.__new__(WindowsIPLookupSkill)
        skill._builder = builder
        skill._executor = mock_exec
        # Template is NOT registered → builder will fail

        result = skill.execute("10.0.0.1", context={})
        assert result.success is False
        mock_exec.execute.assert_not_called()
