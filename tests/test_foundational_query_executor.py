"""Tests for skills.foundational.query_executor — QueryExecutorSkill."""

import json
from unittest.mock import MagicMock

import pytest

from skills.foundational.query_executor import QueryExecutorSkill
from skills.base import InputType
from wazuh.client import DEFAULT_INDEX


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_raw_response(
    sources: list[dict] | None = None,
    total: int | None = None,
    aggregations: dict | None = None,
    took: int = 2,
) -> dict:
    """Build a minimal OpenSearch search response dict."""
    sources = sources or []
    return {
        "took": took,
        "hits": {
            "total": {"value": total if total is not None else len(sources), "relation": "eq"},
            "hits": [{"_index": "wazuh-archives-test", "_source": s} for s in sources],
        },
        "aggregations": aggregations or {},
    }


def _make_client(
    sources: list[dict] | None = None,
    total: int | None = None,
    aggregations: dict | None = None,
) -> MagicMock:
    """Return a mock WazuhIndexerClient whose execute_query() returns a raw response."""
    client = MagicMock()
    client.execute_query.return_value = _make_raw_response(
        sources=sources, total=total, aggregations=aggregations
    )
    return client


def _dsl(query: dict | None = None) -> str:
    """Return a minimal valid DSL JSON string."""
    return json.dumps({"query": query or {"match_all": {}}})


# ---------------------------------------------------------------------------
# Attributes
# ---------------------------------------------------------------------------


class TestQueryExecutorSkillAttributes:
    def test_name(self):
        assert QueryExecutorSkill(_make_client()).name == "query_executor"

    def test_input_type(self):
        assert QueryExecutorSkill(_make_client()).input_type == InputType.QUERY_DSL


# ---------------------------------------------------------------------------
# Validation failures (no network call)
# ---------------------------------------------------------------------------


class TestQueryExecutorValidation:
    def test_invalid_json_returns_fail(self):
        skill = QueryExecutorSkill(_make_client())
        result = skill.execute("not valid json {{{", context={})

        assert result.success is False
        assert "not valid JSON" in result.summary

    def test_json_array_returns_fail(self):
        skill = QueryExecutorSkill(_make_client())
        result = skill.execute(json.dumps([1, 2, 3]), context={})

        assert result.success is False
        assert "JSON object" in result.summary

    def test_json_string_returns_fail(self):
        skill = QueryExecutorSkill(_make_client())
        result = skill.execute(json.dumps("just a string"), context={})

        assert result.success is False

    def test_client_not_called_on_invalid_dsl(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute("bad json", context={})
        client.execute_query.assert_not_called()


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------


class TestQueryExecutorSuccess:
    def test_returns_hits_in_data(self):
        sources = [{"rule": {"id": "5402"}}, {"rule": {"id": "5403"}}]
        skill = QueryExecutorSkill(_make_client(sources=sources, total=2))
        result = skill.execute(_dsl(), context={})

        assert result.success is True
        assert len(result.data["hits"]) == 2
        assert result.data["total"] == 2
        assert "took_ms" in result.data

    def test_aggregations_included_in_data(self):
        aggs = {"top_ips": {"buckets": [{"key": "10.0.0.1", "doc_count": 5}]}}
        skill = QueryExecutorSkill(_make_client(aggregations=aggs))
        result = skill.execute(_dsl(), context={})

        assert result.success is True
        assert result.data["aggregations"] == aggs

    def test_aggregations_empty_dict_when_absent(self):
        skill = QueryExecutorSkill(_make_client())
        result = skill.execute(_dsl(), context={})
        assert result.data["aggregations"] == {}

    def test_summary_mentions_total_not_returned_count(self):
        # total=500 but only 2 returned — summary should reference total
        skill = QueryExecutorSkill(_make_client(sources=[{"a": 1}, {"b": 2}], total=500))
        result = skill.execute(_dsl(), context={})
        assert "500" in result.summary

    def test_zero_total_summary(self):
        skill = QueryExecutorSkill(_make_client(sources=[], total=0))
        result = skill.execute(_dsl(), context={})
        assert result.success is True
        assert "no results" in result.summary.lower()

    def test_size_zero_aggregation_query(self):
        """size=0 → no hits, but aggregations still present."""
        aggs = {"event_count": {"value": 42}}
        skill = QueryExecutorSkill(_make_client(sources=[], total=100, aggregations=aggs))
        result = skill.execute(_dsl(), context={"size": 0})

        assert result.success is True
        assert result.data["hits"] == []
        assert result.data["total"] == 100
        assert result.data["aggregations"] == aggs

    def test_default_index_used(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={})
        assert client.execute_query.call_args[1]["index"] == DEFAULT_INDEX

    def test_custom_index_from_context(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={"index": "wazuh-alerts-*"})
        assert client.execute_query.call_args[1]["index"] == "wazuh-alerts-*"

    def test_custom_size_from_context(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={"size": 500})
        assert client.execute_query.call_args[1]["size"] == 500

    def test_full_log_stripped_by_default(self):
        sources = [{"rule": {"id": "1"}, "full_log": "raw line"}]
        skill = QueryExecutorSkill(_make_client(sources=sources))
        result = skill.execute(_dsl(), context={})
        assert "full_log" not in result.data["hits"][0]

    def test_full_log_kept_when_requested(self):
        sources = [{"rule": {"id": "1"}, "full_log": "raw line"}]
        skill = QueryExecutorSkill(_make_client(sources=sources))
        result = skill.execute(_dsl(), context={"keep_full_log": True})
        assert result.data["hits"][0]["full_log"] == "raw line"

    def test_source_and_duration_stamped(self):
        skill = QueryExecutorSkill(_make_client())
        result = skill.execute(_dsl(), context={})
        assert result.source == "QueryExecutorSkill"
        assert result.duration_ms >= 0

    def test_dsl_dict_passed_to_client(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        raw = _dsl({"term": {"src_ip": "10.0.0.1"}})
        skill.execute(raw, context={})
        passed_dsl = client.execute_query.call_args[0][0]
        assert passed_dsl == {"query": {"term": {"src_ip": "10.0.0.1"}}}


# ---------------------------------------------------------------------------
# Indexer error handling
# ---------------------------------------------------------------------------


class TestQueryExecutorErrors:
    def test_transport_error_returns_fail(self):
        from opensearchpy.exceptions import TransportError

        client = MagicMock()
        client.execute_query.side_effect = TransportError(503, "unavailable")
        skill = QueryExecutorSkill(client)
        result = skill.execute(_dsl(), context={})

        assert result.success is False
        assert "Query execution failed" in result.summary

    def test_connection_error_returns_fail(self):
        from opensearchpy.exceptions import ConnectionError as OSConnectionError

        client = MagicMock()
        client.execute_query.side_effect = OSConnectionError("timeout", None, None)
        skill = QueryExecutorSkill(client)
        result = skill.execute(_dsl(), context={})

        assert result.success is False
        assert "unreachable" in result.summary.lower()
