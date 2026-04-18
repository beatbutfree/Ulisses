"""Tests for skills.foundational.query_executor — QueryExecutorSkill."""

import json
from unittest.mock import MagicMock

import pytest

from skills.foundational.query_executor import QueryExecutorSkill
from skills.base import InputType
from wazuh.client import DEFAULT_INDEX
from wazuh.parser import ParsedResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(hits: list[dict] | None = None, total: int | None = None) -> MagicMock:
    """Return a mock WazuhIndexerClient whose query() returns a ParsedResponse."""
    hits = hits or []
    parsed = ParsedResponse(
        hits=hits,
        total=total if total is not None else len(hits),
        took_ms=5,
    )
    client = MagicMock()
    client.query.return_value = parsed
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
        client.query.assert_not_called()


# ---------------------------------------------------------------------------
# Successful execution
# ---------------------------------------------------------------------------


class TestQueryExecutorSuccess:
    def test_returns_hits_in_data(self):
        hits = [{"rule": {"id": "5402"}}, {"rule": {"id": "5403"}}]
        skill = QueryExecutorSkill(_make_client(hits=hits, total=2))
        result = skill.execute(_dsl(), context={})

        assert result.success is True
        assert result.data["hits"] == hits
        assert result.data["total"] == 2
        assert "took_ms" in result.data

    def test_summary_includes_hit_count(self):
        skill = QueryExecutorSkill(_make_client(hits=[{"rule": {"id": "1"}}]))
        result = skill.execute(_dsl(), context={})
        assert "1 hit" in result.summary

    def test_empty_result_summary(self):
        skill = QueryExecutorSkill(_make_client(hits=[]))
        result = skill.execute(_dsl(), context={})
        assert result.success is True
        assert "no results" in result.summary.lower()

    def test_default_index_used(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={})
        client.query.assert_called_once()
        assert client.query.call_args[1]["index"] == DEFAULT_INDEX

    def test_custom_index_from_context(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={"index": "wazuh-alerts-*"})
        assert client.query.call_args[1]["index"] == "wazuh-alerts-*"

    def test_custom_size_from_context(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={"size": 500})
        assert client.query.call_args[1]["size"] == 500

    def test_keep_full_log_default_false(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={})
        assert client.query.call_args[1]["keep_full_log"] is False

    def test_keep_full_log_from_context(self):
        client = _make_client()
        skill = QueryExecutorSkill(client)
        skill.execute(_dsl(), context={"keep_full_log": True})
        assert client.query.call_args[1]["keep_full_log"] is True

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
        passed_dsl = client.query.call_args[0][0]
        assert passed_dsl == {"query": {"term": {"src_ip": "10.0.0.1"}}}


# ---------------------------------------------------------------------------
# Indexer error handling
# ---------------------------------------------------------------------------


class TestQueryExecutorErrors:
    def test_transport_error_returns_fail(self):
        from opensearchpy.exceptions import TransportError

        client = MagicMock()
        client.query.side_effect = TransportError(503, "unavailable")
        skill = QueryExecutorSkill(client)
        result = skill.execute(_dsl(), context={})

        assert result.success is False
        assert "Query execution failed" in result.summary

    def test_connection_error_returns_fail(self):
        from opensearchpy.exceptions import ConnectionError as OSConnectionError

        client = MagicMock()
        client.query.side_effect = OSConnectionError("timeout", None, None)
        skill = QueryExecutorSkill(client)
        result = skill.execute(_dsl(), context={})

        assert result.success is False
        assert "unreachable" in result.summary.lower()
