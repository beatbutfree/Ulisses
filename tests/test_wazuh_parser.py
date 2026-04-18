"""Tests for wazuh.parser — strip_empty, parse_hits, ParsedResponse."""

import pytest

from wazuh.parser import ParsedResponse, parse_hits, strip_empty


# ---------------------------------------------------------------------------
# strip_empty
# ---------------------------------------------------------------------------


class TestStripEmpty:
    def test_none_value_removed(self):
        assert strip_empty({"a": None}) == {}

    def test_empty_string_removed(self):
        assert strip_empty({"a": ""}) == {}

    def test_empty_dict_removed(self):
        assert strip_empty({"a": {}}) == {}

    def test_empty_list_removed(self):
        assert strip_empty({"a": []}) == {}

    def test_zero_preserved(self):
        assert strip_empty({"a": 0}) == {"a": 0}

    def test_false_preserved(self):
        assert strip_empty({"a": False}) == {"a": False}

    def test_string_zero_preserved(self):
        assert strip_empty({"a": "0"}) == {"a": "0"}

    def test_nested_null_removed(self):
        result = strip_empty({"rule": {"id": "5402", "level": None}})
        assert result == {"rule": {"id": "5402"}}

    def test_deeply_nested_emptied_dict_removed(self):
        # After stripping, the inner dict becomes {} which should also be dropped
        result = strip_empty({"outer": {"inner": {"x": None}}})
        assert result == {}

    def test_list_items_cleaned(self):
        result = strip_empty({"tags": [None, "", "sshd", None]})
        assert result == {"tags": ["sshd"]}

    def test_list_of_dicts_cleaned(self):
        result = strip_empty({"agents": [{"id": "001", "ip": None}, {"id": "002"}]})
        assert result == {"agents": [{"id": "001"}, {"id": "002"}]}

    def test_scalar_passthrough(self):
        assert strip_empty("hello") == "hello"
        assert strip_empty(42) == 42
        assert strip_empty(None) is None

    def test_mixed_flat_dict(self):
        result = strip_empty(
            {"id": "5402", "level": 7, "description": "Sshd", "groups": [], "gdpr": None}
        )
        assert result == {"id": "5402", "level": 7, "description": "Sshd"}


# ---------------------------------------------------------------------------
# parse_hits
# ---------------------------------------------------------------------------


def _make_response(sources: list[dict], total: int = None, took: int = 3) -> dict:
    """Build a minimal OpenSearch search response."""
    hits = [{"_index": "wazuh-archives-4.x-2024", "_source": s} for s in sources]
    return {
        "took": took,
        "hits": {
            "total": {"value": total if total is not None else len(sources), "relation": "eq"},
            "hits": hits,
        },
    }


class TestParseHits:
    def test_basic_extraction(self):
        response = _make_response([{"rule": {"id": "5402", "level": 3}}])
        result = parse_hits(response)
        assert isinstance(result, ParsedResponse)
        assert result.total == 1
        assert result.took_ms == 3
        assert result.hits == [{"rule": {"id": "5402", "level": 3}}]

    def test_empty_response(self):
        response = _make_response([])
        result = parse_hits(response)
        assert result.hits == []
        assert result.total == 0
        assert result.is_empty() is True

    def test_is_empty_false_when_hits_present(self):
        response = _make_response([{"rule": {"id": "1"}}])
        assert parse_hits(response).is_empty() is False

    def test_full_log_stripped_by_default(self):
        source = {"rule": {"id": "5402"}, "full_log": "raw syslog line here"}
        result = parse_hits(_make_response([source]))
        assert "full_log" not in result.hits[0]

    def test_full_log_kept_when_requested(self):
        source = {"rule": {"id": "5402"}, "full_log": "raw syslog line here"}
        result = parse_hits(_make_response([source]), keep_full_log=True)
        assert result.hits[0]["full_log"] == "raw syslog line here"

    def test_null_fields_stripped(self):
        source = {
            "rule": {"id": "5402", "level": 7},
            "syscheck": None,
            "vulnerability": {},
            "agent": {"id": "001", "name": "dc01", "ip": ""},
        }
        result = parse_hits(_make_response([source]))
        hit = result.hits[0]
        assert "syscheck" not in hit
        assert "vulnerability" not in hit
        assert hit["agent"] == {"id": "001", "name": "dc01"}

    def test_total_reflects_opensearch_count(self):
        # total can exceed len(hits) when size cap is applied
        sources = [{"rule": {"id": str(i)}} for i in range(5)]
        response = _make_response(sources, total=1000)
        result = parse_hits(response)
        assert result.total == 1000
        assert len(result.hits) == 5

    def test_multiple_hits(self):
        sources = [{"rule": {"id": "1"}}, {"rule": {"id": "2"}}, {"rule": {"id": "3"}}]
        result = parse_hits(_make_response(sources))
        assert len(result.hits) == 3
        assert result.hits[1]["rule"]["id"] == "2"

    def test_empty_source_yields_empty_dict(self):
        result = parse_hits(_make_response([{}]))
        assert result.hits == [{}]

    def test_missing_hits_key_returns_empty(self):
        result = parse_hits({})
        assert result.hits == []
        assert result.total == 0
        assert result.took_ms == 0

    def test_realistic_wazuh_event(self):
        """Smoke-test with a realistic (sparse) Wazuh _source document."""
        source = {
            "@timestamp": "2024-01-15T10:23:00.000Z",
            "rule": {"id": "5402", "level": 3, "description": "User login success", "groups": []},
            "agent": {"id": "001", "name": "dc01", "ip": "10.0.0.1"},
            "data": {
                "win": {
                    "system": {"eventID": "4624", "computer": "DC01"},
                    "eventdata": {"targetUserName": "jdoe", "ipAddress": "10.0.0.50"},
                }
            },
            "full_log": "Jan 15 10:23:00 DC01 MSWinEventLog...",
            "syscheck": None,
            "vulnerability": {},
            "location": "EventChannel",
        }
        result = parse_hits(_make_response([source]))
        hit = result.hits[0]

        assert "full_log" not in hit
        assert "syscheck" not in hit
        assert "vulnerability" not in hit
        assert "groups" not in hit["rule"]  # empty list stripped
        assert hit["agent"]["ip"] == "10.0.0.1"
        assert hit["data"]["win"]["eventdata"]["targetUserName"] == "jdoe"
