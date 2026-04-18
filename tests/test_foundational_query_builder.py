"""Tests for skills.foundational.query_builder — QueryBuilderSkill."""

import json

import pytest

from skills.foundational.query_builder import QueryBuilderSkill, _substitute
from skills.foundational.template_store import InMemoryTemplateStore, QueryTemplate
from skills.base import InputType, SkillResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _store_with(*templates: QueryTemplate) -> InMemoryTemplateStore:
    store = InMemoryTemplateStore()
    for t in templates:
        store.add(t)
    return store


BRUTE_FORCE = QueryTemplate(
    name="detect_brute_force",
    description="Detect brute force attempts from a source IP",
    input_type="src_ip",
    params=["src_ip", "threshold"],
    template=(
        '{"query":{"bool":{"filter":['
        '{"term":{"src_ip":{{src_ip}}}},'
        '{"range":{"count":{"gte":{{threshold}}}}}'
        ']}}}'
    ),
)

SIMPLE_IP = QueryTemplate(
    name="ip_events",
    description="All events for a source IP",
    input_type="src_ip",
    params=["src_ip"],
    template='{"query":{"term":{"src_ip":{{src_ip}}}}}',
)


# ---------------------------------------------------------------------------
# _substitute (unit tests, not going through execute())
# ---------------------------------------------------------------------------


class TestSubstitute:
    def test_string_param_produces_quoted_value(self):
        result = _substitute('{"field":{{val}}}', {"val": "10.0.0.1"})
        assert result == '{"field":"10.0.0.1"}'

    def test_int_param_produces_bare_number(self):
        result = _substitute('{"gte":{{n}}}', {"n": 100})
        assert result == '{"gte":100}'

    def test_list_param_produces_json_array(self):
        result = _substitute('{"terms":{"ids":{{ids}}}}', {"ids": ["a", "b"]})
        assert result == '{"terms":{"ids":["a","b"]}}'

    def test_multiple_placeholders(self):
        result = _substitute("{{a}} and {{b}}", {"a": "x", "b": 2})
        assert result == '"x" and 2'

    def test_missing_key_raises_key_error(self):
        with pytest.raises(KeyError):
            _substitute("{{missing}}", {})

    def test_extra_params_ignored(self):
        result = _substitute("{{a}}", {"a": 1, "b": 2})
        assert result == "1"

    def test_special_chars_in_string_escaped(self):
        result = _substitute('{{val}}', {"val": 'say "hi"'})
        # json.dumps escapes the inner quotes
        assert result == '"say \\"hi\\""'


# ---------------------------------------------------------------------------
# QueryBuilderSkill
# ---------------------------------------------------------------------------


class TestQueryBuilderSkillAttributes:
    def test_name(self):
        skill = QueryBuilderSkill(_store_with())
        assert skill.name == "query_builder"

    def test_input_type(self):
        skill = QueryBuilderSkill(_store_with())
        assert skill.input_type == InputType.TEMPLATE_NAME


class TestQueryBuilderSkillSuccess:
    def test_returns_dsl_string(self):
        skill = QueryBuilderSkill(_store_with(SIMPLE_IP))
        result = skill.execute("ip_events", context={"params": {"src_ip": "10.0.0.1"}})

        assert result.success is True
        assert "query" in result.data
        # The DSL must be valid JSON
        dsl = json.loads(result.data["query"])
        assert dsl["query"]["term"]["src_ip"] == "10.0.0.1"

    def test_data_contains_template_name_and_params_used(self):
        skill = QueryBuilderSkill(_store_with(SIMPLE_IP))
        result = skill.execute("ip_events", context={"params": {"src_ip": "192.168.1.5"}})

        assert result.data["template_name"] == "ip_events"
        assert result.data["params_used"] == {"src_ip": "192.168.1.5"}

    def test_extra_context_params_not_included_in_params_used(self):
        skill = QueryBuilderSkill(_store_with(SIMPLE_IP))
        result = skill.execute(
            "ip_events",
            context={"params": {"src_ip": "10.0.0.1", "extra_key": "ignored"}},
        )
        assert "extra_key" not in result.data["params_used"]

    def test_multi_param_template(self):
        skill = QueryBuilderSkill(_store_with(BRUTE_FORCE))
        result = skill.execute(
            "detect_brute_force",
            context={"params": {"src_ip": "10.0.0.2", "threshold": 5}},
        )

        assert result.success is True
        dsl = json.loads(result.data["query"])
        filters = dsl["query"]["bool"]["filter"]
        assert filters[0]["term"]["src_ip"] == "10.0.0.2"
        assert filters[1]["range"]["count"]["gte"] == 5

    def test_summary_mentions_template_name(self):
        skill = QueryBuilderSkill(_store_with(SIMPLE_IP))
        result = skill.execute("ip_events", context={"params": {"src_ip": "1.2.3.4"}})
        assert "ip_events" in result.summary

    def test_source_and_duration_stamped_by_execute(self):
        skill = QueryBuilderSkill(_store_with(SIMPLE_IP))
        result = skill.execute("ip_events", context={"params": {"src_ip": "1.2.3.4"}})
        assert result.source == "QueryBuilderSkill"
        assert result.duration_ms >= 0


class TestQueryBuilderSkillFailures:
    def test_template_not_found(self):
        skill = QueryBuilderSkill(_store_with())
        result = skill.execute("nonexistent", context={"params": {}})

        assert result.success is False
        assert "nonexistent" in result.summary

    def test_missing_required_param(self):
        skill = QueryBuilderSkill(_store_with(BRUTE_FORCE))
        result = skill.execute(
            "detect_brute_force",
            context={"params": {"src_ip": "10.0.0.1"}},  # missing "threshold"
        )

        assert result.success is False
        assert "threshold" in result.summary

    def test_empty_params_with_parameterised_template(self):
        skill = QueryBuilderSkill(_store_with(SIMPLE_IP))
        result = skill.execute("ip_events", context={})  # no "params" key at all

        assert result.success is False
        assert "src_ip" in result.summary

    def test_fail_result_has_empty_data(self):
        skill = QueryBuilderSkill(_store_with())
        result = skill.execute("missing", context={})
        assert result.data == {}
