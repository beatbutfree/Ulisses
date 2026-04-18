"""Tests for skills.foundational.template_store."""

import pytest

from skills.foundational.template_store import InMemoryTemplateStore, QueryTemplate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_template(name: str = "t1", params: list[str] | None = None) -> QueryTemplate:
    return QueryTemplate(
        name=name,
        description="A test template",
        input_type="src_ip",
        params=params or ["src_ip"],
        template='{"query":{"term":{"src_ip":{{src_ip}}}}}',
    )


# ---------------------------------------------------------------------------
# QueryTemplate
# ---------------------------------------------------------------------------


class TestQueryTemplate:
    def test_to_dict_is_json_serialisable(self):
        import json
        t = _make_template()
        d = t.to_dict()
        assert json.dumps(d)  # must not raise

    def test_to_dict_keys(self):
        t = _make_template("brute_force", ["src_ip", "threshold"])
        d = t.to_dict()
        assert set(d.keys()) == {"name", "description", "input_type", "params", "template"}
        assert d["params"] == ["src_ip", "threshold"]


# ---------------------------------------------------------------------------
# InMemoryTemplateStore
# ---------------------------------------------------------------------------


class TestInMemoryTemplateStore:
    def test_add_and_get(self):
        store = InMemoryTemplateStore()
        t = _make_template("detect_brute_force")
        store.add(t)
        assert store.get("detect_brute_force") is t

    def test_get_missing_returns_none(self):
        store = InMemoryTemplateStore()
        assert store.get("nonexistent") is None

    def test_overwrite_existing(self):
        store = InMemoryTemplateStore()
        t1 = _make_template("t", params=["a"])
        t2 = _make_template("t", params=["b"])
        store.add(t1)
        store.add(t2)
        assert store.get("t") is t2

    def test_list_all_empty(self):
        assert InMemoryTemplateStore().list_all() == []

    def test_list_all_returns_all(self):
        store = InMemoryTemplateStore()
        t1 = _make_template("t1")
        t2 = _make_template("t2")
        store.add(t1)
        store.add(t2)
        assert set(t.name for t in store.list_all()) == {"t1", "t2"}

    def test_len(self):
        store = InMemoryTemplateStore()
        assert len(store) == 0
        store.add(_make_template("a"))
        store.add(_make_template("b"))
        assert len(store) == 2

    def test_multiple_params(self):
        store = InMemoryTemplateStore()
        t = QueryTemplate(
            name="multi",
            description="multi-param",
            input_type="src_ip",
            params=["src_ip", "threshold", "time_window"],
            template="...",
        )
        store.add(t)
        retrieved = store.get("multi")
        assert retrieved is not None
        assert retrieved.params == ["src_ip", "threshold", "time_window"]
