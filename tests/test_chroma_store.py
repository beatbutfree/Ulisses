"""Tests for store.chroma_client — ChromaQueryStore + StoredQuery."""

import uuid

import chromadb
import pytest

from store.chroma_client import ChromaQueryStore, StoredQuery


@pytest.fixture
def store() -> ChromaQueryStore:
    """Ephemeral in-memory ChromaDB with a per-test collection for isolation."""
    client = chromadb.EphemeralClient()
    return ChromaQueryStore(client=client, collection=f"test_{uuid.uuid4().hex}")


def _sample(
    description: str = "Find Windows logon failures for an IP.",
    security_component: str = "wazuh",
    input_type: str = "ip_address",
    goal: str = "Identify brute-force activity against a host.",
) -> StoredQuery:
    return StoredQuery(
        description=description,
        query='{"query":{"term":{"data.win.eventdata.ipAddress":"{{ip}}"}}}',
        parameters=["ip"],
        security_component=security_component,
        sec_comp_extra="windows_eventchannel",
        input_type=input_type,
        goal=goal,
    )


def test_add_and_get_roundtrip(store: ChromaQueryStore) -> None:
    q = _sample()
    store.add(q)
    retrieved = store.get(q.id)
    assert retrieved is not None
    assert retrieved.query == q.query
    assert retrieved.parameters == q.parameters
    assert retrieved.security_component == "wazuh"
    assert retrieved.input_type == "ip_address"


def test_search_filters_by_metadata(store: ChromaQueryStore) -> None:
    store.add(_sample(input_type="ip_address"))
    store.add(_sample(input_type="username", description="Find logons by username."))

    hits_ip = store.search(
        goal="brute force IP",
        security_component="wazuh",
        input_type="ip_address",
    )
    assert all(h.input_type == "ip_address" for h in hits_ip)

    hits_user = store.search(
        goal="user activity",
        security_component="wazuh",
        input_type="username",
    )
    assert all(h.input_type == "username" for h in hits_user)


def test_search_respects_security_component(store: ChromaQueryStore) -> None:
    store.add(_sample(security_component="wazuh"))
    store.add(_sample(security_component="elastic"))

    hits = store.search(
        goal="anything",
        security_component="wazuh",
        input_type="ip_address",
    )
    assert all(h.security_component == "wazuh" for h in hits)


def test_search_empty_returns_empty(store: ChromaQueryStore) -> None:
    hits = store.search(
        goal="nothing stored yet",
        security_component="wazuh",
        input_type="ip_address",
    )
    assert hits == []


def test_increment_counters_updates_metadata(store: ChromaQueryStore) -> None:
    q = _sample()
    store.add(q)

    store.increment_counters(q.id, success=True)
    store.increment_counters(q.id, success=False)

    updated = store.get(q.id)
    assert updated is not None
    assert updated.times_used == 2
    assert updated.times_successful == 1
    assert updated.last_used_at != ""


def test_increment_counters_unknown_id_is_noop(store: ChromaQueryStore) -> None:
    store.increment_counters("does-not-exist", success=True)  # should not raise
    assert len(store) == 0


def test_all_returns_every_document(store: ChromaQueryStore) -> None:
    store.add(_sample(description="a"))
    store.add(_sample(description="b"))
    all_docs = store.all()
    assert len(all_docs) == 2
