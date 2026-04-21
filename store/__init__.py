"""Persistent knowledge-store layer.

``ChromaQueryStore`` holds discovered / generated query templates so the
agent accumulates analytical memory over time. Curated, battle-tested
templates live in ``skills.foundational.template_store.InMemoryTemplateStore``
— the two stores are separate by design.
"""

from store.chroma_client import ChromaQueryStore, StoredQuery

__all__ = ["ChromaQueryStore", "StoredQuery"]
