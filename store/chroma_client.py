"""ChromaDB-backed store for discovered and reflector-generated query templates.

Documents stored here are OpenSearch DSL templates (with ``{{placeholder}}``
syntax) produced by the ``QueryCrafterSkill`` and promoted by the
``ReflectorAgent``. They sit **alongside** — never replace — the curated
``InMemoryTemplateStore`` that backs battle-tested analysis skills.

Retrieval workflow:

1. Caller supplies ``security_component`` + ``input_type`` — applied as
   ChromaDB metadata filters **before** the embedding search.
2. Semantic similarity is then computed against a concatenation of the
   stored ``description`` and ``goal`` fields.

Embedding: ChromaDB's default ``all-MiniLM-L6-v2`` (sentence-transformers),
which runs locally with no network dependency.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import chromadb
from chromadb.api import ClientAPI
from chromadb.api.models.Collection import Collection

_DEFAULT_PATH = os.getenv("CHROMADB_PATH", "chroma_db")
_COLLECTION = "soc_agent_queries"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class StoredQuery:
    """A ChromaDB document representing one reusable DSL template.

    The embedding text is built from ``description + " " + goal`` so both
    fields contribute to semantic retrieval.
    """

    description: str
    query: str                       # OpenSearch DSL with {{placeholders}}
    parameters: list[str]            # placeholder names
    security_component: str          # e.g. "wazuh"
    sec_comp_extra: str              # e.g. "windows_eventchannel"
    input_type: str                  # ip_address | username | rule_id | event_id
    goal: str
    times_used: int = 0
    times_successful: int = 0
    created_at: str = field(default_factory=_utc_now)
    last_used_at: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_metadata(self) -> dict[str, Any]:
        """Serialise scalar fields only — ChromaDB metadata rejects lists."""
        return {
            "security_component": self.security_component,
            "sec_comp_extra": self.sec_comp_extra,
            "input_type": self.input_type,
            "description": self.description,
            "query": self.query,
            "parameters": ",".join(self.parameters),
            "goal": self.goal,
            "times_used": self.times_used,
            "times_successful": self.times_successful,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
        }

    @classmethod
    def from_metadata(cls, doc_id: str, metadata: dict[str, Any]) -> "StoredQuery":
        params_raw = metadata.get("parameters", "")
        params = [p for p in params_raw.split(",") if p] if isinstance(params_raw, str) else list(params_raw)
        return cls(
            id=doc_id,
            description=metadata.get("description", ""),
            query=metadata.get("query", ""),
            parameters=params,
            security_component=metadata.get("security_component", ""),
            sec_comp_extra=metadata.get("sec_comp_extra", ""),
            input_type=metadata.get("input_type", ""),
            goal=metadata.get("goal", ""),
            times_used=int(metadata.get("times_used", 0)),
            times_successful=int(metadata.get("times_successful", 0)),
            created_at=metadata.get("created_at", ""),
            last_used_at=metadata.get("last_used_at", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ChromaQueryStore:
    """Thin wrapper around a persistent ChromaDB collection.

    Public API::

        search(goal, security_component, input_type, k=3) -> list[StoredQuery]
        add(StoredQuery)                                   -> None
        increment_counters(id, success: bool)              -> None
        get(id)                                            -> StoredQuery | None
        all()                                              -> list[StoredQuery]

    Args:
        path:        On-disk location for the Chroma database. Defaults to
                     ``$CHROMADB_PATH`` or ``./chroma_db``.
        client:      Pre-built ``ClientAPI`` — pass a Chroma ``EphemeralClient``
                     in tests so nothing touches the filesystem.
        collection:  Override the collection name (useful for test isolation).
    """

    def __init__(
        self,
        path: str | Path | None = None,
        client: ClientAPI | None = None,
        collection: str = _COLLECTION,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            resolved = Path(path) if path is not None else Path(_DEFAULT_PATH)
            resolved.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(resolved))
        self._collection: Collection = self._client.get_or_create_collection(collection)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def add(self, query: StoredQuery) -> None:
        """Insert a new query template. Duplicate IDs raise."""
        document = f"{query.description}\n{query.goal}"
        self._collection.add(
            ids=[query.id],
            documents=[document],
            metadatas=[query.to_metadata()],
        )

    def increment_counters(self, query_id: str, success: bool) -> None:
        """Bump ``times_used`` (always) and ``times_successful`` (if ``success``).

        Also stamps ``last_used_at``. No-op if ``query_id`` is unknown.
        """
        existing = self._collection.get(ids=[query_id])
        if not existing.get("ids"):
            return

        metadata = existing["metadatas"][0]
        metadata["times_used"] = int(metadata.get("times_used", 0)) + 1
        if success:
            metadata["times_successful"] = int(metadata.get("times_successful", 0)) + 1
        metadata["last_used_at"] = _utc_now()

        self._collection.update(ids=[query_id], metadatas=[metadata])

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def search(
        self,
        goal: str,
        security_component: str,
        input_type: str,
        k: int = 3,
    ) -> list[StoredQuery]:
        """Return top-k semantically similar queries matching the metadata filters.

        Filters are AND-combined and applied **before** the embedding search,
        so the similarity results are always within scope.

        Args:
            goal:               Natural-language description of what the caller
                                wants to find. Embedded and compared against the
                                stored ``description + goal`` text.
            security_component: Hard filter (e.g. ``"wazuh"``).
            input_type:         Hard filter (e.g. ``"ip_address"``).
            k:                  Maximum number of hits to return.

        Returns:
            List of matching ``StoredQuery`` objects (empty if no hits).
        """
        where = {
            "$and": [
                {"security_component": {"$eq": security_component}},
                {"input_type": {"$eq": input_type}},
            ]
        }
        results = self._collection.query(
            query_texts=[goal],
            n_results=k,
            where=where,
        )
        ids = results.get("ids", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        return [
            StoredQuery.from_metadata(doc_id=ids[i], metadata=metadatas[i])
            for i in range(len(ids))
        ]

    def get(self, query_id: str) -> StoredQuery | None:
        """Return a stored query by its ID, or ``None`` if absent."""
        hit = self._collection.get(ids=[query_id])
        if not hit.get("ids"):
            return None
        return StoredQuery.from_metadata(doc_id=hit["ids"][0], metadata=hit["metadatas"][0])

    def all(self) -> list[StoredQuery]:
        """Return every document in the collection (for inspection / tests)."""
        hit = self._collection.get()
        ids = hit.get("ids", [])
        metadatas = hit.get("metadatas", [])
        return [
            StoredQuery.from_metadata(doc_id=ids[i], metadata=metadatas[i])
            for i in range(len(ids))
        ]

    def __len__(self) -> int:
        return self._collection.count()
