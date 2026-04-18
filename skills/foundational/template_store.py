"""Query template store for the foundational skill layer.

A ``QueryTemplate`` describes a reusable OpenSearch DSL query pattern.
``InMemoryTemplateStore`` is the Step-3 implementation; Step 6 will
introduce a ChromaDB-backed store with semantic retrieval — same protocol,
different backend.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class QueryTemplate:
    """A named, parameterised OpenSearch DSL query template.

    The ``template`` field is a DSL JSON string containing ``{{param}}``
    placeholders.  ``params`` declares every placeholder name so the agent
    knows exactly which values to supply before calling ``QueryBuilderSkill``.

    Args:
        name:        Unique identifier used for exact-match retrieval.
        description: Human-readable purpose — also used as the embedding text
                     for semantic retrieval in Step 6.
        input_type:  Observable type this template targets (e.g. ``"src_ip"``).
        params:      Ordered list of placeholder names the template requires.
        template:    DSL JSON string with ``{{placeholder}}`` syntax.
    """

    name: str
    description: str
    input_type: str
    params: list[str]
    template: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return asdict(self)


class InMemoryTemplateStore:
    """In-memory store for ``QueryTemplate`` objects.

    Supports exact-match retrieval by name.  Designed to be swapped for a
    ChromaDB-backed implementation in Step 6 without changing the callers —
    both expose ``get``, ``add``, and ``list_all``.
    """

    def __init__(self) -> None:
        self._templates: dict[str, QueryTemplate] = {}

    def add(self, template: QueryTemplate) -> None:
        """Register a template, overwriting any existing entry with the same name.

        Args:
            template: The ``QueryTemplate`` to store.
        """
        self._templates[template.name] = template

    def get(self, name: str) -> QueryTemplate | None:
        """Return the template registered under ``name``, or ``None``.

        Args:
            name: Exact template name.

        Returns:
            The matching ``QueryTemplate``, or ``None`` if not found.
        """
        return self._templates.get(name)

    def list_all(self) -> list[QueryTemplate]:
        """Return all stored templates in insertion order."""
        return list(self._templates.values())

    def __len__(self) -> int:
        return len(self._templates)
