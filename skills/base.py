"""Skill interface contract.

Every skill in the system subclasses ``Skill``, declares ``name``,
``description``, and ``input_type`` as class attributes, and implements
``_run()``.  Callers must always use ``execute()`` — never ``_run()``
directly.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
import time
from typing import Any


class InputType(str, Enum):
    """Observable types that skills can accept as input.

    Add new members here as new skill families are introduced.
    """

    IP_ADDRESS = "ip_address"
    USERNAME = "username"
    RULE_ID = "rule_id"
    EVENT_ID = "event_id"
    # Foundational skill types
    TEMPLATE_NAME = "template_name"
    QUERY_DSL = "query_dsl"


class Severity(str, Enum):
    """Internal severity levels, aligned with Wazuh rule levels.

    Mapping:
      - Levels  0–6  → LOW
      - Levels  7–11 → MEDIUM
      - Levels 12–14 → HIGH
      - Level   15   → CRITICAL
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_wazuh_level(cls, level: int) -> "Severity":
        """Map a raw Wazuh rule level (0–15) to a Severity bucket."""
        if level <= 6:
            return cls.LOW
        if level <= 11:
            return cls.MEDIUM
        if level <= 14:
            return cls.HIGH
        return cls.CRITICAL


@dataclass
class SkillResult:
    """Structured output returned by every Skill execution.

    ``data`` and ``summary`` are set by ``_run()``.
    ``source`` and ``duration_ms`` are stamped by ``execute()`` — do not
    set them inside ``_run()``.
    """

    data: dict[str, Any]
    """JSON-serialisable enrichment payload."""

    summary: str
    """1–3 sentence natural-language brief written for a human analyst."""

    success: bool
    """False when the underlying query returned an error or raised."""

    source: str = field(default="", init=True)
    """Skill class name — populated by execute(), not by _run()."""

    duration_ms: float = field(default=0.0, init=True)
    """Wall-clock execution time in milliseconds — populated by execute()."""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return asdict(self)

    @classmethod
    def fail(cls, reason: str) -> "SkillResult":
        """Convenience constructor for an explicit, known failure.

        Use this inside ``_run()`` when the skill encounters a recoverable
        error (missing template, invalid input, etc.) that should not raise.
        The ``execute()`` wrapper already catches unhandled exceptions, so
        ``fail()`` is reserved for intentional, descriptive failures.

        Args:
            reason: Human-readable explanation surfaced in ``summary``.

        Returns:
            A ``SkillResult`` with ``success=False``, empty ``data``, and
            ``summary`` set to ``reason``.
        """
        return cls(data={}, summary=reason, success=False)


class Skill(ABC):
    """Abstract base class for all SOC agent skills.

    Subclasses must declare three class-level attributes::

        name: str          — unique identifier used by SkillRegistry
        description: str   — human-readable purpose (also used for KB retrieval)
        input_type: InputType

    Then implement ``_run()``.  Always invoke skills via ``execute()``.
    """

    name: str
    description: str
    input_type: InputType

    @abstractmethod
    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        """Core skill logic.

        Implementations must populate ``data``, ``summary``, and ``success``
        on the returned ``SkillResult``.  Leave ``source`` and ``duration_ms``
        at their defaults — ``execute()`` stamps them after the call returns.

        Args:
            value:   The observable being investigated (e.g. an IP string).
            context: Shared state from the agent loop (alert dict, prior
                     results, etc.).

        Returns:
            A ``SkillResult`` with ``data``, ``summary``, and ``success`` set.
        """
        ...

    def execute(self, value: str, context: dict[str, Any] | None = None) -> SkillResult:
        """Public entry point — always call this, never ``_run()`` directly.

        Wraps ``_run()`` with:
        - wall-clock timing
        - source tagging (class name)
        - top-level exception guard (any exception → failed SkillResult)

        Args:
            value:   The observable to investigate.
            context: Optional shared agent state; defaults to an empty dict.

        Returns:
            A fully populated ``SkillResult``.
        """
        if context is None:
            context = {}

        t0 = time.monotonic()
        try:
            result = self._run(value, context)
        except Exception as exc:
            result = SkillResult(
                data={},
                summary=f"Skill execution failed: {exc}",
                success=False,
            )

        result.source = self.__class__.__name__
        result.duration_ms = round((time.monotonic() - t0) * 1_000, 3)
        return result
