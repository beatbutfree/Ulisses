"""Structured JSON logging setup for the SOC agent pipeline.

Every pipeline run gets a ``run_id`` that is propagated into every log record
via ``get_logger(run_id)``. Records are emitted to stdout and to a rotating
file at ``logs/soc_agent.jsonl``.

Log schema (see CLAUDE.md for the canonical list of fields)::

    {
      "timestamp": str,           # ISO 8601 UTC
      "level":     str,
      "run_id":    str,           # per pipeline invocation
      "agent":     str,           # analyst | evaluator | formatter | reflector
      "event":     str,           # skill_called | query_retrieved | query_stored | ...
      "skill_name": str,
      ... free-form extras ...
    }
"""

import logging
import logging.handlers
import os
import uuid
from pathlib import Path
from typing import Any

from pythonjsonlogger.json import JsonFormatter

_LOG_DIR = Path(os.getenv("SOC_LOG_DIR", "logs"))
_LOG_FILE = _LOG_DIR / "soc_agent.jsonl"
_LOGGER_NAME = "soc_agent"

_FORMAT_FIELDS = "%(timestamp)s %(level)s %(name)s %(message)s"

_configured: bool = False


def _configure_root_logger() -> None:
    """Install the JSON formatter + handlers exactly once per process."""
    global _configured
    if _configured:
        return

    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = JsonFormatter(
        _FORMAT_FIELDS,
        rename_fields={"levelname": "level", "asctime": "timestamp"},
        timestamp=True,
    )

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)

    rotating = logging.handlers.RotatingFileHandler(
        _LOG_FILE,
        maxBytes=10_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    rotating.setFormatter(formatter)

    root = logging.getLogger(_LOGGER_NAME)
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(stream)
    root.addHandler(rotating)
    root.propagate = False

    _configured = True


class _RunIdAdapter(logging.LoggerAdapter):  # type: ignore[type-arg]
    """LoggerAdapter that stamps every record with ``run_id``."""

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        extra = kwargs.setdefault("extra", {})
        extra["run_id"] = self.extra["run_id"]
        return msg, kwargs


def new_run_id() -> str:
    """Return a fresh UUID v4 string to tag one pipeline invocation."""
    return str(uuid.uuid4())


def get_logger(run_id: str | None = None) -> _RunIdAdapter:
    """Return a logger that auto-stamps ``run_id`` on every record.

    Args:
        run_id: Identifier tagged onto every emitted record. If ``None`` a
                fresh UUID is generated — useful for ad-hoc scripts.

    Returns:
        A ``LoggerAdapter`` ready for ``.info(event="...", extra={...})`` calls.
    """
    _configure_root_logger()
    rid = run_id if run_id is not None else new_run_id()
    return _RunIdAdapter(logging.getLogger(_LOGGER_NAME), {"run_id": rid})
