"""Tests for agent.logging_config — run_id-stamped structured JSON logger."""

import json
import logging
from pathlib import Path

from agent import logging_config


def test_new_run_id_is_unique() -> None:
    a = logging_config.new_run_id()
    b = logging_config.new_run_id()
    assert a != b
    assert len(a) > 0


def test_get_logger_stamps_run_id(tmp_path: Path, monkeypatch) -> None:
    # Force the log directory into a temp location and reset state.
    monkeypatch.setattr(logging_config, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(logging_config, "_LOG_FILE", tmp_path / "soc_agent.jsonl")
    monkeypatch.setattr(logging_config, "_configured", False)
    logging.getLogger(logging_config._LOGGER_NAME).handlers.clear()

    logger = logging_config.get_logger(run_id="test-run-42")
    logger.info("skill_called", extra={"event": "skill_called", "skill_name": "demo"})

    for handler in logging.getLogger(logging_config._LOGGER_NAME).handlers:
        handler.flush()

    log_file = tmp_path / "soc_agent.jsonl"
    assert log_file.exists()
    last = log_file.read_text().strip().splitlines()[-1]
    parsed = json.loads(last)
    assert parsed["run_id"] == "test-run-42"
    assert parsed["event"] == "skill_called"
    assert parsed["skill_name"] == "demo"


def test_idempotent_configuration(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(logging_config, "_LOG_DIR", tmp_path)
    monkeypatch.setattr(logging_config, "_LOG_FILE", tmp_path / "soc_agent.jsonl")
    monkeypatch.setattr(logging_config, "_configured", False)
    logging.getLogger(logging_config._LOGGER_NAME).handlers.clear()

    logging_config.get_logger("a")
    first_handlers = list(logging.getLogger(logging_config._LOGGER_NAME).handlers)

    logging_config.get_logger("b")
    second_handlers = list(logging.getLogger(logging_config._LOGGER_NAME).handlers)

    # Calling twice should not duplicate handlers.
    assert len(first_handlers) == len(second_handlers) == 2
