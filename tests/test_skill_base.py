"""Tests for skills/base.py — InputType, Severity, SkillResult, Skill ABC."""

import pytest
from skills.base import InputType, Severity, Skill, SkillResult


# ---------------------------------------------------------------------------
# InputType
# ---------------------------------------------------------------------------


def test_input_type_members():
    assert InputType.IP_ADDRESS.value == "ip_address"
    assert InputType.USERNAME.value == "username"
    assert InputType.RULE_ID.value == "rule_id"
    assert InputType.EVENT_ID.value == "event_id"


def test_input_type_is_string_enum():
    """InputType values are usable as plain strings."""
    assert InputType.IP_ADDRESS == "ip_address"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", range(0, 7))
def test_severity_low(level: int):
    assert Severity.from_wazuh_level(level) == Severity.LOW


@pytest.mark.parametrize("level", range(7, 12))
def test_severity_medium(level: int):
    assert Severity.from_wazuh_level(level) == Severity.MEDIUM


@pytest.mark.parametrize("level", range(12, 15))
def test_severity_high(level: int):
    assert Severity.from_wazuh_level(level) == Severity.HIGH


def test_severity_critical():
    assert Severity.from_wazuh_level(15) == Severity.CRITICAL


# ---------------------------------------------------------------------------
# SkillResult
# ---------------------------------------------------------------------------


def test_skill_result_to_dict_contains_all_fields():
    result = SkillResult(
        data={"ip": "1.2.3.4", "hits": 5},
        summary="Found 5 hits for 1.2.3.4.",
        success=True,
        source="IPLookupSkill",
        duration_ms=12.5,
    )
    d = result.to_dict()
    assert d["data"] == {"ip": "1.2.3.4", "hits": 5}
    assert d["summary"] == "Found 5 hits for 1.2.3.4."
    assert d["success"] is True
    assert d["source"] == "IPLookupSkill"
    assert d["duration_ms"] == 12.5


def test_skill_result_defaults():
    result = SkillResult(data={}, summary="empty", success=False)
    assert result.source == ""
    assert result.duration_ms == 0.0


def test_skill_result_data_must_be_serialisable():
    """SkillResult.data should hold only JSON-serialisable content.

    This test documents the contract rather than enforcing it at runtime.
    We verify that to_dict() round-trips correctly with a nested payload.
    """
    import json

    result = SkillResult(
        data={"nested": {"a": 1, "b": [True, None, "x"]}},
        summary="Nested payload.",
        success=True,
    )
    assert json.dumps(result.to_dict())  # must not raise


# ---------------------------------------------------------------------------
# Skill ABC — concrete helpers
# ---------------------------------------------------------------------------


class _OkSkill(Skill):
    """Minimal skill that always succeeds."""

    name = "ok_skill"
    description = "Always returns a successful result."
    input_type = InputType.IP_ADDRESS

    def _run(self, value: str, context: dict) -> SkillResult:
        return SkillResult(
            data={"echo": value},
            summary=f"Processed {value} without error.",
            success=True,
        )


class _ErrorSkill(Skill):
    """Minimal skill that always raises inside _run."""

    name = "error_skill"
    description = "Always raises a RuntimeError."
    input_type = InputType.USERNAME

    def _run(self, value: str, context: dict) -> SkillResult:
        raise RuntimeError("deliberate test failure")


# ---------------------------------------------------------------------------
# Skill ABC — instantiation
# ---------------------------------------------------------------------------


def test_skill_abc_cannot_be_instantiated():
    with pytest.raises(TypeError):
        Skill()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Skill.execute() — happy path
# ---------------------------------------------------------------------------


def test_execute_sets_source():
    result = _OkSkill().execute("192.168.1.1")
    assert result.source == "_OkSkill"


def test_execute_sets_duration_ms():
    result = _OkSkill().execute("192.168.1.1")
    assert result.duration_ms >= 0


def test_execute_without_context_does_not_raise():
    result = _OkSkill().execute("192.168.1.1")
    assert result.success is True


def test_execute_passes_value_to_run():
    result = _OkSkill().execute("10.0.0.1")
    assert result.data["echo"] == "10.0.0.1"


def test_execute_passes_context_to_run():
    class _ContextSkill(Skill):
        name = "ctx_skill"
        description = "Reads context."
        input_type = InputType.EVENT_ID

        def _run(self, value: str, context: dict) -> SkillResult:
            return SkillResult(
                data={"alert_id": context.get("alert_id")},
                summary="Read context.",
                success=True,
            )

    result = _ContextSkill().execute("evt-001", context={"alert_id": "abc123"})
    assert result.data["alert_id"] == "abc123"


# ---------------------------------------------------------------------------
# Skill.execute() — error handling
# ---------------------------------------------------------------------------


def test_execute_catches_exception_and_marks_failure():
    result = _ErrorSkill().execute("bad_input")
    assert result.success is False


def test_execute_on_exception_sets_source():
    result = _ErrorSkill().execute("bad_input")
    assert result.source == "_ErrorSkill"


def test_execute_on_exception_sets_duration():
    result = _ErrorSkill().execute("bad_input")
    assert result.duration_ms >= 0


def test_execute_on_exception_empty_data():
    result = _ErrorSkill().execute("bad_input")
    assert result.data == {}


def test_execute_on_exception_summary_contains_message():
    result = _ErrorSkill().execute("bad_input")
    assert "deliberate test failure" in result.summary
