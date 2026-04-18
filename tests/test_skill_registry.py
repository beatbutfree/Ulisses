"""Tests for skills/registry.py — SkillRegistry singleton (instance-based)."""

import pytest
from skills.base import InputType, Skill, SkillResult
from skills.registry import SkillRegistry


# ---------------------------------------------------------------------------
# Minimal concrete skills for testing
# ---------------------------------------------------------------------------


class _FakeIPSkill(Skill):
    name = "fake_ip"
    description = "Fake IP skill for tests."
    input_type = InputType.IP_ADDRESS

    def _run(self, value: str, context: dict) -> SkillResult:
        return SkillResult(data={}, summary="stub", success=True)


class _FakeUserSkill(Skill):
    name = "fake_user"
    description = "Fake user skill for tests."
    input_type = InputType.USERNAME

    def _run(self, value: str, context: dict) -> SkillResult:
        return SkillResult(data={}, summary="stub", success=True)


class _FakeRuleSkill(Skill):
    name = "fake_rule"
    description = "Fake rule skill for tests."
    input_type = InputType.RULE_ID

    def _run(self, value: str, context: dict) -> SkillResult:
        return SkillResult(data={}, summary="stub", success=True)


# ---------------------------------------------------------------------------
# Fixture: isolate each test with a fresh singleton
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_registry():
    """Reset the SkillRegistry singleton before and after every test."""
    SkillRegistry._instance = None
    yield
    SkillRegistry._instance = None


# ---------------------------------------------------------------------------
# Singleton behaviour
# ---------------------------------------------------------------------------


def test_singleton_same_instance():
    r1 = SkillRegistry()
    r2 = SkillRegistry()
    assert r1 is r2


def test_singleton_shared_state():
    skill = _FakeIPSkill()
    r1 = SkillRegistry()
    r1.register(skill)
    r2 = SkillRegistry()
    assert r2.get("fake_ip") is skill


# ---------------------------------------------------------------------------
# register()
# ---------------------------------------------------------------------------


def test_register_and_get():
    skill = _FakeIPSkill()
    r = SkillRegistry()
    r.register(skill)
    assert r.get("fake_ip") is skill


def test_register_multiple_skills():
    ip = _FakeIPSkill()
    user = _FakeUserSkill()
    r = SkillRegistry()
    r.register(ip)
    r.register(user)
    assert r.get("fake_ip") is ip
    assert r.get("fake_user") is user


def test_register_overwrites_same_name():
    """Re-registering under the same name replaces the previous entry."""

    class _Alt(Skill):
        name = "fake_ip"
        description = "Alternative IP skill."
        input_type = InputType.IP_ADDRESS

        def _run(self, value: str, context: dict) -> SkillResult:
            return SkillResult(data={}, summary="alt", success=True)

    original = _FakeIPSkill()
    alt = _Alt()
    r = SkillRegistry()
    r.register(original)
    r.register(alt)
    assert r.get("fake_ip") is alt


def test_register_without_name_raises():
    class _NoName(Skill):
        description = "Missing name."
        input_type = InputType.EVENT_ID

        def _run(self, value: str, context: dict) -> SkillResult:
            return SkillResult(data={}, summary="stub", success=True)

    r = SkillRegistry()
    with pytest.raises(ValueError, match="name"):
        r.register(_NoName())


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


def test_get_unknown_returns_none():
    r = SkillRegistry()
    assert r.get("nonexistent") is None


# ---------------------------------------------------------------------------
# get_by_input_type()
# ---------------------------------------------------------------------------


def test_get_by_input_type_returns_matching_skills():
    ip = _FakeIPSkill()
    user = _FakeUserSkill()
    rule = _FakeRuleSkill()
    r = SkillRegistry()
    r.register(ip)
    r.register(user)
    r.register(rule)

    ip_skills = r.get_by_input_type(InputType.IP_ADDRESS)
    assert ip in ip_skills
    assert user not in ip_skills
    assert rule not in ip_skills


def test_get_by_input_type_empty_when_none_registered():
    r = SkillRegistry()
    assert r.get_by_input_type(InputType.EVENT_ID) == []


def test_get_by_input_type_multiple_matches():
    class _AnotherIPSkill(Skill):
        name = "another_ip"
        description = "Second IP skill."
        input_type = InputType.IP_ADDRESS

        def _run(self, value: str, context: dict) -> SkillResult:
            return SkillResult(data={}, summary="stub", success=True)

    ip1 = _FakeIPSkill()
    ip2 = _AnotherIPSkill()
    r = SkillRegistry()
    r.register(ip1)
    r.register(ip2)

    ip_skills = r.get_by_input_type(InputType.IP_ADDRESS)
    assert len(ip_skills) == 2
    assert ip1 in ip_skills
    assert ip2 in ip_skills


# ---------------------------------------------------------------------------
# all()
# ---------------------------------------------------------------------------


def test_all_returns_all_registered_skills():
    ip = _FakeIPSkill()
    user = _FakeUserSkill()
    r = SkillRegistry()
    r.register(ip)
    r.register(user)
    assert set(r.all()) == {ip, user}


def test_all_empty_when_nothing_registered():
    r = SkillRegistry()
    assert r.all() == []


# ---------------------------------------------------------------------------
# __repr__
# ---------------------------------------------------------------------------


def test_repr_contains_skill_names():
    r = SkillRegistry()
    r.register(_FakeIPSkill())
    assert "fake_ip" in repr(r)
