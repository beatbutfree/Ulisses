"""Tests for skills.analysis auto-discovery."""

from unittest.mock import MagicMock

from skills.analysis import build_analysis_skills, discover_skill_classes
from skills.base import InputType, Skill

_KNOWN_SKILL_NAMES = {
    "windows_ip_lookup",
    "windows_username_lookup",
    "windows_rule_lookup",
}


def test_discover_finds_all_known_skills():
    classes = discover_skill_classes()
    names = {cls.name for cls in classes}
    assert _KNOWN_SKILL_NAMES.issubset(names), f"Missing skills: {_KNOWN_SKILL_NAMES - names}"


def test_discover_returns_concrete_skill_subclasses():
    classes = discover_skill_classes()
    assert len(classes) >= 3
    for cls in classes:
        assert issubclass(cls, Skill)
        assert cls is not Skill


def test_discover_excludes_foundational_types():
    foundational = {InputType.TEMPLATE_NAME, InputType.QUERY_DSL}
    for cls in discover_skill_classes():
        assert cls.input_type not in foundational, (
            f"{cls.name} has foundational input_type {cls.input_type}"
        )


def test_build_analysis_skills_instantiates_all():
    builder = MagicMock()
    executor = MagicMock()
    skills = build_analysis_skills(builder=builder, executor=executor)
    names = {s.name for s in skills}
    assert _KNOWN_SKILL_NAMES.issubset(names)


def test_build_analysis_skills_returns_skill_instances():
    builder = MagicMock()
    executor = MagicMock()
    skills = build_analysis_skills(builder=builder, executor=executor)
    for skill in skills:
        assert isinstance(skill, Skill)
