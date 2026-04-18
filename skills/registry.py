"""SkillRegistry — singleton that maps skill names to Skill instances.

Skills are registered as pre-built instances (not classes) so that
constructor-injected dependencies are wired up once at startup and reused
for every invocation.

Usage::

    from skills.registry import registry
    from skills.analysis.windows_ip_lookup import WindowsIPLookupSkill

    skill = WindowsIPLookupSkill(builder=builder, executor=executor)
    registry.register(skill)

    result = registry.get("windows_ip_lookup").execute("10.0.0.1")
"""

from skills.base import InputType, Skill


class SkillRegistry:
    """Singleton registry that stores ready-to-use Skill instances.

    Skills are registered explicitly via ``register()``.  The singleton
    instance is exposed at module level as ``registry`` for convenience.
    """

    _instance: "SkillRegistry | None" = None
    _skills: dict[str, Skill]  # typed at class level; initialised in __new__

    def __new__(cls) -> "SkillRegistry":
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._skills = {}
            cls._instance = instance
        return cls._instance

    def register(self, skill: Skill) -> None:
        """Register a Skill instance under its declared ``name``.

        Re-registering under the same name replaces the previous entry.

        Args:
            skill: A concrete ``Skill`` instance with a ``name`` attribute.

        Raises:
            ValueError: If ``skill`` has no ``name`` attribute.
        """
        if not hasattr(skill, "name"):
            raise ValueError(
                f"{skill.__class__.__name__} must declare a `name` class "
                "attribute before being registered."
            )
        self._skills[skill.name] = skill

    def get(self, name: str) -> Skill | None:
        """Return the Skill instance registered under ``name``, or None."""
        return self._skills.get(name)

    def get_by_input_type(self, input_type: InputType) -> list[Skill]:
        """Return all registered Skill instances that handle ``input_type``."""
        return [
            skill for skill in self._skills.values()
            if getattr(skill, "input_type", None) == input_type
        ]

    def all(self) -> list[Skill]:
        """Return all registered Skill instances."""
        return list(self._skills.values())

    def __repr__(self) -> str:
        return f"SkillRegistry(skills={list(self._skills.keys())})"


registry = SkillRegistry()
