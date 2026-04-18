"""SkillRegistry — singleton that maps skill names to Skill classes.

Usage::

    from skills.registry import registry
    from skills.analysis.ip_lookup import IPLookupSkill

    registry.register(IPLookupSkill)

    skill_cls = registry.get("ip_lookup")
    result = skill_cls().execute("192.168.1.1")
"""

from skills.base import InputType, Skill


class SkillRegistry:
    """Singleton registry that tracks all available Skill classes.

    Skills are registered explicitly via ``register()``.  The singleton
    instance is exposed at module level as ``registry`` for convenience.
    """

    _instance: "SkillRegistry | None" = None

    def __new__(cls) -> "SkillRegistry":
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._skills: dict[str, type[Skill]] = {}
            cls._instance = instance
        return cls._instance

    def register(self, skill_class: type[Skill]) -> None:
        """Register a Skill class under its declared ``name``.

        Args:
            skill_class: A concrete subclass of ``Skill`` with a ``name``
                         class attribute set.

        Raises:
            ValueError: If ``skill_class`` has no ``name`` attribute.
        """
        if not hasattr(skill_class, "name"):
            raise ValueError(
                f"{skill_class.__name__} must declare a `name` class attribute "
                "before being registered."
            )
        self._skills[skill_class.name] = skill_class

    def get(self, name: str) -> type[Skill] | None:
        """Return the Skill class registered under ``name``, or None."""
        return self._skills.get(name)

    def get_by_input_type(self, input_type: InputType) -> list[type[Skill]]:
        """Return all registered Skill classes that handle ``input_type``."""
        return [
            cls for cls in self._skills.values()
            if getattr(cls, "input_type", None) == input_type
        ]

    def all(self) -> list[type[Skill]]:
        """Return all registered Skill classes."""
        return list(self._skills.values())

    def __repr__(self) -> str:
        return f"SkillRegistry(skills={list(self._skills.keys())})"


registry = SkillRegistry()
