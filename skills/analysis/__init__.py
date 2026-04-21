"""Analysis skills — one module per Wazuh decoder/log source.

Drop a new ``<source>_<observable>_lookup.py`` file into this directory and
it will be discovered automatically by ``discover_skill_classes()``.

Convention: each module must contain exactly one concrete ``Skill`` subclass
with a constructor that accepts ``builder`` and ``executor`` keyword arguments.
"""

import importlib
import inspect
import pkgutil
from typing import Any, TYPE_CHECKING

from skills.base import InputType, Skill

if TYPE_CHECKING:
    from skills.foundational.query_builder import QueryBuilderSkill
    from skills.foundational.query_executor import QueryExecutorSkill

_FOUNDATIONAL_TYPES = {InputType.TEMPLATE_NAME, InputType.QUERY_DSL}


def discover_skill_classes() -> list[type[Skill]]:
    """Return all concrete Skill subclasses found in this package.

    Imports every non-private submodule (files not starting with ``_``) and
    collects concrete ``Skill`` subclasses whose ``input_type`` is not a
    foundational type.

    Returns:
        List of skill classes, one per discovered module.
    """
    package = importlib.import_module(__name__)
    package_path = package.__path__  # type: ignore[attr-defined]

    classes: list[type[Skill]] = []
    for module_info in pkgutil.iter_modules(package_path):
        if module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                obj is not Skill
                and issubclass(obj, Skill)
                and obj.__module__ == module.__name__
                and hasattr(obj, "input_type")
                and obj.input_type not in _FOUNDATIONAL_TYPES
            ):
                classes.append(obj)
    return classes


def build_analysis_skills(
    builder: "QueryBuilderSkill",
    executor: "QueryExecutorSkill",
) -> list[Any]:
    """Instantiate all discovered analysis skill classes.

    Args:
        builder:  Configured ``QueryBuilderSkill`` instance.
        executor: Configured ``QueryExecutorSkill`` instance.

    Returns:
        List of ready-to-register skill instances.
    """
    return [cls(builder=builder, executor=executor) for cls in discover_skill_classes()]
