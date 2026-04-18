"""Foundational skills — infrastructure layer between the agent and the indexer.

Public surface::

    from skills.foundational import (
        QueryTemplate,
        InMemoryTemplateStore,
        QueryBuilderSkill,
        QueryExecutorSkill,
    )
"""

from skills.foundational.template_store import InMemoryTemplateStore, QueryTemplate
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill

__all__ = [
    "QueryTemplate",
    "InMemoryTemplateStore",
    "QueryBuilderSkill",
    "QueryExecutorSkill",
]
