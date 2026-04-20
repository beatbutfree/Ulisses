"""Top-level entry point: wires dependencies and runs the full pipeline.

Usage::

    from agent.runner import run_pipeline

    report = run_pipeline(alert=alert_dict, soar_prompt="Triggered by SIEM rule X.")
    print(report["verdict"], report["confidence"])
"""

import os
from typing import Any

import anthropic
from dotenv import load_dotenv

from skills.analysis import (
    WindowsIPLookupSkill,
    WindowsRuleLookupSkill,
    WindowsUsernameLookupSkill,
)
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore
from skills.registry import SkillRegistry
from wazuh.client import WazuhIndexerClient

from agent.analyst import AnalystAgent
from agent.evaluator import EvaluatorAgent
from agent.formatter import FormatterAgent
from agent.graph import PipelineState, build_graph
from agent.schema import IncidentReport


def build_registry() -> SkillRegistry:
    """Wire and register all analysis skills against a live Wazuh Indexer.

    Reads connection parameters from environment / ``.env``.

    Returns:
        A ``SkillRegistry`` populated with all currently implemented skills.
    """
    wazuh_client = WazuhIndexerClient.from_env()
    store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store=store)
    executor = QueryExecutorSkill(client=wazuh_client)

    registry = SkillRegistry()
    registry.register(WindowsIPLookupSkill(builder=builder, executor=executor))
    registry.register(WindowsUsernameLookupSkill(builder=builder, executor=executor))
    registry.register(WindowsRuleLookupSkill(builder=builder, executor=executor))
    return registry


def run_pipeline(
    alert: dict[str, Any],
    soar_prompt: str = "",
    registry: SkillRegistry | None = None,
) -> IncidentReport:
    """Run the full Analyst → Evaluator → Formatter pipeline.

    Args:
        alert:       Raw Wazuh alert dict.
        soar_prompt: Optional SOAR context injected into the analyst system prompt.
        registry:    Pre-built ``SkillRegistry``; pass a mock for tests to avoid
                     a live Wazuh connection. If ``None``, built from env vars.

    Returns:
        A fully-populated ``IncidentReport`` dict.
    """
    load_dotenv()

    anthropic_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    reg = registry if registry is not None else build_registry()

    analyst = AnalystAgent(client=anthropic_client, registry=reg)
    evaluator = EvaluatorAgent(client=anthropic_client)
    formatter = FormatterAgent(client=anthropic_client)

    pipeline = build_graph(analyst=analyst, evaluator=evaluator, formatter=formatter)

    initial_state: PipelineState = {
        "alert": alert,
        "soar_prompt": soar_prompt,
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
    }

    final_state: PipelineState = pipeline.invoke(initial_state)
    return final_state["report"]
