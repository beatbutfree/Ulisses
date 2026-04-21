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

from skills.analysis import build_analysis_skills
from skills.foundational.chroma_query import ChromaQuerySkill
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_crafter import QueryCrafterSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import InMemoryTemplateStore
from skills.registry import SkillRegistry
from store.chroma_client import ChromaQueryStore
from wazuh.client import WazuhIndexerClient

from agent.analyst import AnalystAgent
from agent.evaluator import EvaluatorAgent
from agent.formatter import FormatterAgent
from agent.graph import PipelineState, build_graph
from agent.logging_config import get_logger, new_run_id
from agent.reflector import ReflectorAgent
from agent.schema import IncidentReport


def build_registry(
    anthropic_client: anthropic.Anthropic,
    chroma_store: ChromaQueryStore,
) -> SkillRegistry:
    """Wire and register every skill the analyst can call.

    Analysis skills (one per decoder.name) are picked up by auto-discovery.
    The two generic foundational skills — ``chroma_query`` and
    ``query_crafter`` — are wired manually because they require explicit
    dependencies (Anthropic client, ChromaDB store) that auto-discovery
    cannot infer.

    Args:
        anthropic_client: Shared Anthropic SDK client.
        chroma_store:     Persistent ``ChromaQueryStore`` instance.

    Returns:
        A ``SkillRegistry`` ready to be handed to the analyst.
    """
    wazuh_client = WazuhIndexerClient.from_env()
    template_store = InMemoryTemplateStore()
    builder = QueryBuilderSkill(store=template_store)
    executor = QueryExecutorSkill(client=wazuh_client)

    registry = SkillRegistry()
    for skill in build_analysis_skills(builder=builder, executor=executor):
        registry.register(skill)

    registry.register(
        ChromaQuerySkill(
            client=anthropic_client,
            store=chroma_store,
            executor=executor,
        )
    )
    registry.register(
        QueryCrafterSkill(
            client=anthropic_client,
            executor=executor,
        )
    )
    return registry


def run_pipeline(
    alert: dict[str, Any],
    soar_prompt: str = "",
    registry: SkillRegistry | None = None,
    chroma_store: ChromaQueryStore | None = None,
    anthropic_client: anthropic.Anthropic | None = None,
) -> IncidentReport:
    """Run the full Analyst → Evaluator → Formatter → Reflector pipeline.

    Args:
        alert:            Raw Wazuh alert dict.
        soar_prompt:      Optional SOAR context injected into the analyst.
        registry:         Pre-built ``SkillRegistry``; pass a mock for tests
                          to avoid a live Wazuh connection.
        chroma_store:     Pre-built ``ChromaQueryStore``; pass an ephemeral
                          store in tests. A default on-disk store is created
                          when ``None``.
        anthropic_client: Pre-built Anthropic client; created from env when
                          ``None``.

    Returns:
        A fully-populated ``IncidentReport`` dict.
    """
    load_dotenv()

    run_id = new_run_id()
    logger = get_logger(run_id=run_id)
    logger.info("pipeline_start", extra={"event": "pipeline_start"})

    client = anthropic_client if anthropic_client is not None else anthropic.Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"]
    )
    store = chroma_store if chroma_store is not None else ChromaQueryStore()
    reg = registry if registry is not None else build_registry(
        anthropic_client=client, chroma_store=store
    )

    analyst = AnalystAgent(client=client, registry=reg)
    evaluator = EvaluatorAgent(client=client)
    formatter = FormatterAgent(client=client)
    reflector = ReflectorAgent(client=client, store=store)

    pipeline = build_graph(
        analyst=analyst,
        evaluator=evaluator,
        formatter=formatter,
        reflector=reflector,
    )

    initial_state: PipelineState = {
        "run_id": run_id,
        "alert": alert,
        "soar_prompt": soar_prompt,
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
        "skill_log": [],
        "reflection": {},
    }

    final_state: PipelineState = pipeline.invoke(initial_state)

    logger.info(
        "pipeline_done",
        extra={
            "event": "pipeline_done",
            "verdict": final_state["report"].get("verdict", "unknown"),
            "confidence": final_state["report"].get("confidence", 0.0),
            "skill_log_size": len(final_state.get("skill_log", [])),
            "reflection": final_state.get("reflection", {}),
        },
    )
    return final_state["report"]
