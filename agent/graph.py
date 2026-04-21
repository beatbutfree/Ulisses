"""LangGraph state machine for the four-agent pipeline.

Graph shape (linear — all transitions are deterministic):

    START → analyst → evaluator → formatter → reflector → END

Each node is a pure function that reads from ``PipelineState`` and returns
a partial state update. LangGraph merges updates into the running state.

The reflector runs as the final node so it has access to the evaluator's
verdict when deciding which skill log entries to promote to ChromaDB. It
produces only side effects — the final report is already populated by the
formatter node, so ``run_pipeline()`` callers receive their report without
waiting on knowledge-base writes in the critical path.
"""

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from agent.analyst import AnalystAgent
from agent.evaluator import EvaluatorAgent
from agent.formatter import FormatterAgent
from agent.reflector import ReflectorAgent
from agent.schema import IncidentReport, SkillExecutionRecord


class PipelineState(TypedDict, total=False):
    """Shared state threaded through every node in the pipeline."""

    run_id: str
    alert: dict[str, Any]
    soar_prompt: str
    analyst_doc: str                         # populated by analyst node
    evaluator_doc: str                       # populated by evaluator node
    report: IncidentReport                   # populated by formatter node
    skill_log: list[SkillExecutionRecord]    # appended by generic skills
    reflection: dict[str, Any]               # populated by reflector node


def build_graph(
    analyst: AnalystAgent,
    evaluator: EvaluatorAgent,
    formatter: FormatterAgent,
    reflector: ReflectorAgent | None = None,
) -> Any:
    """Build and compile the four-agent pipeline as a LangGraph StateGraph.

    Args:
        analyst:   Wired ``AnalystAgent`` instance.
        evaluator: Wired ``EvaluatorAgent`` instance.
        formatter: Wired ``FormatterAgent`` instance.
        reflector: Optional ``ReflectorAgent``. Pass ``None`` to skip the
                   reflector node — useful in tests that do not exercise
                   ChromaDB.

    Returns:
        A compiled ``CompiledStateGraph`` ready to ``.invoke()``.
    """
    graph: StateGraph = StateGraph(PipelineState)

    def analyst_node(s: PipelineState) -> dict[str, Any]:
        skill_log: list[dict[str, Any]] = list(s.get("skill_log", []))
        doc = analyst.run(
            alert=s["alert"],
            soar_prompt=s.get("soar_prompt", ""),
            skill_log=skill_log,
        )
        return {"analyst_doc": doc, "skill_log": skill_log}

    graph.add_node("analyst", analyst_node)
    graph.add_node(
        "evaluator",
        lambda s: {"evaluator_doc": evaluator.run(s["analyst_doc"])},
    )
    graph.add_node(
        "formatter",
        lambda s: {"report": formatter.run(s["analyst_doc"], s["evaluator_doc"])},
    )

    graph.add_edge(START, "analyst")
    graph.add_edge("analyst", "evaluator")
    graph.add_edge("evaluator", "formatter")

    if reflector is not None:
        graph.add_node(
            "reflector",
            lambda s: {
                "reflection": reflector.run(
                    skill_log=list(s.get("skill_log", [])),
                    evaluator_doc=s["evaluator_doc"],
                )
            },
        )
        graph.add_edge("formatter", "reflector")
        graph.add_edge("reflector", END)
    else:
        graph.add_edge("formatter", END)

    return graph.compile()
