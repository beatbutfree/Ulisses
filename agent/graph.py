"""LangGraph state machine for the three-agent pipeline.

Graph shape (linear — all transitions are deterministic):

    START → analyst → evaluator → formatter → END

Each node is a pure function that reads from ``PipelineState`` and returns
a partial state update. LangGraph merges updates into the running state.
"""

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from agent.analyst import AnalystAgent
from agent.evaluator import EvaluatorAgent
from agent.formatter import FormatterAgent
from agent.schema import IncidentReport


class PipelineState(TypedDict):
    """Shared state threaded through every node in the pipeline."""

    alert: dict[str, Any]
    soar_prompt: str
    analyst_doc: str        # populated by analyst node
    evaluator_doc: str      # populated by evaluator node
    report: IncidentReport  # populated by formatter node


def build_graph(
    analyst: AnalystAgent,
    evaluator: EvaluatorAgent,
    formatter: FormatterAgent,
) -> Any:
    """Build and compile the three-agent pipeline as a LangGraph StateGraph.

    Args:
        analyst:   Wired ``AnalystAgent`` instance.
        evaluator: Wired ``EvaluatorAgent`` instance.
        formatter: Wired ``FormatterAgent`` instance.

    Returns:
        A compiled ``CompiledStateGraph`` ready to ``.invoke()``.
    """
    graph: StateGraph = StateGraph(PipelineState)

    graph.add_node(
        "analyst",
        lambda s: {"analyst_doc": analyst.run(s["alert"], s.get("soar_prompt", ""))},
    )
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
    graph.add_edge("formatter", END)

    return graph.compile()
