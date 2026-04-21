"""Tests for graph wiring of the ReflectorAgent node."""

from unittest.mock import MagicMock

from agent.graph import build_graph, PipelineState
from agent.schema import IncidentReport


_ALERT = {"decoder": {"name": "windows_eventchannel"}, "rule": {"id": "60106"}}
_ANALYST_DOC = "<finding><skill_used>s</skill_used></finding>"
_EVALUATOR_DOC = "<assessment><verdict>true_positive</verdict><confidence>0.9</confidence></assessment>"

_REPORT: IncidentReport = {
    "report_id": "r1",
    "generated_at": "2026-01-01T00:00:00Z",
    "verdict": "true_positive",
    "confidence": 0.9,
    "severity": "high",
    "title": "T",
    "executive_summary": "s",
    "technical_breakdown": "t",
    "observables": [],
    "findings": [],
    "recommended_actions": [],
    "open_questions": [],
    "raw_analyst_doc": _ANALYST_DOC,
    "raw_evaluator_doc": _EVALUATOR_DOC,
}


def _make_agents():
    analyst = MagicMock()
    # Analyst populates skill_log via the kwarg list — simulate by mutating.
    def analyst_run(alert, soar_prompt="", skill_log=None):
        if skill_log is not None:
            skill_log.append({"kind": "chroma_retrieved", "query_id": "qX", "success": True, "result_count": 3})
        return _ANALYST_DOC
    analyst.run.side_effect = analyst_run

    evaluator = MagicMock()
    evaluator.run.return_value = _EVALUATOR_DOC

    formatter = MagicMock()
    formatter.run.return_value = _REPORT

    reflector = MagicMock()
    reflector.run.return_value = {"counters_touched": 1, "promoted_ids": []}

    return analyst, evaluator, formatter, reflector


def test_graph_includes_reflector_when_provided() -> None:
    analyst, evaluator, formatter, reflector = _make_agents()
    pipeline = build_graph(analyst=analyst, evaluator=evaluator, formatter=formatter, reflector=reflector)

    initial: PipelineState = {
        "alert": _ALERT,
        "soar_prompt": "",
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
        "skill_log": [],
        "reflection": {},
    }
    final = pipeline.invoke(initial)

    reflector.run.assert_called_once()
    # The reflector received the log entry the analyst mutated in.
    call_kwargs = reflector.run.call_args.kwargs
    assert any(r["query_id"] == "qX" for r in call_kwargs["skill_log"])
    assert call_kwargs["evaluator_doc"] == _EVALUATOR_DOC
    assert final["reflection"]["counters_touched"] == 1


def test_graph_omits_reflector_when_none() -> None:
    analyst, evaluator, formatter, _ = _make_agents()
    pipeline = build_graph(analyst=analyst, evaluator=evaluator, formatter=formatter, reflector=None)

    initial: PipelineState = {
        "alert": _ALERT,
        "soar_prompt": "",
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
        "skill_log": [],
        "reflection": {},
    }
    final = pipeline.invoke(initial)

    assert final["report"] == _REPORT
    # reflection state should remain empty since no reflector node ran
    assert final.get("reflection", {}) == {}
