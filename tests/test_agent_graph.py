"""Tests for agent.graph — build_graph() and PipelineState wiring."""

from unittest.mock import MagicMock

from agent.graph import build_graph, PipelineState
from agent.schema import IncidentReport

_ALERT = {"decoder": {"name": "windows_eventchannel"}, "rule": {"id": "60106"}}
_ANALYST_DOC = "<finding><observable>x</observable><skill_used>s</skill_used><severity_signal>low</severity_signal><notes>n</notes></finding>"
_EVALUATOR_DOC = "<assessment><verdict>false_positive</verdict><confidence>0.4</confidence><technical_breakdown>t</technical_breakdown><malicious_interpretation>m</malicious_interpretation><benign_interpretation>b</benign_interpretation><conclusion>c</conclusion></assessment>"

_SAMPLE_REPORT: IncidentReport = {
    "report_id": "r1",
    "generated_at": "2026-01-01T00:00:00Z",
    "verdict": "false_positive",
    "confidence": 0.4,
    "severity": "low",
    "title": "Test",
    "executive_summary": "All good.",
    "technical_breakdown": "Nothing found.",
    "observables": [],
    "findings": [],
    "recommended_actions": [],
    "open_questions": [],
    "raw_analyst_doc": _ANALYST_DOC,
    "raw_evaluator_doc": _EVALUATOR_DOC,
}


def _make_pipeline():
    analyst = MagicMock()
    analyst.run.return_value = _ANALYST_DOC

    evaluator = MagicMock()
    evaluator.run.return_value = _EVALUATOR_DOC

    formatter = MagicMock()
    formatter.run.return_value = _SAMPLE_REPORT

    pipeline = build_graph(analyst=analyst, evaluator=evaluator, formatter=formatter)
    return pipeline, analyst, evaluator, formatter


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_graph_compiles():
    pipeline, _, _, _ = _make_pipeline()
    assert pipeline is not None


def test_graph_produces_report():
    pipeline, _, _, _ = _make_pipeline()
    initial: PipelineState = {
        "alert": _ALERT,
        "soar_prompt": "",
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
    }
    final = pipeline.invoke(initial)
    assert final["report"]["verdict"] == "false_positive"


def test_graph_calls_agents_in_order():
    pipeline, analyst, evaluator, formatter = _make_pipeline()
    initial: PipelineState = {
        "alert": _ALERT,
        "soar_prompt": "ticket INC-1",
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
    }
    pipeline.invoke(initial)

    analyst.run.assert_called_once_with(
        alert=_ALERT, soar_prompt="ticket INC-1", skill_log=[]
    )
    evaluator.run.assert_called_once_with(_ANALYST_DOC)
    formatter.run.assert_called_once_with(_ANALYST_DOC, _EVALUATOR_DOC)


def test_graph_threads_state_correctly():
    pipeline, analyst, evaluator, formatter = _make_pipeline()
    initial: PipelineState = {
        "alert": _ALERT,
        "soar_prompt": "",
        "analyst_doc": "",
        "evaluator_doc": "",
        "report": {},  # type: ignore[typeddict-item]
    }
    final = pipeline.invoke(initial)

    assert final["analyst_doc"] == _ANALYST_DOC
    assert final["evaluator_doc"] == _EVALUATOR_DOC
    assert final["report"] == _SAMPLE_REPORT
