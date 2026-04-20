"""Tests for agent.formatter — FormatterAgent."""

from unittest.mock import MagicMock

import pytest

from agent.formatter import FormatterAgent
from agent.schema import IncidentReport

_ANALYST_DOC = "<finding><observable>10.0.0.1</observable><skill_used>windows_ip_lookup</skill_used><severity_signal>high</severity_signal><notes>Multiple failed logons.</notes></finding>"
_EVALUATOR_DOC = "<assessment><verdict>true_positive</verdict><confidence>0.9</confidence><technical_breakdown>Brute-force pattern.</technical_breakdown><malicious_interpretation>Attacker.</malicious_interpretation><benign_interpretation>Misconfigured app.</benign_interpretation><conclusion>Volume too high for benign.</conclusion></assessment>"


def _make_tool_block(report_payload: dict) -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.name = "produce_report"
    block.input = report_payload
    return block


def _make_client(content_blocks: list) -> MagicMock:
    response = MagicMock()
    response.content = content_blocks
    response.stop_reason = "tool_use"
    client = MagicMock()
    client.messages.create.return_value = response
    return client


def _sample_payload() -> dict:
    return {
        "report_id": "abc-123",
        "generated_at": "2026-01-01T00:00:00Z",
        "verdict": "true_positive",
        "confidence": 0.9,
        "severity": "high",
        "title": "Brute-force logon attempt",
        "executive_summary": "Repeated failed logons detected.",
        "technical_breakdown": "High volume of Event ID 4625.",
        "observables": [{"type": "ip_address", "value": "10.0.0.1", "disposition": "malicious"}],
        "findings": [{"skill": "windows_ip_lookup", "observable": "10.0.0.1", "severity_signal": "high", "summary": "500 failed logons."}],
        "recommended_actions": ["Block IP", "Reset user passwords"],
        "open_questions": [],
        "raw_analyst_doc": "",    # will be overwritten by FormatterAgent
        "raw_evaluator_doc": "",  # will be overwritten by FormatterAgent
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_formatter_returns_report_on_tool_call():
    payload = _sample_payload()
    client = _make_client([_make_tool_block(payload)])
    formatter = FormatterAgent(client=client)

    report = formatter.run(_ANALYST_DOC, _EVALUATOR_DOC)

    assert report["verdict"] == "true_positive"
    assert report["confidence"] == 0.9
    assert report["severity"] == "high"


def test_formatter_overwrites_audit_fields_verbatim():
    payload = _sample_payload()
    payload["raw_analyst_doc"] = "will be overwritten"
    payload["raw_evaluator_doc"] = "will be overwritten"
    client = _make_client([_make_tool_block(payload)])
    formatter = FormatterAgent(client=client)

    report = formatter.run(_ANALYST_DOC, _EVALUATOR_DOC)

    assert report["raw_analyst_doc"] == _ANALYST_DOC
    assert report["raw_evaluator_doc"] == _EVALUATOR_DOC


def test_formatter_raises_if_no_tool_call():
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = "I forgot to call the tool."
    response = MagicMock()
    response.content = [text_block]
    response.stop_reason = "end_turn"
    client = MagicMock()
    client.messages.create.return_value = response

    formatter = FormatterAgent(client=client)
    with pytest.raises(RuntimeError, match="produce_report"):
        formatter.run(_ANALYST_DOC, _EVALUATOR_DOC)


def test_formatter_skips_non_produce_report_tool_blocks():
    other_block = MagicMock()
    other_block.type = "tool_use"
    other_block.name = "some_other_tool"

    payload = _sample_payload()
    correct_block = _make_tool_block(payload)

    client = _make_client([other_block, correct_block])
    formatter = FormatterAgent(client=client)

    report = formatter.run(_ANALYST_DOC, _EVALUATOR_DOC)
    assert report["verdict"] == "true_positive"


def test_formatter_passes_both_docs_to_api():
    payload = _sample_payload()
    client = _make_client([_make_tool_block(payload)])
    formatter = FormatterAgent(client=client)

    formatter.run(_ANALYST_DOC, _EVALUATOR_DOC)

    call_kwargs = client.messages.create.call_args
    user_content = call_kwargs.kwargs["messages"][0]["content"]
    assert _ANALYST_DOC in user_content
    assert _EVALUATOR_DOC in user_content
