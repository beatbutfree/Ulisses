"""Tests for agent.evaluator — EvaluatorAgent."""

from unittest.mock import MagicMock

import pytest

from agent.evaluator import EvaluatorAgent

_ANALYST_DOC = "<finding><observable>10.0.0.1</observable><skill_used>windows_ip_lookup</skill_used><severity_signal>high</severity_signal><notes>500 failed logons in 10 minutes.</notes></finding>"

_ASSESSMENT_XML = (
    "<assessment>"
    "<verdict>true_positive</verdict>"
    "<confidence>0.87</confidence>"
    "<technical_breakdown>Brute-force pattern confirmed.</technical_breakdown>"
    "<malicious_interpretation>Attacker probing credentials.</malicious_interpretation>"
    "<benign_interpretation>Misconfigured service account.</benign_interpretation>"
    "<conclusion>Volume rules out benign explanation.</conclusion>"
    "</assessment>"
)


def _make_client(text: str) -> MagicMock:
    text_block = MagicMock()
    text_block.text = text
    # hasattr check in evaluator uses `hasattr(block, "text")` — ensure it returns True
    del text_block.nonexistent  # MagicMock returns True for hasattr by default; fine
    response = MagicMock()
    response.content = [text_block]
    client = MagicMock()
    client.messages.create.return_value = response
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_evaluator_returns_assessment_text():
    client = _make_client(_ASSESSMENT_XML)
    evaluator = EvaluatorAgent(client=client)

    result = evaluator.run(_ANALYST_DOC)

    assert "<assessment>" in result
    assert "<verdict>true_positive</verdict>" in result


def test_evaluator_passes_analyst_doc_to_api():
    client = _make_client(_ASSESSMENT_XML)
    evaluator = EvaluatorAgent(client=client)

    evaluator.run(_ANALYST_DOC)

    call_kwargs = client.messages.create.call_args
    user_content = call_kwargs.kwargs["messages"][0]["content"]
    assert _ANALYST_DOC in user_content


def test_evaluator_raises_on_empty_response():
    text_block = MagicMock()
    text_block.text = "   "
    response = MagicMock()
    response.content = [text_block]
    client = MagicMock()
    client.messages.create.return_value = response

    evaluator = EvaluatorAgent(client=client)
    with pytest.raises(RuntimeError, match="empty response"):
        evaluator.run(_ANALYST_DOC)


def test_evaluator_concatenates_multiple_text_blocks():
    block_a = MagicMock()
    block_a.text = "<assessment><verdict>false_positive</verdict>"
    block_b = MagicMock()
    block_b.text = "<confidence>0.6</confidence></assessment>"
    response = MagicMock()
    response.content = [block_a, block_b]
    client = MagicMock()
    client.messages.create.return_value = response

    evaluator = EvaluatorAgent(client=client)
    result = evaluator.run(_ANALYST_DOC)

    assert result == "<assessment><verdict>false_positive</verdict><confidence>0.6</confidence></assessment>"
