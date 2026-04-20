"""FormatterAgent — assembles the final structured incident report.

Receives the analyst findings document and evaluator assessment document.
Calls the ``produce_report`` tool exactly once. Schema is enforced by the
tool definition, not by prompting — this guarantees identical structure
across every run regardless of LLM output variation.
"""

import os
from typing import Any

import anthropic

from agent.schema import PRODUCE_REPORT_TOOL, IncidentReport

_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

_SYSTEM = """\
You are a security report formatter. You receive two documents:
1. An analyst findings document (XML blocks).
2. An evaluator assessment document (XML blocks).

Reconcile them and call produce_report exactly once with all fields populated.
Be faithful to the source documents — do not invent findings or alter the verdict.
Populate raw_analyst_doc and raw_evaluator_doc verbatim from your inputs.
"""


class FormatterAgent:
    """Converts analyst + evaluator documents into a fixed-schema IncidentReport.

    Uses ``tool_choice={"type": "any"}`` so the model is forced to call
    ``produce_report`` — structure is guaranteed by the tool contract, not prose.
    """

    def __init__(self, client: anthropic.Anthropic) -> None:
        """
        Args:
            client: Configured Anthropic SDK client.
        """
        self._client = client

    def run(self, analyst_doc: str, evaluator_doc: str) -> IncidentReport:
        """Produce a structured incident report from the two upstream documents.

        Args:
            analyst_doc:   Full XML findings document from the analyst.
            evaluator_doc: Full XML assessment document from the evaluator.

        Returns:
            A fully-populated ``IncidentReport`` dict.

        Raises:
            RuntimeError: If the model does not call ``produce_report``.
        """
        user_message = (
            f"<analyst_findings>\n{analyst_doc}\n</analyst_findings>\n\n"
            f"<evaluator_assessment>\n{evaluator_doc}\n</evaluator_assessment>\n\n"
            "Call produce_report now with all fields populated."
        )

        response = self._client.messages.create(
            model=_MODEL,
            max_tokens=4096,
            system=_SYSTEM,
            tools=[PRODUCE_REPORT_TOOL],
            tool_choice={"type": "any"},
            messages=[{"role": "user", "content": user_message}],
        )

        for block in response.content:
            if block.type == "tool_use" and block.name == "produce_report":
                report: IncidentReport = dict(block.input)  # type: ignore[assignment]
                # Overwrite audit fields verbatim — model must not truncate them
                report["raw_analyst_doc"] = analyst_doc
                report["raw_evaluator_doc"] = evaluator_doc
                return report

        raise RuntimeError(
            f"FormatterAgent: model did not call produce_report. "
            f"stop_reason={response.stop_reason!r}"
        )
