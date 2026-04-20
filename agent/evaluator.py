"""EvaluatorAgent — makes the TP/FP call from the analyst findings document.

No skill access. Single LLM call. Explains both interpretations before
committing to a verdict. Output is an XML assessment block that the
formatter consumes downstream.
"""

import os

import anthropic

_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

_SYSTEM = """\
You are a senior SOC analyst performing a second-opinion review.

You receive a findings document produced by a junior analyst who investigated
a Wazuh security alert. Your job:

1. Read every finding carefully.
2. Articulate the most plausible malicious interpretation.
3. Articulate the most plausible benign interpretation.
4. Make a definitive TP/FP call with a confidence score (0.0–1.0).
5. Explain clearly why one interpretation wins over the other.

Output exactly one <assessment> block — no text outside it:

<assessment>
  <verdict>true_positive | false_positive | inconclusive</verdict>
  <confidence>0.0–1.0</confidence>
  <technical_breakdown>
    [detailed technical reasoning referencing specific findings]
  </technical_breakdown>
  <malicious_interpretation>
    [prose — what an attacker scenario looks like]
  </malicious_interpretation>
  <benign_interpretation>
    [prose — what a legitimate activity scenario looks like]
  </benign_interpretation>
  <conclusion>
    [why one interpretation wins]
  </conclusion>
</assessment>

Be precise and evidence-based. Reference specific findings from the analyst doc.
"""


class EvaluatorAgent:
    """Second-opinion agent that makes the TP/FP call.

    Reads analyst findings only — no skill access, no tool use.
    """

    def __init__(self, client: anthropic.Anthropic) -> None:
        """
        Args:
            client: Configured Anthropic SDK client.
        """
        self._client = client

    def run(self, analyst_doc: str) -> str:
        """Evaluate analyst findings and return an assessment XML string.

        Args:
            analyst_doc: Full XML findings document from the analyst.

        Returns:
            XML string containing one ``<assessment>`` block.

        Raises:
            RuntimeError: If the model returns an empty response.
        """
        response = self._client.messages.create(
            model=_MODEL,
            max_tokens=4096,
            system=_SYSTEM,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"<analyst_findings>\n{analyst_doc}\n</analyst_findings>\n\n"
                        "Produce your <assessment> block now."
                    ),
                }
            ],
        )

        text = "".join(
            block.text for block in response.content if hasattr(block, "text")
        )
        if not text.strip():
            raise RuntimeError("EvaluatorAgent: model returned an empty response.")
        return text
