"""Fixed output schema for the agent pipeline.

``PRODUCE_REPORT_TOOL`` is the single source of truth for the final report
structure. Field names must never change — downstream classifiers depend on
them. The formatter calls this tool exactly once; the schema is enforced by
the tool definition, not by prompting.
"""

from typing import Any, TypedDict


# ---------------------------------------------------------------------------
# TypedDicts — mirrors the produce_report tool input_schema exactly
# ---------------------------------------------------------------------------


class ObservableRecord(TypedDict):
    """An observable extracted from the alert and its disposition."""

    type: str           # ip_address | username | rule_id | ...
    value: str
    disposition: str    # malicious | benign | suspicious | unknown


class FindingRecord(TypedDict):
    """A single skill invocation result condensed for the report."""

    skill: str
    observable: str
    severity_signal: str
    summary: str


class IncidentReport(TypedDict):
    """Final structured report emitted by the formatter.

    Field names are fixed forever — do not rename.
    """

    report_id: str
    generated_at: str           # ISO 8601 UTC
    verdict: str                # true_positive | false_positive | inconclusive
    confidence: float           # 0.0 – 1.0
    severity: str               # info | low | medium | high | critical
    title: str
    executive_summary: str      # 2–3 sentences, non-technical
    technical_breakdown: str    # detailed technical prose
    observables: list[ObservableRecord]
    findings: list[FindingRecord]
    recommended_actions: list[str]
    open_questions: list[str]
    raw_analyst_doc: str        # preserved verbatim for audit trail
    raw_evaluator_doc: str      # preserved verbatim for audit trail


# ---------------------------------------------------------------------------
# produce_report Anthropic tool definition
# ---------------------------------------------------------------------------

PRODUCE_REPORT_TOOL: dict[str, Any] = {
    "name": "produce_report",
    "description": (
        "Emit the final structured incident report. "
        "Call this exactly once with all fields populated."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "report_id": {
                "type": "string",
                "description": "Unique report identifier (UUID v4).",
            },
            "generated_at": {
                "type": "string",
                "description": "ISO 8601 UTC timestamp.",
            },
            "verdict": {
                "type": "string",
                "enum": ["true_positive", "false_positive", "inconclusive"],
            },
            "confidence": {
                "type": "number",
                "description": "Confidence score 0.0–1.0.",
                "minimum": 0.0,
                "maximum": 1.0,
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
            "title": {"type": "string"},
            "executive_summary": {
                "type": "string",
                "description": "2–3 sentences, non-technical.",
            },
            "technical_breakdown": {
                "type": "string",
                "description": "Detailed technical prose.",
            },
            "observables": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "value": {"type": "string"},
                        "disposition": {
                            "type": "string",
                            "enum": ["malicious", "benign", "suspicious", "unknown"],
                        },
                    },
                    "required": ["type", "value", "disposition"],
                },
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "skill": {"type": "string"},
                        "observable": {"type": "string"},
                        "severity_signal": {"type": "string"},
                        "summary": {"type": "string"},
                    },
                    "required": ["skill", "observable", "severity_signal", "summary"],
                },
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
            },
            "open_questions": {
                "type": "array",
                "items": {"type": "string"},
            },
            "raw_analyst_doc": {
                "type": "string",
                "description": "Full analyst findings document, verbatim.",
            },
            "raw_evaluator_doc": {
                "type": "string",
                "description": "Full evaluator assessment document, verbatim.",
            },
        },
        "required": [
            "report_id",
            "generated_at",
            "verdict",
            "confidence",
            "severity",
            "title",
            "executive_summary",
            "technical_breakdown",
            "observables",
            "findings",
            "recommended_actions",
            "open_questions",
            "raw_analyst_doc",
            "raw_evaluator_doc",
        ],
    },
}
