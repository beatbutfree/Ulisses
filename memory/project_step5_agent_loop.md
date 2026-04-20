---
name: Step 5 — Three-agent pipeline implementation
description: Architecture and wiring of the Analyst/Evaluator/Formatter pipeline built in Step 5
type: project
---

Three-agent LangGraph pipeline implemented in `agent/`. All 206 tests pass.

**Why:** Step 5 of the thesis build — explicit, diagrammable state machine for academic explainability.

**How to apply:** When extending the pipeline (Step 6 ChromaDB), the insertion point is `runner.py:build_registry()` for the store and the analyst's tool loop in `analyst.py`.

## Files

| File | Role |
|------|------|
| `agent/schema.py` | `IncidentReport` TypedDict + `PRODUCE_REPORT_TOOL` Anthropic tool definition |
| `agent/formatter.py` | `FormatterAgent` — forced tool-use (`tool_choice=any`), single API call |
| `agent/evaluator.py` | `EvaluatorAgent` — no tools, single API call, returns `<assessment>` XML |
| `agent/analyst.py` | `AnalystAgent` — tool-use loop, max 10 iterations, skills as tools |
| `agent/graph.py` | `PipelineState` TypedDict + `build_graph()` — linear START→analyst→evaluator→formatter→END |
| `agent/runner.py` | `run_pipeline(alert, soar_prompt, registry=None)` — entry point |

## Key design decisions

- **Formatter uses `tool_choice={"type": "any"}`** — structure guaranteed by tool contract, not prompting.
- **Analyst filters skills by decoder prefix**: `windows_eventchannel` → exposes skills starting with `windows_`.
- **Messages passed as shallow copy** (`list(messages)`) to each Anthropic API call so `call_args` in tests isn't mutated by subsequent appends.
- **`SkillRegistry._instance = None`** reset in analyst tests to avoid singleton state bleed between tests.
- **Model default**: `claude-sonnet-4-6` (overridable via `ANTHROPIC_MODEL` env var).
- **`run_pipeline(registry=None)`**: pass a mock registry to skip live Wazuh connection in tests.
