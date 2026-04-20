# SOC L1 Agent — Project Context

## What this project is

An autonomous L1 SOC analyst agent that queries Wazuh (and later other security
components) to investigate alerts. The agent has access to **skills** (analysis
and foundational), iterates over results, and improves itself by storing useful
queries in a vector knowledge base.

This is also a thesis project — architectural decisions must be explainable
and academically defensible.

---

## Goal

Build a Python agent that:
1. Receives a Wazuh alert
2. Decides which skills to invoke (IP lookup, user check, rule analysis, etc.)
3. Iterates over results, building a picture of the incident
4. Saves useful queries to a knowledge base so it gets better over time
5. Produces a structured incident summary

---

## Maintenance rule

After every step completes with all tests passing, update this file (mark the step ✅ done, advance the ▶ next pointer) and add or update the relevant entry in `memory/` + `memory/MEMORY.md`. Do this autonomously — no reminder needed.

---

## Build status

### Build order

| Step | Status | Description |
|------|--------|-------------|
| 1 | ✅ done | Skill interface: `Skill` ABC, `SkillResult`, `InputType`, `Severity`, `SkillRegistry` |
| 2 | ✅ done | Wazuh Indexer client: OpenSearch SDK wrapper (port 9200) — `execute_query` + `parse_hits` |
| 3 | ✅ done | Foundational skills: `QueryTemplate`, `InMemoryTemplateStore`, `QueryBuilderSkill`, `QueryExecutorSkill` |
| 4 | ✅ done | Analysis skills: one skill per `decoder.name` — `windows_eventchannel` + `wazuh` internal; IP/user/rule lookup per source |
| 5 | ✅ done | Three-agent pipeline: Analyst → Evaluator → Formatter |
| **6** | **▶ next** | **ChromaDB knowledge store + reflection / self-improvement step** |
| 7 | pending | End-to-end test with a live Wazuh alert |

---

## Proposed project structure

```
soc_agent/
├── CLAUDE.md
├── .env                             ← never commit (see vars below)
├── requirements.txt
├── skills/
│   ├── base.py                      ← Skill ABC, SkillResult, InputType, Severity
│   ├── registry.py                  ← SkillRegistry singleton
│   ├── analysis/                    ← Skills that enrich an observable (IP, user, hash)
│   └── foundational/                ← Skills the agent uses to build and run queries
├── wazuh/                           ← Wazuh Indexer client (OpenSearch SDK, port 9200)
├── agent/                           ← LangGraph agent loop
├── store/                           ← ChromaDB knowledge/query store
└── tests/
```

---

## Technology choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | Python 3.12 | Full control, easy LLM SDK integration, thesis-explainable |
| Agent framework | LangGraph | Explicit state machine — easy to diagram for thesis |
| Knowledge store | ChromaDB | Local, no extra infra, semantic similarity retrieval |
| Security platform | Wazuh Indexer (OpenSearch) on port 9200 | Already deployed; same credentials as manager |
| LLM | Anthropic Claude (`claude-sonnet-4-20250514`) | Via Anthropic SDK |

**Do not introduce n8n, AutoGen, or CrewAI** — the explicit Python architecture
is a deliberate thesis decision (observability + academic explainability).

---

## Infrastructure (already deployed)

- **Wazuh manager**: running on port 55000 (management only — not queried or usefull to the agent)
- **Wazuh Indexer**: OpenSearch on port 9200 — this is what the agent queries for alerts/events
- **Windows Domain Controller**: generating AD events
- **Windows client**: generating endpoint events (logon, process, network)
- Wazuh agents installed on both DC and client

`.env` variables needed (never commit this file)

Default query index: `wazuh-archives-*` (all events). Use `wazuh-alerts-*` only when
explicitly querying fired-alert documents.

---

## Design decisions to respect

### Skill contract
- Every skill subclasses `Skill` and implements `_run(value: str, context: dict) -> SkillResult`
- The public `execute()` method wraps `_run` with timing, error handling, and source tagging
- Skills must never be called with `_run` directly — always `execute()`
- `data` inside `SkillResult` must always be JSON-serialisable
- `summary` is a 1–3 sentence natural language brief written for a human analyst

### Self-improvement (Step 6)
After each analysis cycle the agent runs a reflection step:
1. Was the query useful? (did it return relevant, non-empty results?)
2. If yes → store `{description, query, input_type, source, confidence_score}` in ChromaDB
3. On future analyses → retrieve top-K semantically similar past queries before building new ones

The thesis claim: this creates compounding analytical memory without retraining the model.

### Severity alignment
Map Wazuh rule levels to the internal `Severity` enum:
- Levels 0–6 → LOW
- Levels 7–11 → MEDIUM
- Levels 12–14 → HIGH
- Level 15 → CRITICAL

---

## Core design principles

### Specialised skills per log source — no silent field failures
Different Wazuh decoders produce different field names for the same concept
(`data.srcip` for firewalls, `data.win.eventdata.ipAddress` for Windows, etc.).
A generic skill querying the wrong field returns empty results with no error —
the agent cannot distinguish "no activity" from "wrong field name."

**Resolution: one skill per `decoder.name`.** Every Wazuh alert carries
`decoder.name` (e.g. `windows_eventchannel`, `iptables`, `pf`). The agent reads
this field and selects the matching skill directly. No guessing, no retries,
no silent failures.

When a field does not exist in a given log source the skill must be explicit:
```python
"top_src_ips": [],
"top_src_ips_note": "field not present in this log source"
```
**The agent must never treat an empty list as "no activity" without checking
the corresponding `_note` field.**

Currently implemented log sources (expand as the lab grows):
- `windows_eventchannel` — DC and Windows client events
- `wazuh` — Wazuh internal / manager alerts

### Layered I/O
- Analysis skills → `QueryBuilderSkill` → `QueryExecutorSkill` → `WazuhIndexerClient`
- Analysis skills must **never** call `WazuhIndexerClient` directly
- Each layer knows only about the layer directly below it

### Dependency injection
Both analysis and foundational skills receive dependencies via `__init__` and
are registered as **instances** (not classes) in `SkillRegistry`.

### Agent loop — three-agent pipeline (Step 5)

```
Alert + SOAR prompt → Analyst → Evaluator → Formatter → Final report
```

**Analyst** — reads skill registry descriptions from the system prompt to decide which skills to invoke (no ChromaDB for skill selection). Exercises investigative judgement: what looks suspicious, whether to dig deeper, when to stop. Does NOT make the TP/FP call. Output: `<finding>` and `<open_question>` XML blocks (free prose inside, no formatting pressure).

**Evaluator** — reads analyst doc only; no skill access. Makes the TP/FP call with a confidence score; explains both malicious and benign interpretations before committing. Output: `<assessment>` XML block.

**Formatter** — receives both docs; calls a single `produce_report` tool to emit the final report. Schema is enforced by the tool definition, not by prompting — this is the only reliable way to guarantee identical structure across runs.

`produce_report` fixed schema (never change field names):
```
report_id, generated_at, verdict, confidence, severity, title,
executive_summary, technical_breakdown, observables, findings,
recommended_actions, open_questions,
raw_analyst_doc, raw_evaluator_doc   ← full audit trail, preserved verbatim
```

**Implementation order**: Formatter first (fewest dependencies, forces the schema to be concrete) → Evaluator → Analyst (most complex, depends on full skill registry).

---

## Coding conventions

- Type-annotate everything using native Python 3.12 syntax (`list[str]`, `dict[str, Any]`, `X | None`)
- Docstrings on every class and public method
- No bare `except` — catch specific exceptions or `except Exception as exc`
- Every new skill gets a test file in `tests/` before being considered done
- Run `python -m pytest tests/ -v` before every commit

---

## Thesis chapter map (for reference)

1. **Introduction** — SOC analyst workload, alert fatigue, LLM agents as partial solution
2. **Background** — Wazuh architecture, LLM tool-use, ReAct / LangGraph patterns
3. **System design** — skill interface, registry, agent loop, knowledge store
4. **Implementation** — each build step, decisions, tradeoffs
5. **Evaluation** — detection rate, false positive rate, query reuse rate, response time
6. **Conclusion** — limitations, future work (multi-SIEM, fine-tuning on stored queries)