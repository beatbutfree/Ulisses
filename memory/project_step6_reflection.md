---
name: Step 6 — ChromaDB + reflector
description: Self-improvement architecture — ChromaQuerySkill, QueryCrafterSkill, ReflectorAgent, and structured logging
type: project
---

Step 6 adds a compounding-memory layer: the agent can retrieve semantically similar past queries, craft novel ones when nothing fits, and promote successful runtime queries to a persistent store.

**Components**:
- `store/chroma_client.py` — `ChromaQueryStore` wraps ChromaDB. `add/search/get/increment_counters/all`. `search` uses `$and` 2-filter metadata (`security_component`, `input_type`) before semantic search on `description + "\n" + goal`. Parameters stored as comma-joined string (ChromaDB rejects lists).
- `skills/foundational/chroma_query.py` — `ChromaQuerySkill`, generic + META. Internal LLM decides `use_as_is | modify | no_match` via forced `select_template` tool. Executes through `QueryExecutorSkill`. Logs `chroma_retrieved` record to shared `skill_log`.
- `skills/foundational/query_crafter.py` — `QueryCrafterSkill`, generic + META. LLM emits DSL via forced `emit_query` tool; validates by execution (HTTP error → retry once with feedback; zero results = valid information). Logs `query_crafted` record.
- `agent/reflector.py` — `ReflectorAgent`. Runs after formatter. Reads `skill_log` + evaluator doc. For `chroma_retrieved`: always `times_used++`, `times_successful++` only when verdict=TP AND success AND result_count>0. For `query_crafted`: promote iff (TP + results) OR (inconclusive AND confidence≥0.6). Skip on FP/zero-results/low-conf-inconclusive.
- `agent/logging_config.py` — `python-json-logger` + `RotatingFileHandler` at `logs/soc_agent.jsonl`. `new_run_id()` returns UUID v4; `get_logger(run_id)` returns a `_RunIdAdapter` stamping every record. Idempotent via `_configured` flag.

**Pipeline shape**: `alert + soar_prompt → analyst → evaluator → formatter → reflector → report`. Reflector node is optional at `build_graph(reflector=None)`. Analyst threads a shared mutable `skill_log: list[SkillExecutionRecord]` via `context`.

**Tool exposure mechanism**: `is_generic: bool = False` + `tool_input_schema: dict | None = None` on `Skill`. Analyst's `_is_exposed` checks `getattr(skill, "is_generic", False) is True` (identity check — MagicMock() is not True, so mock-based tests fall through to decoder filter unless explicitly set).

**Evaluation methodology**: deferred. The logging schema (`pipeline_start`, `skill_called`, `chroma_retrieved`, `query_crafted`, `pipeline_done`, all stamped with `run_id`) is designed so later metrics (detection rate, FPR, reuse rate, latency) can come from log analysis rather than code changes.

**Why:** Creates compounding analytical memory without fine-tuning. Templates stay hand-authored (primitives); ChromaDB stores queries earned at runtime and rewarded by verdict.

**How to apply:** When touching retrieval/promotion logic, remember the verdict gate lives in the reflector — not in the skills. Skills are dumb loggers; the reflector is the policy layer. When testing skills with `is_generic`, set the attribute explicitly on the mock (not `MagicMock()` alone).
