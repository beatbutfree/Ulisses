---
name: Wazuh Indexer client architecture
description: Data query layer uses OpenSearch SDK on port 9200, not the Wazuh REST API on port 55000
type: project
---

The agent queries the **Wazuh Indexer (OpenSearch) on port 9200** for all alert and event data. The Wazuh manager REST API on port 55000 is management-only and is not used by the agent.

**Credentials**: shared — `WAZUH_API_USER` / `WAZUH_API_PASSWORD` work for both. URL env var is `WAZUH_INDEXER_URL`.

**Default index**: `wazuh-archives-*` (all events). Use `wazuh-alerts-*` only when explicitly querying fired-alert documents.

**Parser design**: `parse_hits()` strips `full_log` by default (raw-string duplicate of structured `data` fields) and recursively removes null/empty values from `_source` to minimise LLM token cost. Returns `ParsedResponse(hits, total, took_ms)` with clean Python dicts — serialisation to compact JSON happens at the skill/agent layer where token budget is known.

**Why:** `full_log` and sparse null fields in Wazuh `_source` would waste significant tokens if passed raw to the LLM.

**How to apply:** When building skills (Step 3) or agent prompts (Step 5), call `json.dumps(hit, separators=(',', ':'))` rather than pretty-printing. Use `keep_full_log=True` only for debugging.
