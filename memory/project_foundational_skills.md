---
name: Foundational skills architecture
description: How QueryBuilderSkill and QueryExecutorSkill are wired together and why they are not in SkillRegistry
type: project
---

`QueryBuilderSkill` and `QueryExecutorSkill` live in `skills/foundational/` and are **not registered in `SkillRegistry`** because they require constructor injection (`store` and `client` respectively). The agent loop (Step 5) wires them up directly by instance.

**Flow**: `QueryBuilderSkill.execute(template_name, context={"params": {...}})` → `SkillResult.data["query"]` (DSL JSON string) → passed as `value` to `QueryExecutorSkill.execute(dsl_str)` → `SkillResult.data["hits"]`.

**Template store**: `InMemoryTemplateStore` for Steps 3–5. Step 6 swaps it for a ChromaDB-backed store — same `get/add/list_all` protocol, no changes to the builder.

**Substitution**: `_substitute()` uses `json.dumps(value, separators=(',',':'))` per placeholder, so strings get quoted, numbers stay bare, lists/dicts become compact JSON. Template author never wraps placeholders in quotes.

**Why:** Keeps query construction (LLM-driven, reusable) separate from execution (pure I/O). Allows Step 6 to store and retrieve templates by semantic similarity without touching the executor.

**How to apply:** When adding new query patterns in Steps 4–5, register a `QueryTemplate` in the store — do not hardcode DSL dicts inline in skills.
