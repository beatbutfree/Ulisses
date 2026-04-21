---
name: Foundational skills architecture
description: How QueryBuilderSkill and QueryExecutorSkill are wired together and why they are not in SkillRegistry
type: project
---

`QueryBuilderSkill` and `QueryExecutorSkill` live in `skills/foundational/` and are **not registered in `SkillRegistry`** because they require constructor injection (`store` and `client` respectively). The agent loop (Step 5) wires them up directly by instance.

**Flow**: `QueryBuilderSkill.execute(template_name, context={"params": {...}})` → `SkillResult.data["query"]` (DSL JSON string) → passed as `value` to `QueryExecutorSkill.execute(dsl_str)` → `SkillResult.data["hits"]`.

**Template store**: `InMemoryTemplateStore` holds hand-authored primitives and remains active in Step 6 alongside ChromaDB. ChromaDB is additive — it stores queries earned at runtime via the reflector, while templates stay hand-authored. The two stores coexist and serve different purposes.

**Step 6 additions**: two generic foundational skills (`ChromaQuerySkill`, `QueryCrafterSkill`) both with `is_generic=True` + `input_type=InputType.META`. Manually wired in `runner.py` (not auto-discovered). They bypass the analyst's decoder-prefix filter and appear as tools for any alert.

**Substitution**: `_substitute()` uses `json.dumps(value, separators=(',',':'))` per placeholder, so strings get quoted, numbers stay bare, lists/dicts become compact JSON. Template author never wraps placeholders in quotes.

**Why:** Keeps query construction (LLM-driven, reusable) separate from execution (pure I/O). Allows Step 6 to store and retrieve templates by semantic similarity without touching the executor.

**How to apply:** When adding new query patterns in Steps 4–5, register a `QueryTemplate` in the store — do not hardcode DSL dicts inline in skills.
