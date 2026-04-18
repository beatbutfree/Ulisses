---
name: Step 4 — analysis skills implementation
description: What was built in Step 4, architectural decisions made, and wiring instructions
type: project
---

## What was built

Three analysis skills for the `windows_eventchannel` decoder, in `skills/analysis/`:

| Skill | File | InputType |
|---|---|---|
| `WindowsIPLookupSkill` | `windows_ip_lookup.py` | `IP_ADDRESS` |
| `WindowsUsernameLookupSkill` | `windows_username_lookup.py` | `USERNAME` |
| `WindowsRuleLookupSkill` | `windows_rule_lookup.py` | `RULE_ID` |

Shared aggregation helpers in `skills/analysis/_helpers.py`:
`fmt_timestamp`, `parse_histogram`, `compute_peak_hour`, `compute_active_days`,
`compute_off_hours`, `parse_top_terms`, `parse_top_rules`, `parse_top_ports`.

## Changed in Step 4

**SkillRegistry** — replaced class-based with instance-based (Option B).
`register(skill: Skill)` stores pre-built instances. Breaking change; all tests updated.

**QueryExecutorSkill** — now calls `client.execute_query()` directly (not `client.query()`)
and adds `"aggregations": {}` key to `SkillResult.data`. Required for analysis skills to
read OpenSearch aggregation results. Summary logic also fixed for `size=0` queries.

**QueryBuilderSkill** — added `store` property so analysis skills can register their own
templates in `__init__` via `builder.store.add(template)`.

## Wiring (for Step 5 agent setup)

```python
from wazuh.client import WazuhIndexerClient
from skills.foundational.template_store import InMemoryTemplateStore
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.analysis.windows_ip_lookup import WindowsIPLookupSkill
from skills.analysis.windows_username_lookup import WindowsUsernameLookupSkill
from skills.analysis.windows_rule_lookup import WindowsRuleLookupSkill
from skills.registry import registry

client   = WazuhIndexerClient.from_env()
store    = InMemoryTemplateStore()
builder  = QueryBuilderSkill(store)
executor = QueryExecutorSkill(client)

registry.register(WindowsIPLookupSkill(builder, executor))
registry.register(WindowsUsernameLookupSkill(builder, executor))
registry.register(WindowsRuleLookupSkill(builder, executor))
```

## Field path notes (best-effort, verify during live testing)

- `data.win.eventdata.ipAddress` — source IP for logon events 4624/4625/4648
- `data.win.eventdata.targetUserName` — account name in logon/privilege events
- `data.win.eventdata.destinationAddress` — destination IP (network events)
- `data.win.eventdata.destinationPort` — destination port
- `data.win.eventdata.protocol` — protocol string
- `data.win.system.eventID` — Windows Event ID (stored as string in Wazuh)
- `agent.name` — Wazuh agent / machine name
- `rule.id`, `rule.level`, `rule.description` — Wazuh rule metadata

Rule level/description for `WindowsRuleLookupSkill` are read from
`context["alert"]["rule"]`, not queried from aggregations (avoids analyzed text field issue).
