---
name: Analysis skills design decisions
description: Architecture constraints for Step 4 analysis skills — decoder-specific, no silent field failures
type: project
---

## Core rule: one skill per decoder.name

Every Wazuh alert has a `decoder.name` field that identifies which decoder
processed the log (e.g. `windows_eventchannel`, `iptables`, `pf`, `wazuh`).
Different decoders produce different field names for the same concept.

**The agent reads `decoder.name` and selects the matching skill — no guessing,
no runtime field-passing, no retries on empty results.**

The old "field as runtime param" approach was rejected because a skill querying
the wrong field returns empty results silently. The agent cannot distinguish
"no activity" from "wrong field name."

## Currently implemented log sources

| decoder.name | Skill module |
|---|---|
| `windows_eventchannel` | `skills/analysis/windows_eventchannel.py` |
| `wazuh` | `skills/analysis/wazuh_internal.py` |

More are added as the lab expands (iptables, pf, syslog, etc.).

## Missing field convention

When a field does not exist in a given log source, the skill MUST output:
```python
"top_src_ips": [],
"top_src_ips_note": "field not present in this log source"
```
The agent must never treat an empty list as "no activity" without checking the
corresponding `_note` field first.

## Output shape

Aggregated summary as primary output — agent reasons over aggregates, not raw hits.
Raw hits included under `"raw_hits"` key for traceability.

## Query path (hard constraint)

Analysis skills → QueryBuilderSkill → QueryExecutorSkill → WazuhIndexerClient.
Analysis skills must NEVER call WazuhIndexerClient directly.

## Dependency injection

Constructor injection. Registered as instances in SkillRegistry.

## Why:
Decoder-specific skills make field mapping a compile-time decision, not a
runtime guess. Silent empty results become impossible. The agent's skill
selection logic is trivial (read one field, pick one skill).

## How to apply:
When adding a new log source skill, first check what decoder.name Wazuh assigns
to that source. Map every relevant observable field (IP, user, etc.) explicitly
in that skill's templates. Document which fields are absent with _note keys.
