"""WindowsUsernameLookupSkill — username investigation for windows_eventchannel.

Targets ``data.win.eventdata.targetUserName``, the account name present in
Windows Security logon/logoff and privilege events.
"""

from typing import Any

from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import QueryTemplate
from skills.analysis._helpers import (
    compute_active_days,
    compute_off_hours,
    compute_peak_hour,
    fmt_timestamp,
    parse_histogram,
    parse_top_terms,
    parse_top_rules,
)


# ---------------------------------------------------------------------------
# DSL template
# ---------------------------------------------------------------------------
# Field path notes:
#   data.win.eventdata.targetUserName — account name (logon events 4624/4625)
#   data.win.eventdata.ipAddress      — source IP for the logon attempt
#   data.win.eventdata.destinationAddress — destination IP (network events)
#   data.win.system.eventID           — Windows Event ID (string in Wazuh)
#   agent.name                        — Wazuh agent / machine name
#   rule.id / rule.level / rule.description — Wazuh rule metadata
#
# logon_events / failed_logon_events use filter aggregations on Event IDs.
# Event ID 4624 = successful logon, 4625 = failed logon.

_TEMPLATE_NAME = "windows_username_lookup"

_TEMPLATE_DSL = """{
  "query": {
    "bool": {
      "filter": [
        {"term": {"data.win.eventdata.targetUserName": {{username}}}},
        {"term": {"decoder.name": "windows_eventchannel"}}
      ]
    }
  },
  "aggs": {
    "activity_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "5m",
        "min_doc_count": 1
      }
    },
    "logon_events": {
      "filter": {"term": {"data.win.system.eventID": "4624"}}
    },
    "failed_logon_events": {
      "filter": {"term": {"data.win.system.eventID": "4625"}}
    },
    "src_ips": {
      "terms": {"field": "data.win.eventdata.ipAddress", "size": 5}
    },
    "dst_ips": {
      "terms": {"field": "data.win.eventdata.destinationAddress", "size": 5}
    },
    "machines_accessed": {
      "terms": {"field": "agent.name", "size": 5}
    },
    "top_rules": {
      "terms": {"field": "rule.id", "size": 5},
      "aggs": {
        "rule_meta": {
          "top_hits": {"size": 1, "_source": ["rule.level", "rule.description"]}
        }
      }
    },
    "first_seen": {"min": {"field": "@timestamp"}},
    "last_seen":  {"max": {"field": "@timestamp"}}
  }
}"""

_TEMPLATE = QueryTemplate(
    name=_TEMPLATE_NAME,
    description=(
        "Aggregate all windows_eventchannel events for a username. "
        "Targets data.win.eventdata.targetUserName (logon events 4624/4625). "
        "Returns event count, 5-min activity histogram, peak hour, active days, "
        "first/last seen, logon count (Event ID 4624), failed logon count "
        "(Event ID 4625), source IPs, destination IPs, machines accessed "
        "(agent.name), off-hours activity flag, top-5 rules."
    ),
    input_type="username",
    params=["username"],
    template=_TEMPLATE_DSL,
)


# ---------------------------------------------------------------------------
# Skill
# ---------------------------------------------------------------------------


class WindowsUsernameLookupSkill(Skill):
    """Investigate a username across windows_eventchannel log events.

    Queries ``data.win.eventdata.targetUserName`` (decoder
    ``windows_eventchannel``). Returns aggregated activity statistics.
    Prefer this skill when ``alert["decoder"]["name"]`` is
    ``windows_eventchannel`` and the observable is a username.
    """

    name: str = "windows_username_lookup"
    description: str = (
        "Investigates a username in windows_eventchannel logs. "
        "Queries data.win.eventdata.targetUserName (logon events 4624/4625, "
        "decoder windows_eventchannel). Returns: event_count, "
        "activity_histogram (5-min buckets), peak_hour (0-23), active_days, "
        "first_seen/last_seen, logon_count (Event ID 4624), "
        "failed_logon_count (Event ID 4625), src_ips (top-5 ipAddress), "
        "dst_ips (top-5 destinationAddress), machines_accessed (top-5 agent.name), "
        "off_hours_activity (bool, outside 08:00-18:00 UTC), "
        "top_rules (top-5 id+level+description+count). "
        "Use when decoder is windows_eventchannel and observable is a username."
    )
    input_type: InputType = InputType.USERNAME

    def __init__(
        self,
        builder: QueryBuilderSkill,
        executor: QueryExecutorSkill,
    ) -> None:
        """
        Args:
            builder:  ``QueryBuilderSkill`` whose store receives this skill's template.
            executor: ``QueryExecutorSkill`` wired to a live ``WazuhIndexerClient``.
        """
        self._builder = builder
        self._executor = executor
        builder.store.add(_TEMPLATE)

    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        """Investigate username ``value`` in windows_eventchannel events.

        Args:
            value:   Username string to investigate.
            context: Passed through to executor; supports ``"index"`` override.

        Returns:
            Successful ``SkillResult`` with aggregated data, or failed on error.
        """
        build = self._builder.execute(
            _TEMPLATE_NAME, context={"params": {"username": value}}
        )
        if not build.success:
            return SkillResult.fail(f"Query build failed: {build.summary}")

        exec_ctx = {k: v for k, v in context.items()}
        exec_ctx["size"] = 0
        run = self._executor.execute(build.data["query"], context=exec_ctx)
        if not run.success:
            return SkillResult.fail(f"Query execution failed: {run.summary}")

        aggs = run.data.get("aggregations", {})
        total: int = run.data.get("total", 0)

        histogram = parse_histogram(aggs.get("activity_over_time", {}))
        logon_count: int = aggs.get("logon_events", {}).get("doc_count", 0)
        failed_count: int = aggs.get("failed_logon_events", {}).get("doc_count", 0)

        data: dict[str, Any] = {
            "event_count": total,
            "activity_histogram": histogram,
            "peak_hour": compute_peak_hour(histogram),
            "active_days": compute_active_days(histogram),
            "first_seen": fmt_timestamp(aggs.get("first_seen", {})),
            "last_seen": fmt_timestamp(aggs.get("last_seen", {})),
            "logon_count": logon_count,
            "failed_logon_count": failed_count,
            "src_ips": parse_top_terms(aggs.get("src_ips", {})),
            "dst_ips": parse_top_terms(aggs.get("dst_ips", {})),
            "machines_accessed": parse_top_terms(aggs.get("machines_accessed", {})),
            "off_hours_activity": compute_off_hours(histogram),
            "top_rules": parse_top_rules(aggs.get("top_rules", {})),
        }

        if total == 0:
            summary = f"No windows_eventchannel events found for username '{value}'."
        else:
            off_hours_note = " (off-hours activity detected)" if data["off_hours_activity"] else ""
            summary = (
                f"Username '{value}' appeared in {total} Windows event(s) "
                f"across {data['active_days']} day(s){off_hours_note}. "
                f"Logons: {logon_count}, failed: {failed_count}."
            )

        return SkillResult(data=data, summary=summary, success=True)
