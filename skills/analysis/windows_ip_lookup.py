"""WindowsIPLookupSkill — IP investigation for windows_eventchannel log source.

Targets the field ``data.win.eventdata.ipAddress``, which carries the source IP
address in Windows Security logon/logoff events (Event IDs 4624, 4625, 4648).
"""

from typing import Any

from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import QueryTemplate
from skills.analysis._helpers import (
    compute_active_days,
    compute_peak_hour,
    fmt_timestamp,
    parse_histogram,
    parse_top_ports,
    parse_top_rules,
    parse_top_terms,
)


# ---------------------------------------------------------------------------
# DSL template
# ---------------------------------------------------------------------------
# Field path notes:
#   data.win.eventdata.ipAddress     — source IP (logon events 4624/4625/4648)
#   data.win.eventdata.targetUserName — account name involved in the event
#   data.win.eventdata.destinationAddress — destination IP (network events)
#   data.win.eventdata.destinationPort   — destination port
#   data.win.eventdata.protocol          — protocol string
#   rule.id / rule.level / rule.description — Wazuh rule metadata
#
# All field paths are best-effort based on Wazuh's standard Windows decoder
# output and will be validated during live testing.

_TEMPLATE_NAME = "windows_ip_lookup"

_TEMPLATE_DSL = """{
  "query": {
    "bool": {
      "filter": [
        {"term": {"data.win.eventdata.ipAddress": {{ip_address}}}},
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
    "top_rules": {
      "terms": {"field": "rule.id", "size": 5},
      "aggs": {
        "rule_meta": {
          "top_hits": {"size": 1, "_source": ["rule.level", "rule.description"]}
        }
      }
    },
    "top_users": {
      "terms": {"field": "data.win.eventdata.targetUserName", "size": 5}
    },
    "top_dst_ips": {
      "terms": {"field": "data.win.eventdata.destinationAddress", "size": 5}
    },
    "top_dst_ports": {
      "terms": {"field": "data.win.eventdata.destinationPort", "size": 5},
      "aggs": {
        "protocol": {"terms": {"field": "data.win.eventdata.protocol", "size": 1}}
      }
    },
    "first_seen": {"min": {"field": "@timestamp"}},
    "last_seen":  {"max": {"field": "@timestamp"}}
  }
}"""

_TEMPLATE = QueryTemplate(
    name=_TEMPLATE_NAME,
    description=(
        "Aggregate all windows_eventchannel events for a source IP address. "
        "Targets data.win.eventdata.ipAddress (logon events 4624/4625/4648). "
        "Returns event count, 5-min activity histogram, peak hour, active days, "
        "first/last seen, top-5 rules (id+level+description), top-5 users "
        "(targetUserName), top-5 destination IPs, top-5 destination ports+protocol."
    ),
    input_type="ip_address",
    params=["ip_address"],
    template=_TEMPLATE_DSL,
)


# ---------------------------------------------------------------------------
# Skill
# ---------------------------------------------------------------------------


class WindowsIPLookupSkill(Skill):
    """Investigate an IP address across windows_eventchannel log events.

    Queries ``data.win.eventdata.ipAddress`` (source IP in logon/network events,
    decoder ``windows_eventchannel``). Returns aggregated activity statistics —
    no raw hits. Prefer this skill when ``alert["decoder"]["name"]`` is
    ``windows_eventchannel`` and the observable is an IP address.

    Fields not present in this log source are returned as empty lists with an
    accompanying ``_note`` key explaining the absence.
    """

    name: str = "windows_ip_lookup"
    description: str = (
        "Investigates an IP address in windows_eventchannel logs. "
        "Queries data.win.eventdata.ipAddress (source IP for logon events "
        "4624/4625/4648, decoder windows_eventchannel). Returns: event_count, "
        "activity_histogram (5-min buckets), peak_hour (0-23), active_days, "
        "first_seen/last_seen, top_5_rules (id+level+description+count), "
        "top_5_users (targetUserName), top_5_dst_ips (destinationAddress), "
        "top_5_dst_ports (port+protocol+count). Use when decoder is "
        "windows_eventchannel and observable is an IP address."
    )
    input_type: InputType = InputType.IP_ADDRESS

    def __init__(
        self,
        builder: QueryBuilderSkill,
        executor: QueryExecutorSkill,
    ) -> None:
        """
        Args:
            builder:  A ``QueryBuilderSkill`` whose store will receive this
                      skill's DSL template on construction.
            executor: A ``QueryExecutorSkill`` wired to a live
                      ``WazuhIndexerClient``.
        """
        self._builder = builder
        self._executor = executor
        builder.store.add(_TEMPLATE)

    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        """Investigate IP ``value`` in windows_eventchannel events.

        Args:
            value:   IP address string to investigate.
            context: Passed through to executor; supports ``"index"`` override.

        Returns:
            Successful ``SkillResult`` with aggregated data, or a failed result
            if the query build or execution step fails.
        """
        # Build DSL
        build = self._builder.execute(
            _TEMPLATE_NAME, context={"params": {"ip_address": value}}
        )
        if not build.success:
            return SkillResult.fail(f"Query build failed: {build.summary}")

        # Execute (aggregation query — no hits needed)
        exec_ctx = {k: v for k, v in context.items()}
        exec_ctx["size"] = 0
        run = self._executor.execute(build.data["query"], context=exec_ctx)
        if not run.success:
            return SkillResult.fail(f"Query execution failed: {run.summary}")

        aggs = run.data.get("aggregations", {})
        total: int = run.data.get("total", 0)

        histogram = parse_histogram(aggs.get("activity_over_time", {}))

        data: dict[str, Any] = {
            "event_count": total,
            "activity_histogram": histogram,
            "peak_hour": compute_peak_hour(histogram),
            "active_days": compute_active_days(histogram),
            "first_seen": fmt_timestamp(aggs.get("first_seen", {})),
            "last_seen": fmt_timestamp(aggs.get("last_seen", {})),
            "top_rules": parse_top_rules(aggs.get("top_rules", {})),
            "top_users": parse_top_terms(aggs.get("top_users", {})),
            "top_dst_ips": parse_top_terms(aggs.get("top_dst_ips", {})),
            "top_dst_ports": parse_top_ports(aggs.get("top_dst_ports", {})),
        }

        if total == 0:
            summary = f"No windows_eventchannel events found for IP {value}."
        else:
            top_rule = data["top_rules"][0]["id"] if data["top_rules"] else "none"
            summary = (
                f"IP {value} appeared in {total} Windows event(s) "
                f"across {data['active_days']} day(s) "
                f"(first {data['first_seen']}, last {data['last_seen']}). "
                f"Top rule: {top_rule}."
            )

        return SkillResult(data=data, summary=summary, success=True)
