"""WindowsRuleLookupSkill — rule investigation for windows_eventchannel.

Investigates how a specific Wazuh rule ID manifests across
windows_eventchannel events: scope, affected hosts/users, associated IPs.

Rule level and description are read from ``context["alert"]`` (the triggering
alert document) rather than being queried from the indexer, since the alert
already carries that metadata.
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
    parse_top_terms,
)


# ---------------------------------------------------------------------------
# DSL template
# ---------------------------------------------------------------------------
# Field path notes:
#   rule.id                              — Wazuh rule ID (keyword field)
#   agent.name                           — Wazuh agent / machine that fired
#   data.win.eventdata.targetUserName    — affected account name
#   data.win.eventdata.ipAddress         — source IP associated with the event
#   data.win.eventdata.destinationAddress — destination IP

_TEMPLATE_NAME = "windows_rule_lookup"

_TEMPLATE_DSL = """{
  "query": {
    "bool": {
      "filter": [
        {"term": {"rule.id": {{rule_id}}}},
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
    "affected_agents": {
      "terms": {"field": "agent.name", "size": 5}
    },
    "affected_users": {
      "terms": {"field": "data.win.eventdata.targetUserName", "size": 5}
    },
    "top_src_ips": {
      "terms": {"field": "data.win.eventdata.ipAddress", "size": 5}
    },
    "top_dst_ips": {
      "terms": {"field": "data.win.eventdata.destinationAddress", "size": 5}
    },
    "first_seen": {"min": {"field": "@timestamp"}},
    "last_seen":  {"max": {"field": "@timestamp"}}
  }
}"""

_TEMPLATE = QueryTemplate(
    name=_TEMPLATE_NAME,
    description=(
        "Aggregate all windows_eventchannel events for a Wazuh rule ID. "
        "Queries rule.id with decoder filter windows_eventchannel. "
        "Returns event count, 5-min activity histogram, peak hour, active days, "
        "first/last seen, rule level and description (from context alert), "
        "top-5 affected agents (agent.name), top-5 affected users "
        "(targetUserName), top-5 source IPs (ipAddress), "
        "top-5 destination IPs (destinationAddress). "
        "Use when decoder is windows_eventchannel and observable is a rule ID."
    ),
    input_type="rule_id",
    params=["rule_id"],
    template=_TEMPLATE_DSL,
)


# ---------------------------------------------------------------------------
# Skill
# ---------------------------------------------------------------------------


class WindowsRuleLookupSkill(Skill):
    """Investigate a Wazuh rule ID across windows_eventchannel log events.

    Queries ``rule.id`` (decoder ``windows_eventchannel``). Rule level and
    description are sourced from ``context["alert"]["rule"]`` to avoid
    querying analyzed text fields in aggregations. Prefer this skill when
    ``alert["decoder"]["name"]`` is ``windows_eventchannel`` and the
    observable is a rule ID.
    """

    name: str = "windows_rule_lookup"
    description: str = (
        "Investigates a Wazuh rule ID in windows_eventchannel logs. "
        "Queries rule.id with decoder filter windows_eventchannel. Returns: "
        "event_count, activity_histogram (5-min buckets), peak_hour (0-23), "
        "active_days, first_seen/last_seen, rule_level and rule_description "
        "(read from context alert), top-5 affected_agents (agent.name), "
        "top-5 affected_users (targetUserName), top-5 top_src_ips (ipAddress), "
        "top-5 top_dst_ips (destinationAddress). "
        "Use when decoder is windows_eventchannel and observable is a rule ID."
    )
    input_type: InputType = InputType.RULE_ID

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
        """Investigate rule ID ``value`` in windows_eventchannel events.

        Args:
            value:   Wazuh rule ID string.
            context: Passed through to executor; also read for
                     ``context["alert"]["rule"]`` to source level/description.

        Returns:
            Successful ``SkillResult`` with aggregated data, or failed on error.
        """
        build = self._builder.execute(
            _TEMPLATE_NAME, context={"params": {"rule_id": value}}
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

        # Rule metadata comes from the context alert, not from aggregations
        alert_rule: dict[str, Any] = context.get("alert", {}).get("rule", {})

        histogram = parse_histogram(aggs.get("activity_over_time", {}))

        data: dict[str, Any] = {
            "event_count": total,
            "activity_histogram": histogram,
            "peak_hour": compute_peak_hour(histogram),
            "active_days": compute_active_days(histogram),
            "first_seen": fmt_timestamp(aggs.get("first_seen", {})),
            "last_seen": fmt_timestamp(aggs.get("last_seen", {})),
            "rule_level": alert_rule.get("level"),
            "rule_description": alert_rule.get("description"),
            "affected_agents": parse_top_terms(aggs.get("affected_agents", {})),
            "affected_users": parse_top_terms(aggs.get("affected_users", {})),
            "top_src_ips": parse_top_terms(aggs.get("top_src_ips", {})),
            "top_dst_ips": parse_top_terms(aggs.get("top_dst_ips", {})),
        }

        if total == 0:
            summary = (
                f"Rule {value} has no windows_eventchannel events in the index."
            )
        else:
            agents = len(data["affected_agents"])
            summary = (
                f"Rule {value} ({data['rule_description'] or 'no description'}) "
                f"fired {total} time(s) across {agents} agent(s) "
                f"over {data['active_days']} day(s)."
            )

        return SkillResult(data=data, summary=summary, success=True)
