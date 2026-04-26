"""OPNSense host behavior skill.

Investigates one source host and aggregates destination IPs contacted in the
last 4 hours, with per-destination event counts.
"""

from typing import Any

from skills.analysis._helpers import fmt_timestamp, parse_top_terms
from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import QueryTemplate

_TEMPLATE_NAME = "opnsense_host_behavior_lookup"

_TEMPLATE_DSL = """{
  "query": {
    "bool": {
      "filter": [
        {"term": {"decoder.name": "opnsense"}},
        {"term": {"data.srcip": {{ip_address}}}},
        {"range": {"@timestamp": {"gte": "now-4h", "lte": "now"}}}
      ]
    }
  },
  "aggs": {
    "contacted_ips": {
      "terms": {"field": "data.dstip", "size": 100}
    },
    "first_seen": {"min": {"field": "@timestamp"}},
    "last_seen": {"max": {"field": "@timestamp"}}
  }
}"""

_TEMPLATE = QueryTemplate(
    name=_TEMPLATE_NAME,
    description=(
        "Aggregate OPNSense traffic for one source IP in the last 4 hours. "
        "Filters decoder.name=opnsense and data.srcip=<ip>. Returns destination "
        "hosts contacted (data.dstip) with event counts plus first/last seen."
    ),
    input_type="ip_address",
    params=["ip_address"],
    template=_TEMPLATE_DSL,
)


class OpnsenseHostBehaviorLookupSkill(Skill):
    """Profile host-to-host behavior for OPNSense traffic events.

    Input is a source IP address. Output is an aggregation of all destination
    IPs contacted in the last 4 hours with event counts.
    """

    name: str = "opnsense_host_behavior_lookup"
    description: str = (
        "Profiles OPNSense traffic for one source IP over the last 4 hours. "
        "Queries decoder.name=opnsense and data.srcip, then aggregates all "
        "destination hosts (data.dstip) with their event counts to assess "
        "broad probing vs deeper/legitimate traffic concentration."
    )
    input_type: InputType = InputType.IP_ADDRESS

    def __init__(self, builder: QueryBuilderSkill, executor: QueryExecutorSkill) -> None:
        self._builder = builder
        self._executor = executor
        builder.store.add(_TEMPLATE)

    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        build = self._builder.execute(
            _TEMPLATE_NAME,
            context={"params": {"ip_address": value}},
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
        contacted = parse_top_terms(aggs.get("contacted_ips", {}))

        data: dict[str, Any] = {
            "event_count": total,
            "distinct_contacted_hosts": len(contacted),
            "contacted_ips": contacted,
            "first_seen": fmt_timestamp(aggs.get("first_seen", {})),
            "last_seen": fmt_timestamp(aggs.get("last_seen", {})),
            "time_window": "last_4_hours",
        }

        if total == 0:
            summary = f"No OPNSense traffic events found for source IP {value} in the last 4 hours."
        else:
            summary = (
                f"Source IP {value} generated {total} OPNSense event(s) toward "
                f"{len(contacted)} destination host(s) in the last 4 hours."
            )

        return SkillResult(data=data, summary=summary, success=True)
