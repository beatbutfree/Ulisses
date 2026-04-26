"""OPNSense multi-port contact skill.

Investigates one source host and returns destination hosts where at least five
distinct destination ports were contacted.
"""

from typing import Any

from skills.analysis._helpers import fmt_timestamp
from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import QueryTemplate

_TEMPLATE_NAME = "opnsense_multiport_contact_lookup"

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
    "hosts": {
      "terms": {"field": "data.dstip", "size": 100},
      "aggs": {
        "unique_ports": {"cardinality": {"field": "data.dstport"}},
        "ports_sample": {"terms": {"field": "data.dstport", "size": 50}},
        "at_least_5_ports": {
          "bucket_selector": {
            "buckets_path": {"portCount": "unique_ports"},
            "script": "params.portCount >= 5"
          }
        }
      }
    },
    "first_seen": {"min": {"field": "@timestamp"}},
    "last_seen": {"max": {"field": "@timestamp"}}
  }
}"""

_TEMPLATE = QueryTemplate(
    name=_TEMPLATE_NAME,
    description=(
        "Aggregate OPNSense traffic for one source IP in the last 4 hours and "
        "return only destination hosts contacted on at least 5 distinct "
        "destination ports."
    ),
    input_type="ip_address",
    params=["ip_address"],
    template=_TEMPLATE_DSL,
)


class OpnsenseMultiportContactLookupSkill(Skill):
    """Find destination hosts touched on many ports by one source IP.

    This is useful for identifying horizontal scan behavior where a source host
    tests multiple ports against each target destination.
    """

    name: str = "opnsense_multiport_contact_lookup"
    description: str = (
        "Finds OPNSense destination hosts contacted by a source IP on at least "
        "5 distinct destination ports in the last 4 hours. Returns per-host "
        "port cardinality and a sample of contacted ports."
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

        hosts: list[dict[str, Any]] = []
        for bucket in aggs.get("hosts", {}).get("buckets", []):
            ports_sample = [
                p.get("key") for p in bucket.get("ports_sample", {}).get("buckets", [])
            ]
            hosts.append(
                {
                    "host": bucket.get("key"),
                    "event_count": bucket.get("doc_count", 0),
                    "distinct_port_count": int(bucket.get("unique_ports", {}).get("value", 0)),
                    "ports_sample": ports_sample,
                }
            )

        data: dict[str, Any] = {
            "event_count": total,
            "hosts_with_5plus_ports": hosts,
            "qualified_host_count": len(hosts),
            "first_seen": fmt_timestamp(aggs.get("first_seen", {})),
            "last_seen": fmt_timestamp(aggs.get("last_seen", {})),
            "time_window": "last_4_hours",
        }

        if total == 0:
            summary = f"No OPNSense traffic events found for source IP {value} in the last 4 hours."
        elif not hosts:
            summary = (
                f"Source IP {value} has OPNSense traffic, but no destination host "
                "was contacted on 5 or more distinct ports in the last 4 hours."
            )
        else:
            summary = (
                f"Source IP {value} contacted {len(hosts)} destination host(s) on "
                "at least 5 distinct ports in the last 4 hours."
            )

        return SkillResult(data=data, summary=summary, success=True)
