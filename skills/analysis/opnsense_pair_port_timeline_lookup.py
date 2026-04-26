"""OPNSense source-destination traffic timeline skill.

For a source and destination IP pair, aggregates traffic by destination port
and by minute.
"""

from typing import Any

from skills.base import InputType, Skill, SkillResult
from skills.foundational.query_builder import QueryBuilderSkill
from skills.foundational.query_executor import QueryExecutorSkill
from skills.foundational.template_store import QueryTemplate

_TEMPLATE_NAME = "opnsense_pair_port_timeline_lookup"

_TEMPLATE_DSL = """{
  "query": {
    "bool": {
      "filter": [
        {"term": {"decoder.name": "opnsense"}},
        {"term": {"data.srcip": {{src_ip}}}},
        {"term": {"data.dstip": {{dst_ip}}}},
        {"range": {"@timestamp": {"gte": "now-4h", "lte": "now"}}}
      ]
    }
  },
  "aggs": {
    "by_port": {
      "terms": {"field": "data.dstport", "size": 100},
      "aggs": {
        "per_minute": {
          "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "1m",
            "min_doc_count": 1
          }
        }
      }
    }
  }
}"""

_TEMPLATE = QueryTemplate(
    name=_TEMPLATE_NAME,
    description=(
        "Aggregate OPNSense traffic for a source-destination IP pair over the "
        "last 4 hours, grouped by destination port and 1-minute buckets."
    ),
    input_type="ip_address",
    params=["src_ip", "dst_ip"],
    template=_TEMPLATE_DSL,
)


class OpnsensePairPortTimelineLookupSkill(Skill):
    """Analyze minute-level traffic evolution for one source-destination pair."""

    name: str = "opnsense_pair_port_timeline_lookup"
    description: str = (
        "Analyzes OPNSense traffic between a source IP and destination IP over "
        "the last 4 hours. Aggregates by destination port and, for each port, "
        "counts events per minute."
    )
    input_type: InputType = InputType.IP_ADDRESS
    tool_input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "src_ip": {
                "type": "string",
                "description": "Source IP to investigate.",
            },
            "dst_ip": {
                "type": "string",
                "description": "Destination IP to investigate.",
            },
        },
        "required": ["src_ip", "dst_ip"],
    }

    def __init__(self, builder: QueryBuilderSkill, executor: QueryExecutorSkill) -> None:
        self._builder = builder
        self._executor = executor
        builder.store.add(_TEMPLATE)

    def _run(self, value: str, context: dict[str, Any]) -> SkillResult:
        tool_input = context.get("tool_input", {})
        src_ip = tool_input.get("src_ip")
        dst_ip = tool_input.get("dst_ip")

        if (not src_ip or not dst_ip) and value:
            # Fallback for direct tests/manual invocation using "src,dst".
            parts = [p.strip() for p in value.split(",", 1)]
            if len(parts) == 2 and all(parts):
                src_ip, dst_ip = parts

        if not src_ip or not dst_ip:
            return SkillResult.fail(
                "Both src_ip and dst_ip are required (tool_input or value='src_ip,dst_ip')."
            )

        build = self._builder.execute(
            _TEMPLATE_NAME,
            context={"params": {"src_ip": src_ip, "dst_ip": dst_ip}},
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

        by_port: list[dict[str, Any]] = []
        for port_bucket in aggs.get("by_port", {}).get("buckets", []):
            per_minute = [
                {
                    "timestamp": minute_bucket.get("key_as_string"),
                    "count": minute_bucket.get("doc_count", 0),
                }
                for minute_bucket in port_bucket.get("per_minute", {}).get("buckets", [])
                if minute_bucket.get("doc_count", 0) > 0
            ]
            by_port.append(
                {
                    "port": port_bucket.get("key"),
                    "event_count": port_bucket.get("doc_count", 0),
                    "per_minute": per_minute,
                }
            )

        data: dict[str, Any] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "event_count": total,
            "by_port": by_port,
            "distinct_port_count": len(by_port),
            "time_window": "last_4_hours",
        }

        if total == 0:
            summary = (
                f"No OPNSense traffic events found for pair {src_ip} -> {dst_ip} "
                "in the last 4 hours."
            )
        else:
            summary = (
                f"Pair {src_ip} -> {dst_ip} has {total} OPNSense event(s) across "
                f"{len(by_port)} destination port(s) in the last 4 hours."
            )

        return SkillResult(data=data, summary=summary, success=True)
