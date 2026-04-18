"""Shared aggregation-parsing helpers for analysis skills.

All functions operate on the raw dicts returned by OpenSearch aggregations
(i.e. the value of ``SkillResult.data["aggregations"]``).
"""

from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------


def fmt_timestamp(agg_result: dict[str, Any]) -> str | None:
    """Format a ``min``/``max`` aggregation result as an ISO 8601 string.

    Uses ``value_as_string`` when present (OpenSearch formatted output),
    otherwise converts the epoch-millisecond ``value`` field.

    Args:
        agg_result: The aggregation result dict, e.g.
                    ``{"value": 1705305600000, "value_as_string": "..."}``.

    Returns:
        ISO 8601 string, or ``None`` when the aggregation matched no docs.
    """
    if not agg_result:
        return None
    value = agg_result.get("value")
    if value is None:
        return None
    if vs := agg_result.get("value_as_string"):
        return vs
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Histogram helpers
# ---------------------------------------------------------------------------


def parse_histogram(agg: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract non-empty buckets from a ``date_histogram`` aggregation.

    Args:
        agg: The ``date_histogram`` aggregation result dict.

    Returns:
        List of ``{"timestamp": <ISO str>, "count": <int>}`` dicts, one per
        non-empty bucket.
    """
    return [
        {"timestamp": b.get("key_as_string"), "count": b.get("doc_count", 0)}
        for b in agg.get("buckets", [])
        if b.get("doc_count", 0) > 0
    ]


def compute_peak_hour(histogram: list[dict[str, Any]]) -> int | None:
    """Return the hour of day (0–23) with the highest total activity.

    Aggregates counts across all days — e.g. if 08:00 had 10 events on
    Monday and 5 on Tuesday, the hour bucket for 8 has value 15.

    Args:
        histogram: Output of :func:`parse_histogram`.

    Returns:
        Hour integer (0–23), or ``None`` when the histogram is empty.
    """
    if not histogram:
        return None
    hour_totals: dict[int, int] = {}
    for bucket in histogram:
        ts = bucket.get("timestamp")
        count = bucket.get("count", 0)
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour_totals[dt.hour] = hour_totals.get(dt.hour, 0) + count
            except ValueError:
                pass
    return max(hour_totals, key=lambda h: hour_totals[h]) if hour_totals else None


def compute_active_days(histogram: list[dict[str, Any]]) -> int:
    """Count distinct calendar days that have at least one event.

    Args:
        histogram: Output of :func:`parse_histogram`.

    Returns:
        Number of distinct active days.
    """
    days: set[str] = set()
    for bucket in histogram:
        ts = bucket.get("timestamp")
        if ts and bucket.get("count", 0) > 0:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                days.add(dt.strftime("%Y-%m-%d"))
            except ValueError:
                pass
    return len(days)


def compute_off_hours(
    histogram: list[dict[str, Any]],
    start_hour: int = 8,
    end_hour: int = 18,
) -> bool:
    """Return ``True`` if any activity occurred outside business hours.

    Business hours are defined as [``start_hour``, ``end_hour``) UTC.

    Args:
        histogram:  Output of :func:`parse_histogram`.
        start_hour: First hour considered "business" (inclusive, default 8).
        end_hour:   First hour considered "after business" (exclusive, default 18).

    Returns:
        ``True`` if at least one event falls outside business hours.
    """
    for bucket in histogram:
        ts = bucket.get("timestamp")
        if ts and bucket.get("count", 0) > 0:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.hour < start_hour or dt.hour >= end_hour:
                    return True
            except ValueError:
                pass
    return False


# ---------------------------------------------------------------------------
# Terms aggregation helpers
# ---------------------------------------------------------------------------


def parse_top_terms(agg: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract key/count pairs from a ``terms`` aggregation.

    Args:
        agg: A ``terms`` aggregation result dict.

    Returns:
        List of ``{"key": <value>, "count": <int>}`` dicts.
    """
    return [
        {"key": b.get("key"), "count": b.get("doc_count", 0)}
        for b in agg.get("buckets", [])
    ]


def parse_top_rules(agg: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract rule buckets including level and description from a ``top_hits`` sub-agg.

    Expects the ``terms`` aggregation on ``rule.id`` to include a ``rule_meta``
    ``top_hits`` sub-aggregation sourcing ``rule.level`` and ``rule.description``.

    Args:
        agg: The ``terms`` aggregation result for ``rule.id``.

    Returns:
        List of ``{"id": str, "count": int, "level": int|None,
        "description": str|None}`` dicts.
    """
    rules = []
    for bucket in agg.get("buckets", []):
        entry: dict[str, Any] = {
            "id": bucket.get("key"),
            "count": bucket.get("doc_count", 0),
            "level": None,
            "description": None,
        }
        hits = bucket.get("rule_meta", {}).get("hits", {}).get("hits", [])
        if hits:
            source = hits[0].get("_source", {})
            rule_meta = source.get("rule", {})
            entry["level"] = rule_meta.get("level")
            entry["description"] = rule_meta.get("description")
        rules.append(entry)
    return rules


def parse_top_ports(agg: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract port/protocol buckets from a ``terms`` agg with protocol sub-agg.

    Args:
        agg: The ``terms`` aggregation result for a port field, with an optional
             ``protocol`` sub-aggregation.

    Returns:
        List of ``{"port": <value>, "request_count": int, "protocol": str|None}``
        dicts.
    """
    ports = []
    for bucket in agg.get("buckets", []):
        protocol_buckets = bucket.get("protocol", {}).get("buckets", [])
        ports.append({
            "port": bucket.get("key"),
            "request_count": bucket.get("doc_count", 0),
            "protocol": protocol_buckets[0].get("key") if protocol_buckets else None,
        })
    return ports
