"""Log analysis — stats, anomaly detection, timeline."""

from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime
import re


def compute_stats(records: List[Dict]) -> Dict[str, Any]:
    """Compute summary statistics from parsed log records."""
    stats = {
        "total_lines": len(records),
        "parsed": sum(1 for r in records if "_error" not in r),
        "errors": sum(1 for r in records if "_error" in r),
    }

    # IP analysis
    ips = [r.get("ip") for r in records if r.get("ip")]
    stats["unique_ips"] = len(set(ips))
    ip_counter = Counter(ips)
    stats["top_ips"] = ip_counter.most_common(10)

    # Status code analysis
    statuses = [r.get("status") for r in records if r.get("status")]
    status_counter = Counter(statuses)
    stats["status_codes"] = dict(status_counter.most_common())
    stats["error_count"] = sum(int(s) >= 400 for s in statuses if s.isdigit())
    stats["error_pct"] = round(stats["error_count"] / len(statuses) * 100, 1) if statuses else 0

    # Request analysis
    methods = []
    paths = []
    for r in records:
        req = r.get("request", "")
        parts = req.split()
        if len(parts) >= 2:
            methods.append(parts[0])
            paths.append(parts[1])

    stats["methods"] = dict(Counter(methods).most_common())
    stats["top_paths"] = Counter(paths).most_common(10)

    # Size analysis
    sizes = []
    for r in records:
        s = r.get("size", "0")
        if s and s != "-":
            try:
                sizes.append(int(s))
            except ValueError:
                pass

    if sizes:
        stats["total_bytes"] = sum(sizes)
        stats["avg_size"] = round(sum(sizes) / len(sizes), 1)
        stats["max_size"] = max(sizes)
        stats["min_size"] = min(sizes)

    # User agent analysis
    agents = [r.get("user_agent") for r in records if r.get("user_agent")]
    stats["unique_agents"] = len(set(agents))
    stats["top_agents"] = Counter(agents).most_common(5)

    # Timeline
    timestamps = [r.get("timestamp") for r in records if r.get("timestamp")]
    if timestamps:
        stats["first_seen"] = min(timestamps)
        stats["last_seen"] = max(timestamps)

    return stats


def format_stats(stats: Dict) -> str:
    """Format stats as text."""
    lines = []
    lines.append("=" * 56)
    lines.append("  Log Analysis Summary")
    lines.append("=" * 56)
    lines.append(f"  Total lines:    {stats['total_lines']}")
    lines.append(f"  Parsed:         {stats['parsed']}")
    lines.append(f"  Parse errors:   {stats['errors']}")
    lines.append("")

    if "first_seen" in stats:
        lines.append(f"  First entry:    {stats['first_seen']}")
        lines.append(f"  Last entry:     {stats['last_seen']}")
        lines.append("")

    if "unique_ips" in stats:
        lines.append(f"  Unique IPs:     {stats['unique_ips']}")
        lines.append("  Top IPs:")
        for ip, count in stats.get("top_ips", []):
            lines.append(f"    {ip:<20s}  {count}")
        lines.append("")

    if "status_codes" in stats:
        lines.append(f"  Status codes:")
        for code, count in sorted(stats["status_codes"].items()):
            bar = "#" * min(count, 40)
            lines.append(f"    {code}: {count:>5d}  {bar}")
        lines.append(f"  Errors (4xx+5xx): {stats.get('error_count', 0)} ({stats.get('error_pct', 0)}%)")
        lines.append("")

    if "methods" in stats:
        lines.append(f"  HTTP Methods:")
        for method, count in sorted(stats["methods"].items()):
            bar = "#" * min(count, 40)
            lines.append(f"    {method:<8s} {count:>5d}  {bar}")
        lines.append("")

    if "top_paths" in stats:
        lines.append(f"  Top paths:")
        for path, count in stats.get("top_paths", []):
            bar = "#" * min(count, 40)
            lines.append(f"    {count:>5d}  {path[:60]:60s}  {bar}")
        lines.append("")

    if "total_bytes" in stats:
        lines.append(f"  Traffic:")
        lines.append(f"    Total: {stats['total_bytes']:,} bytes")
        lines.append(f"    Avg:   {stats['avg_size']:,} bytes")
        lines.append(f"    Min:   {stats['min_size']:,} bytes")
        lines.append(f"    Max:   {stats['max_size']:,} bytes")
        lines.append("")

    return "\n".join(lines)


def detect_anomalies(records: List[Dict]) -> List[Dict]:
    """Detect anomalous patterns in log records."""
    anomalies = []

    # Group by minute for rate analysis
    timestamps = defaultdict(list)
    for r in records:
        ts = r.get("timestamp", "")
        # Extract minute-level grouping
        minute_key = ts[:16] if len(ts) >= 16 else ts
        timestamps[minute_key].append(r)

    # Find spike minutes (>2 std from mean)
    minute_counts = {k: len(v) for k, v in timestamps.items()}
    if minute_counts:
        values = list(minute_counts.values())
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values) if len(values) > 1 else 0
        std = variance ** 0.5
        threshold = mean + 2 * std

        for minute, count in sorted(minute_counts.items()):
            if count > threshold and count > 10:
                anomalies.append({
                    "type": "traffic_spike",
                    "time": minute,
                    "count": count,
                    "expected": round(mean, 1),
                    "severity": "high" if count > mean + 3 * std else "medium",
                })

    # Find error rate anomalies
    for minute, recs in sorted(timestamps.items()):
        total = len(recs)
        error_count = sum(1 for r in recs if r.get("status", "").isdigit() and int(r["status"]) >= 400)
        if total >= 5:  # Skip low-traffic minutes
            error_rate = error_count / total
            if error_rate > 0.5:
                anomalies.append({
                    "type": "high_error_rate",
                    "time": minute,
                    "error_rate": round(error_rate * 100, 1),
                    "errors": error_count,
                    "total": total,
                    "severity": "high" if error_rate > 0.8 else "medium",
                })

    # Suspicious IPs (rapid requests)
    ip_times = defaultdict(list)
    for r in records:
        ip = r.get("ip", "")
        ts = r.get("timestamp", "")
        if ip and ts:
            ip_times[ip].append(ts)

    for ip, times in ip_times.items():
        if len(times) > 100:
            anomalies.append({
                "type": "rapid_requests",
                "ip": ip,
                "count": len(times),
                "severity": "medium",
            })

    return anomalies


def format_anomalies(anomalies: List[Dict]) -> str:
    """Format anomalies as text."""
    if not anomalies:
        return "  No anomalies detected."

    lines = ["=" * 56, "  Anomalies Detected", "=" * 56]
    for a in anomalies:
        severity_indicator = "[HIGH]" if a.get("severity") == "high" else "[MED]"
        if a["type"] == "traffic_spike":
            lines.append(f"  {severity_indicator} Traffic spike at {a['time']}: {a['count']} req/min (expected ~{a['expected']})")
        elif a["type"] == "high_error_rate":
            lines.append(f"  {severity_indicator} High error rate at {a['time']}: {a['error_rate']}% ({a['errors']}/{a['total']})")
        elif a["type"] == "rapid_requests":
            lines.append(f"  {severity_indicator} Rapid requests from {a['ip']}: {a['count']} requests")

    return "\n".join(lines)
