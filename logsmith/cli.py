"""Logsmith CLI — Log file forensics toolkit."""

import argparse
import sys
import os

from . import __version__
from .parsers import parse_file, detect_log_format
from .analysis import compute_stats, format_stats, detect_anomalies, format_anomalies
from .search import search_logs, grep_logs
from .report import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog="logsmith",
        description="Log file forensics and analysis toolkit",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # parse
    p = sub.add_parser("parse", help="Parse log file into structured output")
    p.add_argument("file", help="Log file path")
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")
    p.add_argument("--json", action="store_true", help="Output as JSON")

    # stats
    p = sub.add_parser("stats", help="Show log summary statistics")
    p.add_argument("file", help="Log file path")
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")

    # anomalies
    p = sub.add_parser("anomalies", help="Detect anomalous patterns")
    p.add_argument("file", help="Log file path")
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")

    # search
    p = sub.add_parser("search", help="Search logs with context")
    p.add_argument("pattern", help="Regex pattern to search for")
    p.add_argument("file", help="Log file path")
    p.add_argument("--context", "-C", type=int, default=0, help="Lines of context")
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")

    # top
    p = sub.add_parser("top", help="Show top values by column")
    p.add_argument("column", help="Column name (e.g. ip, path, status)")
    p.add_argument("file", help="Log file path")
    p.add_argument("--limit", "-n", type=int, default=10)
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")

    # timeline
    p = sub.add_parser("timeline", help="Filter by time range")
    p.add_argument("file", help="Log file path")
    p.add_argument("--from", dest="from_ts", help="Start timestamp")
    p.add_argument("--to", dest="to_ts", help="End timestamp")
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")

    # report
    p = sub.add_parser("report", help="Generate HTML report")
    p.add_argument("file", help="Log file path")
    p.add_argument("-o", "--output", default="log_report.html", help="Output file")
    p.add_argument("--title", default="Log Analysis Report", help="Report title")
    p.add_argument("--format", choices=["apache_common", "apache_combined", "syslog_3164",
                                         "syslog_5424", "jsonl", "auto"], default="auto")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[ERR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Detect format if auto
    fmt = args.format if hasattr(args, 'format') and args.format != "auto" else None
    if fmt is None:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            sample = [f.readline().strip() for _ in range(5)]
        fmt = detect_log_format(sample)
        if fmt is None:
            fmt = "apache_combined"  # best guess

    records = parse_file(args.file, fmt)

    if args.command == "parse":
        if args.json:
            import json
            json.dump(records, sys.stdout, indent=2, default=str)
        else:
            print(f"[OK] Parsed {len(records)} records from {args.file} ({fmt})")
            for r in records[:5]:
                print(f"  {r}")

    elif args.command == "stats":
        stats = compute_stats(records)
        print(format_stats(stats))

    elif args.command == "anomalies":
        anom = detect_anomalies(records)
        print(format_anomalies(anom))

    elif args.command == "search":
        result = grep_logs(records, args.pattern, args.context)
        if result:
            print(result)
        else:
            print(f"No matches for '{args.pattern}'")

    elif args.command == "top":
        from collections import Counter
        if args.column in ("ip", "ips"):
            values = [r.get("ip", "") for r in records if r.get("ip")]
        elif args.column in ("path", "paths", "url", "urls"):
            values = []
            for r in records:
                req = r.get("request", "")
                parts = req.split()
                if len(parts) >= 2:
                    values.append(parts[1])
        elif args.column in ("status", "statuses", "code", "codes"):
            values = [r.get("status", "") for r in records if r.get("status")]
        elif args.column in ("agent", "agents", "user_agent", "ua"):
            values = [r.get("user_agent", "") for r in records if r.get("user_agent")]
        elif args.column in ("method", "methods"):
            values = [r.get("request", "").split()[0] for r in records if r.get("request")]
        else:
            values = [r.get(args.column, "") for r in records if r.get(args.column)]

        counter = Counter(values)
        print(f"  Top {min(args.limit, len(counter))} by '{args.column}':")
        for value, count in counter.most_common(args.limit):
            bar = "#" * min(count, 50)
            print(f"    {count:>6d}  {str(value)[:60]:60s}  {bar}")

    elif args.command == "timeline":
        filtered = records
        if args.from_ts:
            filtered = [r for r in filtered if r.get("timestamp", "") >= args.from_ts]
        if args.to_ts:
            filtered = [r for r in filtered if r.get("timestamp", "") <= args.to_ts]
        print(f"[OK] Timeline filter: {len(filtered)} records in range")
        if filtered:
            print(f"  First: {filtered[0].get('timestamp', 'N/A')}")
            print(f"  Last:  {filtered[-1].get('timestamp', 'N/A')}")

    elif args.command == "report":
        out = generate_report(records, args.output, args.title)
        size = os.path.getsize(out)
        print(f"[OK] Report saved to {out} ({size:,} bytes)")


if __name__ == "__main__":
    main()
