"""Log format parsers for Logsmith."""

import re
from typing import List, Dict, Any, Optional, Pattern


# Apache common log format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
APACHE_COMMON_PATTERN = re.compile(
    r'(\S+)\s+'           # IP
    r'(\S+)\s+'           # ident
    r'(\S+)\s+'           # user
    r'\[([^\]]+)\]\s+'    # datetime
    r'"([^"]*)"\s+'       # request
    r'(\d+)\s+'           # status
    r'(\S+)'              # size
)

# Apache combined log format (common + referer + user-agent)
APACHE_COMBINED_PATTERN = re.compile(
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"([^"]*)"\s+'
    r'(\d+)\s+'
    r'(\S+)\s+'
    r'"([^"]*)"\s+'       # referer
    r'"([^"]*)"'          # user-agent
)

# Nginx combined log (same as Apache combined)
NGINX_PATTERN = APACHE_COMBINED_PATTERN

# Syslog (RFC 3164) — partial match
# <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
SYSLOG_3164_PATTERN = re.compile(
    r'<(\d+)>?'                     # priority (optional)
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+)'  # timestamp
    r'\s+(\S+)\s+'                  # hostname
    r'(.*)'                          # message
)

# Syslog (RFC 5424)
# <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed
SYSLOG_5424_PATTERN = re.compile(
    r'<(\d+)>'                       # priority
    r'(\d+)\s+'                      # version
    r'(\S+)\s+'                      # timestamp ISO
    r'(\S+)\s+'                      # hostname
    r'(\S+)\s+'                      # appname
    r'(\S+)\s+'                      # procid
    r'(\S+)\s+'                      # msgid
    r'(.*)'                          # structured data + message
)

# JSON-lines (each line is a JSON object)
# No pattern, parsed as JSON

# CSV-lines (configurable delimiter)
# No pattern, parsed with csv module


def parse_apache_common(line: str) -> Optional[Dict[str, str]]:
    """Parse Apache common log format."""
    m = APACHE_COMMON_PATTERN.match(line)
    if not m:
        return None
    return {
        "ip": m.group(1),
        "ident": m.group(2),
        "user": m.group(3),
        "timestamp": m.group(4),
        "request": m.group(5),
        "status": m.group(6),
        "size": m.group(7),
    }


def parse_apache_combined(line: str) -> Optional[Dict[str, str]]:
    """Parse Apache combined log format."""
    m = APACHE_COMBINED_PATTERN.match(line)
    if not m:
        return None
    result = parse_apache_common(line)
    if result:
        result["referer"] = m.group(8)
        result["user_agent"] = m.group(9)
    return result


def parse_syslog_3164(line: str) -> Optional[Dict[str, str]]:
    """Parse syslog (RFC 3164)."""
    m = SYSLOG_3164_PATTERN.match(line)
    if not m:
        return None
    return {
        "priority": m.group(1) if m.group(1) else "",
        "timestamp": m.group(2).strip(),
        "hostname": m.group(3),
        "message": m.group(4),
    }


def parse_syslog_5424(line: str) -> Optional[Dict[str, str]]:
    """Parse syslog (RFC 5424)."""
    m = SYSLOG_5424_PATTERN.match(line)
    if not m:
        return None
    return {
        "priority": m.group(1),
        "version": m.group(2),
        "timestamp": m.group(3),
        "hostname": m.group(4),
        "appname": m.group(5),
        "procid": m.group(6),
        "msgid": m.group(7),
        "message": m.group(8),
    }


def detect_log_format(lines: List[str]) -> Optional[str]:
    """Auto-detect log format from sample lines."""
    if not lines:
        return None

    sample = "\n".join(lines[:5])

    if APACHE_COMBINED_PATTERN.match(sample):
        return "apache_combined"
    if APACHE_COMMON_PATTERN.match(sample):
        return "apache_common"
    if SYSLOG_5424_PATTERN.match(sample):
        return "syslog_5424"
    if SYSLOG_3164_PATTERN.match(sample):
        return "syslog_3164"

    # Try JSON
    for line in lines[:5]:
        line = line.strip()
        if line and line.startswith("{"):
            return "jsonl"

    return None


def parse_lines(lines: List[str], fmt: Optional[str] = None) -> List[Dict[str, Any]]:
    """Parse log lines in a given format or auto-detect."""
    if not lines:
        return []

    fmt = fmt or detect_log_format(lines)

    parsers = {
        "apache_common": parse_apache_common,
        "apache_combined": parse_apache_combined,
        "syslog_3164": parse_syslog_3164,
        "syslog_5424": parse_syslog_5424,
    }

    parser = parsers.get(fmt)
    if fmt == "jsonl":
        import json
        results = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    results.append({"_raw": line, "_error": "json_parse_error"})
        return results

    if not parser:
        # Try all parsers
        for name, fn in parsers.items():
            result = fn(lines[0])
            if result:
                parser = fn
                fmt = name
                break

    if not parser:
        return [{"_raw": line} for line in lines]

    results = []
    for line in lines:
        parsed = parser(line)
        if parsed:
            results.append(parsed)
        else:
            results.append({"_raw": line, "_error": "parse_error"})

    return results


def parse_file(path: str, fmt: Optional[str] = None) -> List[Dict[str, Any]]:
    """Parse a log file."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return parse_lines([l.rstrip("\n\r") for l in lines], fmt)
