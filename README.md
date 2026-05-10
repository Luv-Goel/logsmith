# Logsmith — Log File Forensics Toolkit

<div align="center">

**Parse, analyze, search, and visualize log files from the command line.**

[![CI](https://github.com/Luv-Goel/logsmith/actions/workflows/ci.yml/badge.svg)](https://github.com/Luv-Goel/logsmith/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue?logo=python)](https://github.com/Luv-Goel/logsmith)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Luv-Goel/logsmith?style=social)](https://github.com/Luv-Goel/logsmith/stargazers)

**Zero API keys. Zero dependencies. Pure Python.**

</div>

---

## Why Logsmith?

Logs are everywhere — web servers, applications, containers, systems. But analyzing them usually means:

- `grep` — powerful but loses structure
- ELK/Grafana — heavy infrastructure for simple tasks
- Writing custom scripts — every time, from scratch

Logsmith is the middle ground: a single CLI that parses, analyzes, and visualizes logs. No setup, no dependencies, no cloud.

## Quick Start

```bash
pip install logsmith

# Parse and analyze web server logs
logsmith stats access.log

# Detect anomalies
logsmith anomalies access.log

# Search with context
logsmith search "error" --context 2 system.log

# Top talkers
logsmith top ips -n 10 access.log

# Generate HTML report
logsmith report access.log -o report.html

# Timeline filter
logsmith timeline --from "2024-01-01" access.log
```

## Commands

| Command | Description |
|---------|-------------|
| `logsmith parse file` | Parse logs into structured records |
| `logsmith stats file` | Summary statistics with ASCII charts |
| `logsmith anomalies file` | Detect traffic spikes, error rates, rapid requests |
| `logsmith search pattern file` | Context-aware regex search with --context |
| `logsmith top col file` | Top values by column (ip, path, status, method, agent) |
| `logsmith timeline file` | Filter records by time range |
| `logsmith report file` | Generate HTML forensic report |

## Supported Formats

| Format | Auto-detect | Description |
|--------|-------------|-------------|
| Apache Common | Yes | `IP ident user [date] "request" status size` |
| Apache Combined | Yes | Common + Referer + User-Agent |
| Nginx Combined | Yes | Same as Apache Combined |
| Syslog RFC 3164 | Yes | `<pri>timestamp hostname message` |
| Syslog RFC 5424 | Yes | `<pri>version timestamp hostname appname procid msgid data` |
| JSON Lines | Yes | One JSON object per line |
| Any format | — | Auto-detected from sample lines |

## Example Output

```
$ logsmith stats access.log
========================================================
  Log Analysis Summary
========================================================
  Total lines:    15000
  Parsed:         14892
  Parse errors:   108

  First entry:    10/Oct/2024:13:55:36 -0700
  Last entry:     10/Oct/2024:14:55:36 -0700

  Unique IPs:     342
  Top IPs:
    192.168.1.100        2345
    10.0.0.50            1890
    ...

  Status codes:
    200: 12000  ########################################
    301: 1500   ######
    404: 300    #
    500: 108

  Errors (4xx+5xx): 408 (2.7%)
```

## Project Structure

```
logsmith/
├── logsmith/
│   ├── cli.py       # 7 CLI subcommands
│   ├── parsers.py   # Apache, syslog, JSON-Lines parsers
│   ├── analysis.py  # Stats, anomaly detection, timeline
│   ├── search.py    # Context-aware regex search
│   └── report.py    # HTML report with ASCII bar charts
├── pyproject.toml
└── README.md
```

**Pure Python, zero external dependencies.** Works on Python 3.8+.

---

*Built by [ClawWorks Engineering Inc.](https://github.com/Luv-Goel) — 6 projects/day, no excuses.*
