# Logsmith ðŸ”

<div align="center">

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-lightgrey)]()

**Log file forensics and analysis toolkit â€” parse, search, analyze, and generate reports. Zero dependencies.**

</div>

---

## Features

- **Multi-format parsing** â€” Apache Common/Combined, Nginx, syslog (RFC 3164/5424), JSON-lines
- **Auto-detection** â€” Automatic log format identification
- **Statistical analysis** â€” Request counts, response codes, IP frequency, temporal patterns
- **Anomaly detection** â€” Spikes, error rate surges, unusual patterns
- **Pattern search** â€” Regex grep across parsed log fields
- **Timeline generation** â€” Chronological event sequencing
- **Top-N analysis** â€” Most frequent IPs, URLs, user agents, error codes
- **HTML reports** â€” Beautiful dark-mode reports with ASCII bar charts
- **Zero dependencies** â€” Pure Python 3.8+, stdlib only

## Quick Start

```bash
pip install logsmith

# Parse and display log file
logsmith parse access.log

# Get statistics
logsmith stats access.log

# Detect anomalies
logsmith anomalies access.log

# Search for patterns
logsmith search access.log --pattern "404|500"

# Top IPs
logsmith top access.log --field ip --limit 10

# Generate timeline
logsmith timeline access.log

# Full HTML report
logsmith report access.log --output report.html
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `logsmith parse [file]` | Parse and display log entries |
| `logsmith stats [file]` | Log statistics and summaries |
| `logsmith anomalies [file]` | Detect anomalies and spikes |
| `logsmith search [file]` | Search across parsed logs |
| `logsmith top [file]` | Top-N values by field |
| `logsmith timeline [file]` | Chronological event view |
| `logsmith report [file]` | Generate HTML analysis report |

## Supported Formats

| Format | Description |
|--------|-------------|
| Apache Common | `%h %l %u %t "%r" %>s %b` |
| Apache Combined | Common + Referer + User-Agent |
| Nginx Combined | Nginx combined log format |
| Syslog RFC 3164 | Traditional BSD syslog |
| Syslog RFC 5424 | Structured syslog format |
| JSON-lines | One JSON object per line |

## Architecture

```
logsmith/
â”œâ”€â”€ logsmith/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ cli.py       # CLI entry point
â”‚   â”œâ”€â”€ parsers.py   # Log format parsers
â”‚   â”œâ”€â”€ analysis.py  # Stats, anomalies, timeline
â”‚   â”œâ”€â”€ search.py    # Pattern search
â”‚   â””â”€â”€ report.py    # HTML report generation
â”œâ”€â”€ pyproject.toml
â””â”€â”€ README.md
```

## License

MIT â€” see [LICENSE](LICENSE).
