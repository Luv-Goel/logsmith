"""Context-aware search for Logsmith."""

import re
from typing import List, Dict, Any, Optional


def search_logs(records: List[Dict], pattern: str, context: int = 0,
                case_sensitive: bool = False, column: Optional[str] = None) -> List[Dict]:
    """Search log records for a pattern with context."""
    compiled = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
    results = []

    for i, record in enumerate(records):
        if column:
            text = str(record.get(column, ""))
        else:
            text = str(record)

        if compiled.search(text):
            # Get context
            ctx_lines = []
            start = max(0, i - context)
            end = min(len(records), i + context + 1)

            for j in range(start, end):
                entry = {
                    "record": records[j],
                    "is_match": j == i,
                    "offset": j - i,
                }
                ctx_lines.append(entry)

            results.append({
                "line": i + 1,
                "record": record,
                "context": ctx_lines,
            })

    return results


def grep_logs(records: List[Dict], pattern: str, context: int = 0) -> str:
    """Search and format results like grep."""
    matches = search_logs(records, pattern, context)
    lines = []

    for m in matches:
        if context > 0:
            for ctx in m["context"]:
                prefix = ":" if ctx["is_match"] else "-"
                offset = ctx["offset"]
                record_str = str(ctx["record"])
                lines.append(f"  {m['line'] + offset}{prefix} {record_str[:200]}")
            lines.append("  --")
        else:
            record_str = str(m["record"])
            lines.append(f"  {m['line']}: {record_str[:200]}")

    return "\n".join(lines)
