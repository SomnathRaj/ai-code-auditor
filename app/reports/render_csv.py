"""CSV export of the technical report: one row per finding.

Cells that a spreadsheet would treat as a formula (=, +, -, @, tab, CR) are prefixed
with an apostrophe — finding text comes from audited repositories (CSV injection)."""
import csv
import io

COLUMNS = ["id", "severity", "status", "title", "category", "rule_id", "scanner", "file", "line_start", "line_end",
           "function", "cwe", "owasp", "confidence", "ai_verdict", "ai_confidence", "ai_false_positive_probability",
           "package", "current_version", "recommended_version", "description", "recommendation"]
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _safe(value) -> str:
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def render(report: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for f in report["findings"]:
        ev = f.get("evidence") or {}
        row = {**f, "package": ev.get("package"), "current_version": ev.get("current_version"),
               "recommended_version": ev.get("recommended_version")}
        writer.writerow([_safe(row.get(c)) for c in COLUMNS])
    return "﻿" + buf.getvalue()  # BOM so Excel opens UTF-8 correctly
