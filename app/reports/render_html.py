"""Self-contained, printable HTML report. Every value is escaped: finding text and code
come from audited repositories and are untrusted. A CSP meta tag blocks scripts even
when the file is opened locally."""
from datetime import datetime
from html import escape

SEV_COLORS = {"critical": "#c62828", "high": "#d84315", "medium": "#a66f00", "low": "#1565c0", "info": "#546e7a"}

CSS = """
*{box-sizing:border-box} body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1d232b;
margin:0;background:#fff} main{max-width:1000px;margin:0 auto;padding:32px 24px}
h1{font-size:24px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #d8dee6;padding-bottom:6px}
h3{font-size:15px;margin:0 0 6px} .muted{color:#5b6573} .small{font-size:12px}
table{border-collapse:collapse;width:100%;margin:6px 0 12px} th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e6eaf0;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#5b6573}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:12px 0}
.kpi{border:1px solid #e0e5ec;border-radius:8px;padding:10px 12px} .kpi b{display:block;font-size:22px}
.sev{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff;border-radius:999px;padding:1px 8px}
.finding{border:1px solid #e0e5ec;border-radius:8px;padding:14px 16px;margin:12px 0;break-inside:avoid}
pre{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f5f7fa;border:1px solid #e6eaf0;
border-radius:6px;padding:10px;overflow-x:auto;white-space:pre} .ai{background:#f3f6ff;border-left:3px solid #4f6fd8;padding:8px 12px;margin:8px 0}
dl{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin:8px 0} dt{color:#5b6573} dd{margin:0}
.notes{font-size:12px;color:#5b6573;border-top:1px solid #d8dee6;margin-top:28px;padding-top:10px}
@media print{main{padding:0} .finding{page-break-inside:avoid} a{color:inherit}}
"""


def when(iso_value) -> str:
    """'2026-09-30T08:12:16Z' → '30 Sep 2026 08:12 UTC' (reports are read, not parsed)."""
    if not iso_value:
        return "—"
    try:
        return datetime.fromisoformat(str(iso_value).replace("Z", "+00:00")).strftime("%d %b %Y %H:%M UTC")
    except ValueError:
        return str(iso_value)


def _e(v) -> str:
    return escape("" if v is None else str(v))


def _sev(s: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLORS.get(s, "#546e7a")}">{_e(s)}</span>'


def _pct(x) -> str:
    return "—" if x is None else f"{round(x * 100)}%"


def _header(r: dict, title: str) -> str:
    a, repo, s = r["audit"], r["repository"], r["summary"]
    counts = s["open_counts"]
    kpis = "".join(f'<div class="kpi"><span class="small muted">{_e(k.upper())}</span><b>{_e(v)}</b></div>'
                   for k, v in (("Score", f"{s['security_score']}/100" if s["security_score"] is not None else "—"),
                                ("Critical", counts["critical"]), ("High", counts["high"]),
                                ("Medium", counts["medium"]), ("Low", counts["low"])))
    meta = " · ".join(_e(x) for x in (repo.get("name"), a["display_id"],
                                       f"branch {a['branch']}" if repo.get("provider") == "github" else "ZIP upload",
                                       f"commit {a['commit'][:10]}" if a.get("commit") else None,
                                       f"completed {when(a['completed_at'])}") if x)
    return (f"<h1>{_e(title)}</h1><p class='muted'>{meta}</p><div class='kpis'>{kpis}</div>"
            f"<p class='small muted'>{s['open_findings']} open of {s['total_findings']} findings · "
            f"stack: {_e(' / '.join(s['frameworks'] + [s['primary_language'] or '']).strip(' /'))} · "
            f"{_e(s['dependency_count'])} dependencies ({_e(s['vulnerable_dependency_count'])} vulnerable) · "
            f"generated {_e(when(r['report']['generated_at']))}</p>")


def _finding_html(f: dict) -> str:
    loc = f"{f['file']}:{f['line_start']}" if f.get("line_start") else (f.get("file") or "")
    parts = [f"<div class='finding'><h3>{_sev(f['severity'])} {_e(f['title'])}</h3>",
             f"<p class='small muted'>{_e(loc)}{' in ' + _e(f['function']) + '()' if f.get('function') else ''} · "
             f"{_e(f.get('category'))} · {_e(f.get('rule_id'))} · status: {_e(f['status'].replace('_', ' '))}"
             f"{' · ' + _e(f['cwe']) if f.get('cwe') else ''}{' · OWASP ' + _e(f['owasp']) if f.get('owasp') else ''}</p>"]
    if f.get("description"):
        parts.append(f"<p>{_e(f['description'])}</p>")
    if f.get("code_snippet"):
        start = f.get("snippet_start_line") or 1
        numbered = "\n".join(f"{start + i:>5}  {line}" for i, line in enumerate(f["code_snippet"].splitlines()))
        parts.append(f"<pre>{_e(numbered)}</pre>")
    ev = f.get("evidence") or {}
    if ev:
        parts.append("<dl>" + "".join(f"<dt>{_e(k.replace('_', ' ').capitalize())}</dt><dd>{_e(', '.join(v) if isinstance(v, list) else v)}</dd>"
                                      for k, v in ev.items()) + "</dl>")
    if f.get("recommendation"):
        parts.append(f"<p><b>Recommendation:</b> {_e(f['recommendation'])}</p>")
    ai = f.get("ai_analysis")
    if ai:
        verdict = {"true_positive": "Likely a real issue", "false_positive": "Likely a false positive",
                   "needs_more_context": "Needs more context"}.get(ai.get("verdict"), ai.get("verdict"))
        parts.append(f"<div class='ai'><b>AI ({_e(ai.get('model'))}): {_e(verdict)}</b> "
                     f"<span class='small muted'>confidence {_pct(ai.get('confidence'))}, "
                     f"false-positive probability {_pct(ai.get('false_positive_probability'))}</span>"
                     f"<p>{_e(ai.get('explanation'))}</p>"
                     + (f"<p><b>Impact:</b> {_e(ai['impact'])}</p>" if ai.get("impact") else "")
                     + (f"<p><b>Suggested fix:</b> {_e(ai['recommendation'])}</p>" if ai.get("recommendation") else "")
                     + (f"<pre>{_e(ai['fixed_code'])}</pre>" if ai.get("fixed_code") else "") + "</div>")
    refs = f.get("references") or []
    if refs:
        parts.append("<p class='small'>References: " + ", ".join(f'<a href="{_e(u)}" rel="noreferrer">{_e(u)}</a>' for u in refs) + "</p>")
    parts.append("</div>")
    return "".join(parts)


def _page(title: str, body: str) -> str:
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>")


def render(r: dict) -> str:
    kind = r["report"]["type"]
    title = f"{'Executive' if kind == 'executive' else 'Technical'} security report — {r['repository'].get('name')}"
    body = [_header(r, title)]
    if kind == "executive":
        change = r.get("change_since_previous")
        if change:
            body.append(f"<h2>Change since {_e(r['previous_audit'])}</h2><p>{change['new']} new · {change['resolved']} resolved · "
                        f"{change['reopened']} reopened · {change['unchanged']} unchanged</p>")
        body.append("<h2>Top risks</h2>")
        if r["top_risks"]:
            body.append("<table><tr><th>Severity</th><th>Issue</th><th>Location</th><th>AI</th></tr>" + "".join(
                f"<tr><td>{_sev(f['severity'])}</td><td>{_e(f['title'])}<div class='small muted'>{_e(f.get('recommendation'))}</div></td>"
                f"<td class='small'>{_e(f['file'])}:{_e(f['line_start'])}</td><td class='small'>{_e((f.get('ai_verdict') or '—').replace('_', ' '))}</td></tr>"
                for f in r["top_risks"]) + "</table>")
        else:
            body.append("<p>No open critical or high findings.</p>")
        body.append("<h2>Recommendations</h2><ol>" + "".join(
            f"<li><b>{_e(x['title'])}</b> ({_sev(x['severity'])}) — {x['count']} finding(s) in {x['file_count']} file(s). "
            f"{_e(x['recommendation'])}</li>" for x in r["recommendations"]) + "</ol>")
        if r.get("trend"):
            body.append("<h2>Trend</h2><table><tr><th>Audit</th><th>Completed</th><th>Open findings</th><th>Score</th></tr>" + "".join(
                f"<tr><td>{_e(t['audit'])}</td><td>{_e(when(t['completed_at']))}</td><td>{_e(t['open_findings'])}</td><td>{_e(t['security_score'])}</td></tr>"
                for t in r["trend"]) + "</table>")
        cats = r["summary"]["by_category"]
        if cats:
            body.append("<h2>Open findings by category</h2><table>" + "".join(
                f"<tr><td>{_e(c)}</td><td>{_e(n)}</td></tr>" for c, n in cats.items()) + "</table>")
    else:
        if r.get("filters"):
            body.append(f"<p class='small muted'>Filtered: {_e(', '.join(f'{k}={v}' for k, v in r['filters'].items()))}</p>")
        body.append(f"<h2>Findings ({len(r['findings'])})</h2>")
        body.extend(_finding_html(f) for f in r["findings"])
        deps = r.get("vulnerable_dependencies") or []
        if deps:
            body.append("<h2>Vulnerable dependencies</h2><table><tr><th>Package</th><th>Version</th><th>Severity</th><th>Upgrade to</th><th>Advisories</th></tr>" + "".join(
                f"<tr><td>{_e(d['package'])} <span class='small muted'>{_e(d['ecosystem'])}</span></td><td>{_e(d['version'])}</td>"
                f"<td>{_sev(d['max_severity'] or 'info')}</td><td>{_e(d['recommended_version'] or '—')}</td><td class='small'>{_e(', '.join(d['vulnerabilities']))}</td></tr>"
                for d in deps) + "</table>")
    body.append("<div class='notes'>" + "".join(f"<p>{_e(n)}</p>" for n in r["notes"]) + "</div>")
    return _page(title, "".join(body))
