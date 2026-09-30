"""PDF report with ReportLab (BSD). Paragraph text is XML-escaped (ReportLab parses a
mini-markup, and finding text is untrusted); code goes into Preformatted blocks."""
import io
import os
from datetime import datetime
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

_FONT_DIR = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
_registered = False
SEV = {"critical": "#c62828", "high": "#d84315", "medium": "#a66f00", "low": "#1565c0", "info": "#546e7a"}
MAX_CODE_COLS = 110
MUTED = colors.HexColor("#5b6573")


def when(iso_value) -> str:
    """'2026-09-30T08:12:16Z' → '30 Sep 2026 08:12 UTC' (reports are read, not parsed)."""
    if not iso_value:
        return "—"
    try:
        return datetime.fromisoformat(str(iso_value).replace("Z", "+00:00")).strftime("%d %b %Y %H:%M UTC")
    except ValueError:
        return str(iso_value)


def _fonts() -> tuple[str, str]:
    """Vera (bundled with ReportLab) covers far more characters than the base-14 fonts."""
    global _registered
    if not _registered:
        pdfmetrics.registerFont(TTFont("Vera", os.path.join(_FONT_DIR, "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("Vera-Bold", os.path.join(_FONT_DIR, "VeraBd.ttf")))
        _registered = True
    return "Vera", "Vera-Bold"


def _styles():
    regular, bold = _fonts()
    return {
        "title": ParagraphStyle("title", fontName=bold, fontSize=18, leading=22, spaceAfter=4),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=13, leading=16, spaceBefore=12, spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName=bold, fontSize=10.5, leading=13, spaceAfter=2),
        "body": ParagraphStyle("body", fontName=regular, fontSize=9, leading=12, alignment=TA_LEFT),
        "muted": ParagraphStyle("muted", fontName=regular, fontSize=8, leading=10.5, textColor=MUTED),
        "code": ParagraphStyle("code", fontName="Courier", fontSize=7, leading=8.6, backColor=colors.HexColor("#f5f7fa"),
                               borderPadding=4, leftIndent=2),
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape("" if text is None else str(text)).replace("\n", "<br/>"), style)


def _code(text: str) -> str:
    """Courier is Latin-1 only; replace other characters and wrap very long lines."""
    out = []
    for line in text.splitlines():
        line = line.encode("latin-1", "replace").decode("latin-1").replace("\t", "    ")
        while len(line) > MAX_CODE_COLS:
            out.append(line[:MAX_CODE_COLS])
            line = "      ... " + line[MAX_CODE_COLS:]
        out.append(line)
    return "\n".join(out)


def _sev_label(sev: str, st) -> Paragraph:
    return Paragraph(f'<font color="{SEV.get(sev, "#546e7a")}"><b>{escape(sev.upper())}</b></font>', st["body"])


def _table(rows, widths, st, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (-1, -1), "Vera"),
             ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e5ec")),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("FONTNAME", (0, 0), (-1, 0), "Vera-Bold"), ("TEXTCOLOR", (0, 0), (-1, 0), MUTED)]
    t.setStyle(TableStyle(style))
    return t


def _pct(x):
    return "—" if x is None else f"{round(x * 100)}%"


def render(r: dict) -> bytes:
    st = _styles()
    buf = io.BytesIO()
    kind = r["report"]["type"]
    repo, a, s = r["repository"], r["audit"], r["summary"]
    title = f"{'Executive' if kind == 'executive' else 'Technical'} security report"
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"{title} — {repo.get('name')}", author="AI Code Auditor")
    width = doc.width
    story = [_p(title, st["title"]), _p(f"{repo.get('name')} · {a['display_id']}"
                                        + (f" · branch {a['branch']}" if repo.get("provider") == "github" else " · ZIP upload")
                                        + (f" · commit {a['commit'][:10]}" if a.get("commit") else "")
                                        + f" · completed {when(a['completed_at'])}", st["muted"]), Spacer(1, 8)]
    counts = s["open_counts"]
    story.append(_table([["Score", "Critical", "High", "Medium", "Low", "Open / total"],
                         [f"{s['security_score']}/100" if s["security_score"] is not None else "—", counts["critical"],
                          counts["high"], counts["medium"], counts["low"], f"{s['open_findings']} / {s['total_findings']}"]],
                        [width / 6] * 6, st))
    story.append(_p(f"Stack: {' / '.join(s['frameworks'] + [s['primary_language'] or ''])} · "
                    f"dependencies: {s['dependency_count']} ({s['vulnerable_dependency_count']} vulnerable) · "
                    f"generated {when(r['report']['generated_at'])}", st["muted"]))

    if kind == "executive":
        change = r.get("change_since_previous")
        if change:
            story += [_p(f"Change since {r['previous_audit']}", st["h2"]),
                      _p(f"{change['new']} new · {change['resolved']} resolved · {change['reopened']} reopened · "
                         f"{change['unchanged']} unchanged", st["body"])]
        story.append(_p("Top risks", st["h2"]))
        if r["top_risks"]:
            rows = [["Severity", "Issue", "Location", "AI"]] + [
                [_sev_label(f["severity"], st), _p(f"{f['title']}\n{f.get('recommendation') or ''}", st["body"]),
                 _p(f"{f['file']}:{f['line_start']}", st["muted"]), _p((f.get("ai_verdict") or "—").replace("_", " "), st["muted"])]
                for f in r["top_risks"]]
            story.append(_table(rows, [width * 0.12, width * 0.5, width * 0.25, width * 0.13], st))
        else:
            story.append(_p("No open critical or high findings.", st["body"]))
        story.append(_p("Recommendations", st["h2"]))
        for i, x in enumerate(r["recommendations"], 1):
            story.append(_p(f"{i}. {x['title']} ({x['severity']}) — {x['count']} finding(s) in {x['file_count']} file(s). "
                            f"{x['recommendation']}", st["body"]))
            story.append(Spacer(1, 3))
        if r.get("trend"):
            story.append(_p("Trend", st["h2"]))
            story.append(_table([["Audit", "Completed", "Open findings", "Score"]] +
                                [[t["audit"], when(t["completed_at"]), t["open_findings"], t["security_score"]]
                                 for t in r["trend"]], [width / 4] * 4, st))
    else:
        if r.get("filters"):
            story.append(_p("Filtered: " + ", ".join(f"{k}={v}" for k, v in r["filters"].items()), st["muted"]))
        story.append(_p(f"Findings ({len(r['findings'])})", st["h2"]))
        for f in r["findings"]:
            block = [Paragraph(f'<font color="{SEV.get(f["severity"], "#546e7a")}"><b>{escape(f["severity"].upper())}</b></font> '
                               f'{escape(f["title"])}', st["h3"]),
                     _p(f"{f['file']}:{f['line_start']}" + (f" in {f['function']}()" if f.get("function") else "")
                        + f" · {f.get('category')} · {f.get('rule_id')} · status: {f['status'].replace('_', ' ')}"
                        + (f" · {f['cwe']}" if f.get("cwe") else "") + (f" · OWASP {f['owasp']}" if f.get("owasp") else ""),
                        st["muted"])]
            if f.get("description"):
                block.append(_p(f["description"], st["body"]))
            if f.get("code_snippet"):
                start = f.get("snippet_start_line") or 1
                numbered = "\n".join(f"{start + i:>5}  {line}" for i, line in enumerate(f["code_snippet"].splitlines()))
                block.append(Preformatted(_code(numbered), st["code"]))
            ev = f.get("evidence") or {}
            if ev:
                block.append(_p("; ".join(f"{k.replace('_', ' ')}: {', '.join(v) if isinstance(v, list) else v}"
                                          for k, v in ev.items()), st["muted"]))
            if f.get("recommendation"):
                block.append(_p(f"Recommendation: {f['recommendation']}", st["body"]))
            ai = f.get("ai_analysis")
            if ai:
                verdict = {"true_positive": "likely a real issue", "false_positive": "likely a false positive",
                           "needs_more_context": "needs more context"}.get(ai.get("verdict"), ai.get("verdict"))
                block.append(_p(f"AI ({ai.get('model')}): {verdict} — confidence {_pct(ai.get('confidence'))}. "
                                f"{ai.get('explanation') or ''}", st["body"]))
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))  # blocks taller than a page are split normally
        deps = r.get("vulnerable_dependencies") or []
        if deps:
            story.append(_p("Vulnerable dependencies", st["h2"]))
            story.append(_table([["Package", "Version", "Severity", "Upgrade to", "Advisories"]] + [
                [_p(f"{d['package']} ({d['ecosystem']})", st["body"]), d["version"] or "", _sev_label(d["max_severity"] or "info", st),
                 d["recommended_version"] or "—", _p(", ".join(d["vulnerabilities"]), st["muted"])] for d in deps],
                [width * 0.28, width * 0.12, width * 0.12, width * 0.14, width * 0.34], st))
    story.append(Spacer(1, 12))
    story += [_p(n, st["muted"]) for n in r["notes"]]

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Vera", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(16 * mm, 9 * mm, f"AI Code Auditor · {repo.get('name')} · {a['display_id']}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
