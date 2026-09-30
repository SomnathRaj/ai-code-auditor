"""Report model (PRD §48): one structure, rendered as JSON, HTML, PDF and CSV.

technical — every finding (location, code excerpt, evidence, CWE/OWASP, fix, AI analysis),
            plus vulnerable dependencies. Accepts the same filters as the findings list.
executive — for technical leads: risk summary, critical/high items, grouped
            recommendations, trend and change since the previous audit.
"""
from collections import Counter, defaultdict

from bson import ObjectId

from ..constants import OPEN_FINDING_STATUSES
from ..db import get_db
from ..db.utils import id_str, iso, utcnow
from ..services.finding_service import SEVERITY_RANK, build_query
from ..services.scoring import empty_counts

REPORT_VERSION = 1
TOP_RISKS = 10
TOP_RECOMMENDATIONS = 8
TREND_AUDITS = 10

SCORE_NOTE = ("The security score (100 minus weighted open findings) is a project-management indicator, "
              "not proof that the code is secure.")
AI_NOTE = ("AI analysis (Google Gemini) is advisory: it never changes a finding's status or severity. "
           "Findings are confirmed or dismissed by people.")


def _finding(f: dict, detailed: bool) -> dict:
    loc = f.get("location") or {}
    ai = f.get("ai_analysis") or {}
    item = {
        "id": id_str(f["_id"]),
        "severity": f["severity"],
        "status": f["status"],
        "title": f["title"],
        "category": f.get("category"),
        "rule_id": f.get("rule_id"),
        "scanner": f.get("scanner"),
        "confidence": f.get("confidence"),
        "file": loc.get("file"),
        "line_start": loc.get("line_start"),
        "line_end": loc.get("line_end"),
        "function": loc.get("function"),
        "cwe": f.get("cwe"),
        "owasp": f.get("owasp"),
        "ai_verdict": ai.get("verdict"),
        "ai_confidence": ai.get("confidence"),
        "ai_false_positive_probability": ai.get("false_positive_probability"),
    }
    if detailed:
        raw = f.get("raw") or {}
        item.update({
            "description": f.get("description"),
            "impact": f.get("impact"),
            "recommendation": f.get("recommendation"),
            "code_snippet": f.get("code_snippet"),
            "snippet_start_line": f.get("snippet_start_line"),
            "references": [r for r in f.get("references") or [] if isinstance(r, str) and r.startswith("https://")],
            "evidence": {k: raw.get(k) for k in ("package", "ecosystem", "current_version", "affected_range",
                                                 "vulnerability", "aliases", "cvss_score", "recommended_version")
                         if raw.get(k) is not None} if f.get("scanner") == "osv" else {},
            "ai_analysis": {k: ai.get(k) for k in ("verdict", "confidence", "false_positive_probability", "severity",
                                                   "explanation", "impact", "attack_scenario", "recommendation",
                                                   "fixed_code", "missing_context", "model")
                            if ai.get(k) not in (None, "", [])} if ai.get("status") == "completed" else None,
            "status_history": [{"status": h.get("status"), "from": h.get("from"), "comment": h.get("comment"),
                                "at": iso(h.get("at"))} for h in f.get("status_history") or []],
        })
    return item


def _sort_key(f: dict):
    loc = f.get("location") or {}
    return (-SEVERITY_RANK.get(f["severity"], 0), loc.get("file") or "", loc.get("line_start") or 0)


def _trend(org_id: ObjectId, repo_id: ObjectId, upto: dict) -> list[dict]:
    audits = list(get_db().audits.find(
        {"organization_id": org_id, "repository_id": repo_id, "status": "completed",
         "created_at": {"$lte": upto["created_at"]}},
        {"audit_number": 1, "completed_at": 1, "summary.counts": 1, "summary.security_score": 1},
    ).sort("created_at", -1).limit(TREND_AUDITS))
    return [{"audit": f"AUD-{a['audit_number']}", "completed_at": iso(a.get("completed_at")),
             "open_findings": sum(((a.get("summary") or {}).get("counts") or {}).values()),
             "security_score": (a.get("summary") or {}).get("security_score")} for a in reversed(audits)]


def _recommendations(open_findings: list[dict]) -> list[dict]:
    """Group open findings: code issues by rule ('Fix 12 SQL-injection issues in 4 files'),
    dependency advisories by package ('Upgrade requests to 2.33.0: fixes 4 advisories')."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in open_findings:
        raw = f.get("raw") or {}
        key = f"pkg:{raw.get('ecosystem')}:{raw.get('package')}" if f.get("scanner") == "osv" and raw.get("package") \
            else f.get("rule_id") or f["title"]
        groups[key].append(f)
    out = []
    for rule, items in groups.items():
        worst = min(items, key=_sort_key)
        if rule.startswith("pkg:"):
            raw = worst.get("raw") or {}
            target = next((i.get("raw", {}).get("recommended_version") for i in items
                           if i.get("raw", {}).get("recommended_version")), None)
            out.append({
                "title": f"Upgrade {raw.get('package')} {raw.get('current_version')}" + (f" to {target}" if target else ""),
                "rule_id": rule, "category": "Dependencies", "severity": worst["severity"], "count": len(items),
                "files": [(worst.get("location") or {}).get("file")], "file_count": 1,
                "recommendation": f"Fixes {len(items)} known advisor{'y' if len(items) == 1 else 'ies'}: "
                                  + ", ".join(i.get("rule_id") or "" for i in items[:6]) + ("…" if len(items) > 6 else ""),
            })
            continue
        files = sorted({(i.get("location") or {}).get("file") for i in items if (i.get("location") or {}).get("file")})
        out.append({
            "title": worst["title"], "rule_id": rule, "category": worst.get("category"), "severity": worst["severity"],
            "count": len(items), "files": files[:10], "file_count": len(files),
            "recommendation": worst.get("recommendation") or "",
        })
    out.sort(key=lambda r: (-SEVERITY_RANK.get(r["severity"], 0), -r["count"]))
    return out[:TOP_RECOMMENDATIONS]


def build_report(audit: dict, report_type: str, args=None, comparison: dict | None = None) -> dict:
    db = get_db()
    org_id = audit["organization_id"]
    repo = db.repositories.find_one({"_id": audit["repository_id"], "organization_id": org_id}) or {}
    org = db.organizations.find_one({"_id": org_id}, {"name": 1}) or {}
    summary = audit.get("summary") or {}

    all_findings = list(db.findings.find({"organization_id": org_id, "audit_id": audit["_id"]},
                                         {"code_context": 0}))
    open_findings = sorted((f for f in all_findings if f["status"] in OPEN_FINDING_STATUSES), key=_sort_key)
    counts = empty_counts()
    for f in open_findings:
        counts[f["severity"]] += 1

    report = {
        "report": {"type": report_type, "version": REPORT_VERSION, "generated_at": iso(utcnow()),
                   "generator": "AI Code Auditor"},
        "organization": {"name": org.get("name")},
        "repository": {"id": id_str(repo.get("_id")), "name": repo.get("name"), "provider": repo.get("provider"),
                       "url": repo.get("url")},
        "audit": {
            "id": id_str(audit["_id"]), "display_id": f"AUD-{audit['audit_number']}",
            "type": audit.get("audit_type"), "branch": audit.get("branch"), "commit": audit.get("commit_hash"),
            "started_at": iso(audit.get("started_at")), "completed_at": iso(audit.get("completed_at")),
            "scanner_versions": audit.get("scanner_versions") or {},
            "enabled_scanners": (audit.get("settings") or {}).get("enabled_scanners"),
        },
        "summary": {
            "security_score": summary.get("security_score"),
            "open_counts": counts,
            "open_findings": len(open_findings),
            "total_findings": len(all_findings),
            "by_status": dict(Counter(f["status"] for f in all_findings)),
            "by_category": dict(Counter(f.get("category") or "Other" for f in open_findings).most_common()),
            "by_scanner": dict(Counter(f.get("scanner") for f in all_findings)),
            "primary_language": summary.get("primary_language"),
            "frameworks": summary.get("frameworks") or [],
            "file_count": summary.get("file_count"),
            "dependency_count": summary.get("dependency_count"),
            "vulnerable_dependency_count": summary.get("vulnerable_dependency_count"),
            "ai": {k: (summary.get("ai") or {}).get(k) for k in ("status", "model", "analyzed", "cached",
                                                                 "likely_false_positives")},
            "scanner_errors": [e.get("message") for e in summary.get("scanner_errors") or []],
        },
        "notes": [SCORE_NOTE, AI_NOTE],
    }

    if report_type == "executive":
        risks = [f for f in open_findings if f["severity"] in ("critical", "high")][:TOP_RISKS]
        report["top_risks"] = [_finding(f, detailed=False) | {"recommendation": f.get("recommendation")}
                               for f in risks]
        report["recommendations"] = _recommendations(open_findings)
        report["trend"] = _trend(org_id, audit["repository_id"], audit)
        report["change_since_previous"] = comparison["counts"] if comparison else None
        report["previous_audit"] = comparison["base"]["display_id"] if comparison else None
        return report

    # technical
    selected = all_findings
    if args is not None and any(args.get(k) for k in ("severity", "status", "category", "scanner", "ai_verdict",
                                                       "file", "q")):
        wanted = {f["_id"] for f in db.findings.find(build_query(org_id, audit["_id"], args), {"_id": 1})}
        selected = [f for f in all_findings if f["_id"] in wanted]
    report["findings"] = [_finding(f, detailed=True) for f in sorted(selected, key=_sort_key)]
    report["filters"] = {k: args.get(k) for k in ("severity", "status", "category", "scanner", "ai_verdict",
                                                   "file", "q") if args is not None and args.get(k)}
    deps = db.dependencies.find({"organization_id": org_id, "audit_id": audit["_id"], "vulnerable": True})
    report["vulnerable_dependencies"] = sorted((
        {"package": d["package_name"], "version": d.get("version"), "ecosystem": d["ecosystem"],
         "manifest": d["manifest"], "max_severity": d.get("max_severity"),
         "recommended_version": d.get("recommended_version"),
         "vulnerabilities": [v["id"] for v in d.get("vulnerabilities", [])]} for d in deps),
        key=lambda d: (-SEVERITY_RANK.get(d["max_severity"] or "info", 0), d["package"]))
    return report

