"""Findings: list with filters, detail, code viewer, triage (status lifecycle), comments.
PRD §31-§36, §43.4.
"""
import re
from datetime import timedelta

from bson import ObjectId
from pymongo import ReturnDocument

from ..constants import (
    FINDING_STATUSES, FINDING_TRANSITIONS, OPEN_FINDING_STATUSES, REASON_REQUIRED_STATUSES, SEVERITIES,
)
from ..db import get_db
from ..db.utils import id_str, iso, utcnow
from ..errors import ApiError
from ..scanners.detect import EXTENSIONS
from .audit_log import log_event
from .scoring import empty_counts, refresh_repository_snapshot, security_score

AI_VERDICTS = ("true_positive", "false_positive", "needs_more_context")
SORTS = {
    "severity": [("severity_rank", -1), ("location.file", 1), ("location.line_start", 1)],
    "file": [("location.file", 1), ("location.line_start", 1)],
    "confidence": [("confidence", -1), ("severity_rank", -1)],
    "ai_false_positive": [("ai_analysis.false_positive_probability", -1), ("severity_rank", -1)],
    "newest": [("created_at", -1)],
}
SEVERITY_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}  # critical=5 … info=1
VIEW_LOG_WINDOW = timedelta(minutes=10)


def _csv(value: str | None, allowed: tuple | None = None, name: str = "filter") -> list[str]:
    items = [v.strip() for v in (value or "").split(",") if v.strip()]
    if allowed is not None:
        bad = [v for v in items if v not in allowed]
        if bad:
            raise ApiError(400, "validation_error", f"Unknown {name}: {', '.join(bad)}", {name: "invalid"})
    return items


def build_query(org_id: ObjectId, audit_id: ObjectId, args) -> dict:
    """Mongo filter from query-string args: severity, status (or "open"), category, scanner, file,
    ai_verdict, q."""
    query: dict = {"organization_id": org_id, "audit_id": audit_id}
    if sev := _csv(args.get("severity"), SEVERITIES, "severity"):
        query["severity"] = {"$in": sev}
    statuses = _csv(args.get("status"), FINDING_STATUSES + ("open", "closed"), "status")
    if statuses:
        expanded = set()
        for s in statuses:
            if s == "open":
                expanded |= set(OPEN_FINDING_STATUSES)
            elif s == "closed":
                expanded |= set(FINDING_STATUSES) - set(OPEN_FINDING_STATUSES)
            else:
                expanded.add(s)
        query["status"] = {"$in": sorted(expanded)}
    if cats := _csv(args.get("category")):
        query["category"] = {"$in": cats}
    if scanners := _csv(args.get("scanner"), ("semgrep", "gitleaks", "osv"), "scanner"):
        query["scanner"] = {"$in": scanners}
    if verdicts := _csv(args.get("ai_verdict"), AI_VERDICTS + ("none",), "ai_verdict"):
        conds = []
        real = [v for v in verdicts if v != "none"]
        if real:
            conds.append({"ai_analysis.verdict": {"$in": real}})
        if "none" in verdicts:
            conds.append({"ai_analysis.verdict": {"$exists": False}})
        query["$or"] = conds
    if file := (args.get("file") or "").strip():
        query["location.file"] = {"$regex": re.escape(file[:300]), "$options": "i"}
    if q := (args.get("q") or "").strip():
        rx = {"$regex": re.escape(q[:200]), "$options": "i"}
        query.setdefault("$and", []).append({"$or": [{"title": rx}, {"rule_id": rx}, {"description": rx}]})
    return query


def list_findings(org_id: ObjectId, audit: dict, args, page: int, per_page: int) -> tuple[list[dict], int, dict]:
    sort = args.get("sort", "severity")
    if sort not in SORTS:
        raise ApiError(400, "validation_error", f"sort must be one of {', '.join(SORTS)}", {"sort": "invalid"})
    query = build_query(org_id, audit["_id"], args)
    db = get_db()
    total = db.findings.count_documents(query)
    pipeline = [
        {"$match": query},
        {"$addFields": {"severity_rank": {"$switch": {
            "branches": [{"case": {"$eq": ["$severity", s]}, "then": r} for s, r in SEVERITY_RANK.items()],
            "default": 0}}}},
        {"$sort": dict(SORTS[sort] + [("_id", 1)])},
        {"$skip": (page - 1) * per_page},
        {"$limit": per_page},
        {"$project": {"code_context": 0, "raw": 0, "status_history": 0, "code_snippet": 0}},
    ]
    items = list(db.findings.aggregate(pipeline))
    return items, total, facets(org_id, audit["_id"])


def facets(org_id: ObjectId, audit_id: ObjectId) -> dict:
    """Counts for the filter UI, over the whole audit (not the current filter)."""
    rows = list(get_db().findings.aggregate([
        {"$match": {"organization_id": org_id, "audit_id": audit_id}},
        {"$facet": {
            "severity": [{"$group": {"_id": "$severity", "n": {"$sum": 1}}}],
            "status": [{"$group": {"_id": "$status", "n": {"$sum": 1}}}],
            "category": [{"$group": {"_id": "$category", "n": {"$sum": 1}}}],
            "scanner": [{"$group": {"_id": "$scanner", "n": {"$sum": 1}}}],
            "ai_verdict": [{"$group": {"_id": {"$ifNull": ["$ai_analysis.verdict", "none"]}, "n": {"$sum": 1}}}],
        }},
    ]))
    out = {}
    for key, groups in (rows[0] if rows else {}).items():
        out[key] = {str(g["_id"]): g["n"] for g in groups if g["_id"] is not None}
    return out


def get_finding(org_id: ObjectId, finding_id: ObjectId) -> dict:
    f = get_db().findings.find_one({"_id": finding_id, "organization_id": org_id})
    if f is None:
        raise ApiError.not_found("Finding")
    return f


def _ai_public(ai: dict | None) -> dict | None:
    if not ai:
        return None
    keep = ("status", "reason", "error", "provider", "model", "verdict", "confidence", "false_positive_probability",
            "severity", "title", "explanation", "impact", "attack_scenario", "recommendation", "fixed_code",
            "missing_context", "evidence_lines", "cwe", "cached", "context")
    data = {k: ai[k] for k in keep if k in ai}
    if "analyzed_at" in ai:
        data["analyzed_at"] = iso(ai["analyzed_at"])
    return data


def _references(f: dict) -> list[dict]:
    refs = []
    if f.get("cwe") and re.fullmatch(r"CWE-\d+", f["cwe"]):
        refs.append({"label": f["cwe"], "url": f"https://cwe.mitre.org/data/definitions/{f['cwe'][4:]}.html"})
    if f.get("owasp") and re.fullmatch(r"A\d{2}:20\d{2}", f["owasp"]):
        refs.append({"label": f"OWASP {f['owasp']}", "url": "https://owasp.org/Top10/"})
    for url in f.get("references") or []:
        if isinstance(url, str) and url.startswith("https://"):
            refs.append({"label": url, "url": url})
    return refs


def allowed_transitions(status: str) -> list[str]:
    return list(FINDING_TRANSITIONS.get(status, ()))


def serialize_summary(f: dict) -> dict:
    ai = f.get("ai_analysis") or {}
    loc = f.get("location") or {}
    return {
        "id": id_str(f["_id"]),
        "audit_id": id_str(f["audit_id"]),
        "title": f["title"],
        "rule_id": f.get("rule_id"),
        "scanner": f.get("scanner"),
        "category": f.get("category"),
        "severity": f["severity"],
        "confidence": f.get("confidence"),
        "status": f["status"],
        "file": loc.get("file"),
        "line_start": loc.get("line_start"),
        "line_end": loc.get("line_end"),
        "function": loc.get("function"),
        "cwe": f.get("cwe"),
        "ai": {"status": ai.get("status"), "verdict": ai.get("verdict"), "confidence": ai.get("confidence"),
               "false_positive_probability": ai.get("false_positive_probability")} if ai else None,
        "created_at": iso(f["created_at"]),
    }


def serialize_detail(f: dict, audit: dict | None, repo: dict | None, users: dict[ObjectId, str]) -> dict:
    data = serialize_summary(f)
    data.update({
        "description": f.get("description"),
        "impact": f.get("impact"),
        "recommendation": f.get("recommendation"),
        "owasp": f.get("owasp"),
        "fingerprint": f.get("fingerprint"),
        "code_snippet": f.get("code_snippet"),
        "snippet_start_line": f.get("snippet_start_line"),
        "references": _references(f),
        "evidence": f.get("raw") or {},
        "ai_analysis": _ai_public(f.get("ai_analysis")),
        "allowed_transitions": allowed_transitions(f["status"]),
        "reason_required_for": list(REASON_REQUIRED_STATUSES),
        "status_history": [
            {"status": h.get("status"), "from": h.get("from"), "comment": h.get("comment"), "at": iso(h.get("at")),
             "user": users.get(h.get("user_id")) if h.get("user_id") else None}
            for h in f.get("status_history") or []
        ],
        "audit": {"id": id_str(audit["_id"]), "display_id": f"AUD-{audit['audit_number']}",
                  "branch": audit.get("branch"), "commit_hash": audit.get("commit_hash")} if audit else None,
        "repository": {"id": id_str(repo["_id"]), "name": repo["name"], "provider": repo["provider"],
                       "url": repo.get("url")} if repo else None,
        "updated_at": iso(f["updated_at"]),
    })
    return data


def user_names(ids) -> dict:
    ids = [i for i in set(ids) if isinstance(i, ObjectId)]
    if not ids:
        return {}
    return {u["_id"]: u["name"] for u in get_db().users.find({"_id": {"$in": ids}}, {"name": 1})}


def record_view(org_id: ObjectId, user_id: ObjectId, finding_id: ObjectId) -> None:
    """Audit-log a view (PRD §57), at most once per user and finding per 10 minutes."""
    recent = get_db().audit_logs.find_one({
        "organization_id": org_id, "user_id": user_id, "event": "finding.viewed",
        "details.finding_id": id_str(finding_id), "created_at": {"$gt": utcnow() - VIEW_LOG_WINDOW}})
    if recent is None:
        log_event("finding.viewed", org_id=org_id, user_id=user_id, details={"finding_id": id_str(finding_id)})


def code_view(f: dict) -> dict:
    """Stored, masked excerpt for the code viewer (PRD §36). Source is deleted after audits,
    so this is the exact audited version."""
    text = f.get("code_context") or f.get("code_snippet") or ""
    start = f.get("context_start_line") if f.get("code_context") else f.get("snippet_start_line")
    loc = f.get("location") or {}
    first, last = loc.get("line_start"), loc.get("line_end") or loc.get("line_start")
    ai = f.get("ai_analysis") or {}
    evidence = set(ai.get("evidence_lines") or []) if ai.get("status") == "completed" else set()
    lines = []
    for i, line in enumerate(text.splitlines() if text else []):
        n = (start or 1) + i
        lines.append({"number": n, "text": line, "highlight": bool(first and first <= n <= last),
                      "evidence": n in evidence})
    ext = "." + (loc.get("file") or "").rsplit(".", 1)[-1].lower() if "." in (loc.get("file") or "") else ""
    return {
        "file": loc.get("file"),
        "language": EXTENSIONS.get(ext),
        "line_start": first,
        "line_end": last,
        "lines": lines,
        "marker": {"line": last, "message": f.get("title")} if first else None,
        "fixed_code": ai.get("fixed_code") or None,
        "available": bool(lines),
    }


def _recount_audit(audit_id: ObjectId, org_id: ObjectId) -> None:
    """Keep the audit summary and the repository score in step with triage decisions."""
    db = get_db()
    counts = empty_counts()
    for row in db.findings.aggregate([
        {"$match": {"organization_id": org_id, "audit_id": audit_id, "status": {"$in": list(OPEN_FINDING_STATUSES)}}},
        {"$group": {"_id": "$severity", "n": {"$sum": 1}}}]):
        if row["_id"] in counts:
            counts[row["_id"]] = row["n"]
    audit = db.audits.find_one_and_update(
        {"_id": audit_id, "organization_id": org_id, "summary": {"$ne": None}},
        {"$set": {"summary.counts": counts, "summary.security_score": security_score(counts), "updated_at": utcnow()}},
        projection={"repository_id": 1}, return_document=ReturnDocument.AFTER)
    if audit:
        refresh_repository_snapshot(org_id, audit["repository_id"])


def change_status(org_id: ObjectId, user_id: ObjectId, finding_id: ObjectId, new_status: str,
                  comment: str | None) -> dict:
    f = get_finding(org_id, finding_id)
    current = f["status"]
    if new_status == current:
        raise ApiError.conflict(f"The finding is already {current.replace('_', ' ')}")
    if new_status not in FINDING_TRANSITIONS.get(current, ()):
        raise ApiError(409, "invalid_transition",
                       f"Can't change a finding from {current.replace('_', ' ')} to {new_status.replace('_', ' ')}",
                       {"allowed": allowed_transitions(current)})
    if new_status in REASON_REQUIRED_STATUSES and not comment:
        raise ApiError(400, "validation_error", "Explain why (a comment is required for this decision)",
                       {"comment": "required"})
    now = utcnow()
    entry = {"status": new_status, "from": current, "user_id": user_id, "at": now, "comment": comment}
    updated = get_db().findings.find_one_and_update(
        {"_id": finding_id, "organization_id": org_id, "status": current},  # guard against concurrent changes
        {"$set": {"status": new_status, "updated_at": now}, "$push": {"status_history": entry}},
        return_document=ReturnDocument.AFTER)
    if updated is None:
        raise ApiError.conflict("The finding was changed by someone else; reload and try again")
    if comment:
        _insert_comment(org_id, user_id, updated, comment, kind="status_change", status=new_status)
    was_open, is_open = current in OPEN_FINDING_STATUSES, new_status in OPEN_FINDING_STATUSES
    if was_open != is_open:
        _recount_audit(updated["audit_id"], org_id)
    log_event("finding.status_changed", org_id=org_id, user_id=user_id,
              details={"finding_id": id_str(finding_id), "from": current, "to": new_status})
    return updated


def _insert_comment(org_id, user_id, finding: dict, body: str, *, kind: str = "comment",
                    status: str | None = None) -> dict:
    doc = {"organization_id": org_id, "finding_id": finding["_id"], "repository_id": finding["repository_id"],
           "fingerprint": finding.get("fingerprint"), "user_id": user_id, "body": body, "kind": kind,
           "status": status, "created_at": utcnow()}
    doc["_id"] = get_db().finding_comments.insert_one(doc).inserted_id
    return doc


def add_comment(org_id: ObjectId, user_id: ObjectId, finding_id: ObjectId, body: str) -> dict:
    f = get_finding(org_id, finding_id)
    doc = _insert_comment(org_id, user_id, f, body)
    log_event("finding.commented", org_id=org_id, user_id=user_id, details={"finding_id": id_str(finding_id)})
    return doc


def list_comments(org_id: ObjectId, finding: dict, page: int, per_page: int) -> tuple[list[dict], int]:
    """Comments on this finding and on the same issue (fingerprint) in earlier audits of the repository."""
    query = {"organization_id": org_id, "$or": [{"finding_id": finding["_id"]}]}
    if finding.get("fingerprint"):
        query["$or"].append({"repository_id": finding["repository_id"], "fingerprint": finding["fingerprint"]})
    col = get_db().finding_comments
    total = col.count_documents(query)
    items = list(col.find(query).sort([("created_at", 1), ("_id", 1)]).skip((page - 1) * per_page).limit(per_page))
    return items, total


def serialize_comment(c: dict, users: dict, current_finding_id: ObjectId) -> dict:
    return {"id": id_str(c["_id"]), "body": c["body"], "kind": c.get("kind", "comment"), "status": c.get("status"),
            "user": users.get(c["user_id"]), "created_at": iso(c["created_at"]),
            "earlier_audit": c["finding_id"] != current_finding_id}
