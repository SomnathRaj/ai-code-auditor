from datetime import timedelta

from bson import ObjectId

from ..db import get_db
from ..db.utils import id_str, iso, utcnow
from .comparison_service import fixed_between
from .finding_service import SEVERITY_RANK
from .repository_service import serialize_audit
from .scoring import empty_counts, security_score


def dashboard(org_id: ObjectId) -> dict:
    db = get_db()
    repos = list(db.repositories.find({"organization_id": org_id}, {"name": 1, "last_audit": 1}))

    counts = empty_counts()
    audited = 0
    for repo in repos:
        snapshot = repo.get("last_audit")
        if snapshot:
            audited += 1
            for sev, n in (snapshot.get("counts") or {}).items():
                if sev in counts:
                    counts[sev] += n

    names = {r["_id"]: r["name"] for r in repos}
    recent = db.audits.find({"organization_id": org_id}).sort([("created_at", -1), ("_id", -1)]).limit(5)

    return {
        "counts": counts,
        "open_findings": sum(counts.values()),
        "security_score": security_score(counts) if audited else None,
        "repository_count": len(repos),
        "audited_repository_count": audited,
        "recent_audits": [serialize_audit(a, names.get(a["repository_id"], "")) for a in recent],
    }


def trends(org_id: ObjectId, days: int = 90) -> dict:
    """Dashboard analytics (PRD §59): risk over time, resolved this month, recurring issues."""
    db = get_db()
    now = utcnow()
    since = now - timedelta(days=days)
    repos = {r["_id"]: r for r in db.repositories.find({"organization_id": org_id}, {"name": 1, "last_audit": 1})}
    audits = list(db.audits.find(
        {"organization_id": org_id, "status": "completed", "repository_id": {"$in": list(repos)}},
        {"organization_id": 1, "repository_id": 1, "audit_number": 1, "completed_at": 1, "created_at": 1,
         "summary.counts": 1},
    ).sort([("completed_at", 1), ("_id", 1)]))

    # Organization risk over time: after each audit, the sum of every repository's latest open counts.
    latest: dict = {}
    points = []
    for a in audits:
        latest[a["repository_id"]] = ((a.get("summary") or {}).get("counts") or empty_counts())
        if a.get("completed_at") and a["completed_at"] >= since:
            total = empty_counts()
            for counts in latest.values():
                for sev, n in counts.items():
                    if sev in total:
                        total[sev] += n
            points.append({"at": iso(a["completed_at"]), "audit_id": id_str(a["_id"]),
                           "display_id": f"AUD-{a['audit_number']}",
                           "repository": repos[a["repository_id"]]["name"],
                           "open_findings": sum(total.values()), "counts": total,
                           "security_score": security_score(total)})

    # Resolved this month: triage decisions + issues that disappeared from the code.
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    triaged = next(iter(db.findings.aggregate([
        {"$match": {"organization_id": org_id, "status_history.at": {"$gte": month_start}}},
        {"$unwind": "$status_history"},
        {"$match": {"status_history.at": {"$gte": month_start}, "status_history.status": {"$in": ["resolved", "verified"]}}},
        {"$group": {"_id": None, "n": {"$sum": 1}}},
    ])), {}).get("n", 0)
    fixed_in_code = 0
    previous_by_repo: dict = {}
    for a in audits:
        prev = previous_by_repo.get(a["repository_id"])
        if prev is not None and a.get("completed_at") and a["completed_at"] >= month_start:
            fixed_in_code += fixed_between(prev, a)
        previous_by_repo[a["repository_id"]] = a

    # Recurring issues: still open in the repository's latest audit and seen in earlier audits too.
    latest_audit_ids = [r["last_audit"]["audit_id"] for r in repos.values() if r.get("last_audit")]
    recurring = []
    if latest_audit_ids:
        current = {(f["repository_id"], f["fingerprint"]): f for f in db.findings.find(
            {"organization_id": org_id, "audit_id": {"$in": latest_audit_ids}, "status": {"$in": ["new", "confirmed", "in_progress"]}},
            {"repository_id": 1, "fingerprint": 1, "title": 1, "severity": 1, "location": 1})}
        if current:
            seen = db.findings.aggregate([
                {"$match": {"organization_id": org_id, "fingerprint": {"$in": list({k[1] for k in current})}}},
                {"$group": {"_id": {"repo": "$repository_id", "fp": "$fingerprint"}, "audits": {"$addToSet": "$audit_id"}}},
                {"$project": {"n": {"$size": "$audits"}}},
                {"$match": {"n": {"$gte": 2}}},
            ])
            for row in seen:
                f = current.get((row["_id"]["repo"], row["_id"]["fp"]))
                if f:
                    loc = f.get("location") or {}
                    recurring.append({"finding_id": id_str(f["_id"]), "title": f["title"], "severity": f["severity"],
                                      "repository": repos[f["repository_id"]]["name"], "file": loc.get("file"),
                                      "line_start": loc.get("line_start"), "audits": row["n"]})
            recurring.sort(key=lambda r: (-r["audits"], -SEVERITY_RANK.get(r["severity"], 0), r["title"]))

    return {"days": days, "points": points,
            "resolved_this_month": {"total": triaged + fixed_in_code, "triaged": triaged, "fixed_in_code": fixed_in_code},
            "recurring": recurring[:10], "recurring_total": len(recurring)}
