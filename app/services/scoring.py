from bson import ObjectId
from flask import current_app

from ..constants import OPEN_FINDING_STATUSES, SEVERITIES
from ..db import get_db
from ..db.utils import utcnow


def empty_counts() -> dict:
    return {s: 0 for s in SEVERITIES}


def security_score(counts: dict) -> int:
    """Project-management indicator, not proof of security (PRD §49)."""
    weights = current_app.config["SCORE_WEIGHTS"]
    return max(0, 100 - sum(weights.get(sev, 0) * n for sev, n in counts.items()))


def open_counts_for_audit(org_id: ObjectId, audit_id: ObjectId) -> dict:
    counts = empty_counts()
    pipeline = [
        {"$match": {"organization_id": org_id, "audit_id": audit_id, "status": {"$in": list(OPEN_FINDING_STATUSES)}}},
        {"$group": {"_id": "$severity", "n": {"$sum": 1}}},
    ]
    for row in get_db().findings.aggregate(pipeline):
        if row["_id"] in counts:
            counts[row["_id"]] = row["n"]
    return counts


def refresh_repository_snapshot(org_id: ObjectId, repo_id: ObjectId) -> dict | None:
    """Recompute `repositories.last_audit` from the latest completed audit.

    Call after an audit completes and after any finding status change, so lists
    and the dashboard can read the snapshot without aggregating (PRD §41.2).
    """
    db = get_db()
    audit = db.audits.find_one(
        {"organization_id": org_id, "repository_id": repo_id, "status": "completed"},
        sort=[("created_at", -1), ("_id", -1)],
    )
    snapshot = None
    if audit is not None:
        counts = open_counts_for_audit(org_id, audit["_id"])
        snapshot = {
            "audit_id": audit["_id"],
            "audit_number": audit["audit_number"],
            "branch": audit["branch"],
            "status": audit["status"],
            "completed_at": audit.get("completed_at"),
            "counts": counts,
            "security_score": security_score(counts),
        }
    db.repositories.update_one(
        {"_id": repo_id, "organization_id": org_id}, {"$set": {"last_audit": snapshot, "updated_at": utcnow()}}
    )
    return snapshot
