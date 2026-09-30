"""Data retention (PRD §53, §81), applied daily by the worker and by `flask retention`.

Per organization (organizations.retention):
- audit_days (default 90; 0 = keep forever): older audits are deleted with their findings,
  comments and dependencies. Each repository's latest completed audit is always kept, so the
  current state, the score and remembered triage decisions survive.
- source_days (default 0 = keep until replaced): uploaded ZIP archives older than this are
  deleted; the repository then needs a new upload before its next audit.
Server-wide: activity-log entries older than AUDIT_LOG_RETENTION_DAYS are deleted.
"""
from datetime import timedelta

from flask import current_app

from ..db import get_db
from ..db.utils import id_str, utcnow
from .audit_log import log_event
from .source_archive import delete_archive

FINAL = ["completed", "failed", "cancelled"]


def apply(dry_run: bool = False) -> dict:
    db = get_db()
    now = utcnow()
    totals = {"audits": 0, "findings": 0, "dependencies": 0, "comments": 0, "archives": 0, "audit_logs": 0}
    for org in db.organizations.find({}, {"retention": 1}):
        org_id = org["_id"]
        retention = {"audit_days": 90, "source_days": 0, **(org.get("retention") or {})}
        counts = {k: 0 for k in totals if k != "audit_logs"}

        if retention["audit_days"]:
            cutoff = now - timedelta(days=retention["audit_days"])
            keep = set()
            for repo_id in db.repositories.distinct("_id", {"organization_id": org_id}):
                latest = db.audits.find_one({"organization_id": org_id, "repository_id": repo_id, "status": "completed"},
                                            {"_id": 1}, sort=[("created_at", -1), ("_id", -1)])
                if latest:
                    keep.add(latest["_id"])
            old = [a["_id"] for a in db.audits.find(
                {"organization_id": org_id, "status": {"$in": FINAL}, "created_at": {"$lt": cutoff},
                 "_id": {"$nin": list(keep)}}, {"_id": 1})]
            if old:
                scope = {"organization_id": org_id, "audit_id": {"$in": old}}
                finding_ids = db.findings.distinct("_id", scope)
                counts["audits"] = len(old)
                counts["findings"] = len(finding_ids)
                counts["dependencies"] = db.dependencies.count_documents(scope)
                counts["comments"] = db.finding_comments.count_documents(
                    {"organization_id": org_id, "finding_id": {"$in": finding_ids}})
                if not dry_run:
                    db.finding_comments.delete_many({"organization_id": org_id, "finding_id": {"$in": finding_ids}})
                    db.findings.delete_many(scope)
                    db.dependencies.delete_many(scope)
                    db.audits.delete_many({"organization_id": org_id, "_id": {"$in": old}})

        if retention["source_days"]:
            cutoff = now - timedelta(days=retention["source_days"])
            for repo in db.repositories.find({"organization_id": org_id, "provider": "zip",
                                              "source.uploaded_at": {"$lt": cutoff}}, {"source": 1, "name": 1}):
                counts["archives"] += 1
                if not dry_run:
                    delete_archive(repo["source"]["archive_id"])
                    db.repositories.update_one({"_id": repo["_id"]}, {"$set": {"source": None, "updated_at": now}})
                    log_event("retention.archive_deleted", org_id=org_id,
                              details={"repository_id": id_str(repo["_id"]), "name": repo["name"]})

        if any(counts.values()) and not dry_run:
            log_event("retention.applied", org_id=org_id, details={**counts, **retention})
        for k, v in counts.items():
            totals[k] += v

    log_days = current_app.config["AUDIT_LOG_RETENTION_DAYS"]
    if log_days:
        query = {"created_at": {"$lt": now - timedelta(days=log_days)}}
        totals["audit_logs"] = db.audit_logs.count_documents(query)
        if not dry_run:
            db.audit_logs.delete_many(query)
    return totals
