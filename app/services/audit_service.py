"""Audits: queueing, reading, cancelling and deleting (PRD §38–§40, §43.4).

The work itself is done by app.worker.AuditWorker.
"""
from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from ..constants import AUDIT_TYPES
from ..db import get_db, run_in_transaction
from ..db.utils import id_str, iso, utcnow
from ..errors import ApiError
from .audit_log import log_event
from .repository_service import get_repository
from .scoring import refresh_repository_snapshot

# (name, label) in pipeline order — PRD §39 / §63.
STAGES = [
    ("cloning", "Fetch source"),
    ("detecting", "Detect project"),
    ("scanning", "Static analysis & secrets"),
    ("dependency_analysis", "Dependency scan"),
    ("ai_analysis", "AI analysis"),
    ("processing", "Process results"),
]
STAGE_WEIGHTS = {"cloning": 15, "detecting": 5, "scanning": 45, "dependency_analysis": 20, "ai_analysis": 5,
                 "processing": 10}
RUNNING_STATUSES = tuple(name for name, _ in STAGES)
ACTIVE_STATUSES = ("queued",) + RUNNING_STATUSES
FINAL_STATUSES = ("completed", "failed", "cancelled")

# Audit type → scanners it may run (intersected with the repository's enabled scanners), PRD §38.
AUDIT_TYPE_SCANNERS = {
    "full": {"semgrep", "gitleaks", "dependencies"},
    "security": {"semgrep", "gitleaks"},
    "dependency": {"dependencies"},
    "secret": {"gitleaks"},
    "quick": {"semgrep", "gitleaks"},
}
QUICK_THRESHOLD = "high"


def initial_stages(provider: str) -> list[dict]:
    stages = []
    for name, label in STAGES:
        if name == "cloning" and provider == "zip":
            label = "Extract archive"
        stages.append({"name": name, "label": label, "status": "pending", "detail": None,
                       "started_at": None, "completed_at": None})
    return stages


def next_audit_number(org_id: ObjectId) -> int:
    org = get_db().organizations.find_one_and_update(
        {"_id": org_id}, {"$inc": {"audit_counter": 1}}, return_document=ReturnDocument.AFTER)
    return org["audit_counter"]


def effective_settings(repo: dict, audit_type: str) -> dict:
    settings = dict(repo["settings"])
    enabled = set(settings.get("enabled_scanners") or []) & AUDIT_TYPE_SCANNERS[audit_type]
    if not enabled:
        raise ApiError(400, "validation_error",
                       f"The '{audit_type}' audit needs a scanner that is disabled in this repository's settings",
                       {"audit_type": "no_enabled_scanners"})
    settings["enabled_scanners"] = sorted(enabled)
    if audit_type == "quick":
        settings["severity_threshold"] = QUICK_THRESHOLD
    return settings


def enqueue(repo: dict, user_id: ObjectId | None, branch: str | None = None, audit_type: str = "full") -> dict:
    """Create a queued audit. Raises 409 if the repository already has one queued or running."""
    if audit_type not in AUDIT_TYPES:
        raise ApiError(400, "validation_error", "Unknown audit type", {"audit_type": "invalid"})
    if repo["provider"] == "zip":
        if not repo.get("source"):
            raise ApiError(409, "no_source", "Upload an archive before auditing this repository")
        branch = None
    now = utcnow()
    audit = {
        "organization_id": repo["organization_id"],
        "repository_id": repo["_id"],
        "audit_number": next_audit_number(repo["organization_id"]),
        "branch": branch or repo.get("default_branch") or "upload",
        "audit_type": audit_type,
        "settings": effective_settings(repo, audit_type),
        "status": "queued",
        "active": True,  # partial unique index: one queued/running audit per repository
        "stages": initial_stages(repo["provider"]),
        "cancel_requested": False,
        "attempts": 0,
        "worker": None,
        "error": None,
        "commit_hash": None,
        # started_at is set by the first claim ($min); it must be absent, not null, until then
        "completed_at": None,
        "summary": None,
        "scanner_versions": None,
        "created_by": user_id,
        "created_at": now,
        "updated_at": now,
    }
    try:
        audit["_id"] = get_db().audits.insert_one(audit).inserted_id
    except DuplicateKeyError:
        raise ApiError.conflict("An audit is already queued or running for this repository")
    log_event("audit.queued", org_id=repo["organization_id"], user_id=user_id,
              details={"audit_id": id_str(audit["_id"]), "repository_id": id_str(repo["_id"]),
                       "audit_type": audit_type, "branch": audit["branch"]})
    return audit


def get_audit(org_id: ObjectId, audit_id: ObjectId) -> dict:
    audit = get_db().audits.find_one({"_id": audit_id, "organization_id": org_id})
    if audit is None:
        raise ApiError.not_found("Audit")
    return audit


def progress_percent(audit: dict) -> int:
    if audit["status"] == "completed":
        return 100
    done = 0.0
    for stage in audit.get("stages") or []:
        weight = STAGE_WEIGHTS.get(stage["name"], 0)
        if stage["status"] in ("completed", "skipped"):
            done += weight
        elif stage["status"] == "running":
            done += weight / 2
    return min(99, int(done))


def _serialize_stage(stage: dict) -> dict:
    return {"name": stage["name"], "label": stage["label"], "status": stage["status"], "detail": stage.get("detail"),
            "started_at": iso(stage.get("started_at")), "completed_at": iso(stage.get("completed_at"))}


def serialize_status(audit: dict) -> dict:
    return {
        "id": id_str(audit["_id"]),
        "display_id": f"AUD-{audit['audit_number']}",
        "status": audit["status"],
        "is_final": audit["status"] in FINAL_STATUSES,
        "progress": progress_percent(audit),
        "stages": [_serialize_stage(s) for s in audit.get("stages") or []],
        "cancel_requested": bool(audit.get("cancel_requested")),
        "error": audit.get("error"),
        "started_at": iso(audit.get("started_at")),
        "completed_at": iso(audit.get("completed_at")),
        "updated_at": iso(audit.get("updated_at")),
    }


def serialize_detail(audit: dict, repo: dict | None) -> dict:
    from .repository_service import serialize_audit
    data = serialize_audit(audit)
    data.update(serialize_status(audit))
    data.update({
        "repository": {"id": id_str(repo["_id"]), "name": repo["name"], "provider": repo["provider"]} if repo else None,
        "settings": audit.get("settings"),
        "scanner_versions": audit.get("scanner_versions"),
        "attempts": audit.get("attempts", 0),
        "created_by": id_str(audit.get("created_by")),
    })
    return data


def cancel(org_id: ObjectId, user_id: ObjectId, audit_id: ObjectId) -> dict:
    """Queued audits are cancelled immediately; running ones are flagged and stopped by the worker."""
    db = get_db()
    audit = get_audit(org_id, audit_id)
    if audit["status"] in FINAL_STATUSES:
        raise ApiError.conflict(f"The audit is already {audit['status']}")
    now = utcnow()
    stages = [{**s, "status": "cancelled"} if s["status"] in ("pending", "running") else s for s in audit["stages"]]
    done = db.audits.find_one_and_update(
        {"_id": audit_id, "organization_id": org_id, "status": "queued"},
        {"$set": {"status": "cancelled", "stages": stages, "completed_at": now, "updated_at": now,
                  "cancel_requested": True, "error": {"code": "cancelled", "message": "Cancelled before it started"}},
         "$unset": {"active": ""}},
        return_document=ReturnDocument.AFTER)
    if done is None:  # already picked up by a worker
        done = db.audits.find_one_and_update(
            {"_id": audit_id, "organization_id": org_id, "status": {"$in": list(RUNNING_STATUSES)}},
            {"$set": {"cancel_requested": True, "updated_at": now}}, return_document=ReturnDocument.AFTER)
        if done is None:
            raise ApiError.conflict("The audit has already finished")
    log_event("audit.cancel_requested", org_id=org_id, user_id=user_id, details={"audit_id": id_str(audit_id)})
    return done


def delete(org_id: ObjectId, user_id: ObjectId, audit_id: ObjectId) -> None:
    audit = get_audit(org_id, audit_id)
    if audit["status"] in ACTIVE_STATUSES:
        raise ApiError.conflict("Cancel the audit before deleting it")
    db = get_db()

    def remove(session):
        scope = {"organization_id": org_id, "audit_id": audit_id}
        finding_ids = [f["_id"] for f in db.findings.find(scope, {"_id": 1}, session=session)]
        if finding_ids:
            db.finding_comments.delete_many({"organization_id": org_id, "finding_id": {"$in": finding_ids}},
                                            session=session)
        db.findings.delete_many(scope, session=session)
        db.dependencies.delete_many(scope, session=session)
        db.audits.delete_one({"_id": audit_id, "organization_id": org_id}, session=session)

    run_in_transaction(remove)
    refresh_repository_snapshot(org_id, audit["repository_id"])
    log_event("audit.deleted", org_id=org_id, user_id=user_id,
              details={"audit_id": id_str(audit_id), "display_id": f"AUD-{audit['audit_number']}"})


def start_for_repository(org_id: ObjectId, user_id: ObjectId, repo_id: ObjectId, branch: str | None,
                         audit_type: str) -> dict:
    repo = get_repository(org_id, repo_id)
    return enqueue(repo, user_id, branch, audit_type)
