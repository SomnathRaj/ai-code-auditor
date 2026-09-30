import re
from typing import BinaryIO

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from ..db import get_db, run_in_transaction
from ..db.utils import id_str, iso, utcnow
from ..errors import ApiError
from . import git_client, source_archive
from .audit_log import log_event
from .crypto import decrypt_text, encrypt_text
from .scoring import empty_counts

GITHUB_URL_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*\.lock$)(?!/)(?!.*/$)[A-Za-z0-9._/-]{1,200}$")
DEFAULT_SCANNERS = ["semgrep", "gitleaks", "dependencies"]
DEFAULT_EXCLUDES = ["node_modules/", "vendor/", ".git/", "dist/", "build/", "coverage/"]

_GIT_ERROR_STATUS = {
    "repository_inaccessible": 422,
    "branch_not_found": 400,
    "network_error": 502,
    "timeout": 504,
    "protocol_not_allowed": 400,
}


def _default_settings() -> dict:
    return {
        "enabled_scanners": list(DEFAULT_SCANNERS),
        "excluded_paths": list(DEFAULT_EXCLUDES),
        "severity_threshold": "low",
        "ai_enabled": True,
    }


def git_api_error(err: git_client.GitError) -> ApiError:
    return ApiError(_GIT_ERROR_STATUS.get(err.code, 502), err.code, err.message)


# ---- serialization ----

def serialize_snapshot(snapshot: dict | None) -> dict | None:
    if not snapshot:
        return None
    return {
        "audit_id": id_str(snapshot["audit_id"]),
        "display_id": f"AUD-{snapshot['audit_number']}",
        "branch": snapshot.get("branch"),
        "status": snapshot["status"],
        "completed_at": iso(snapshot.get("completed_at")),
    }


def serialize_source(source: dict | None) -> dict | None:
    if not source:
        return None
    return {
        "type": source["type"],
        "filename": source["filename"],
        "size": source["size"],
        "sha256": source["sha256"],
        "file_count": source["file_count"],
        "uncompressed_size": source["uncompressed_size"],
        "uploaded_at": iso(source["uploaded_at"]),
    }


def serialize_repository(repo: dict, *, with_settings: bool = False) -> dict:
    snapshot = repo.get("last_audit")
    counts = (snapshot or {}).get("counts") or empty_counts()
    data = {
        "id": id_str(repo["_id"]),
        "name": repo["name"],
        "provider": repo["provider"],
        "url": repo.get("url"),
        "default_branch": repo.get("default_branch"),
        "language": repo.get("language"),
        "framework": repo.get("framework"),
        "frameworks": repo.get("frameworks") or [],
        "languages": repo.get("languages") or [],
        "status": repo["status"],
        "has_access_token": bool((repo.get("credentials") or {}).get("encrypted_token")),
        "source": serialize_source(repo.get("source")),
        "counts": counts,
        "open_findings": sum(counts.values()),
        "security_score": snapshot["security_score"] if snapshot else None,
        "last_audit": serialize_snapshot(snapshot),
        "created_at": iso(repo["created_at"]),
        "updated_at": iso(repo["updated_at"]),
    }
    if with_settings:
        data["settings"] = repo["settings"]
    return data


def serialize_audit(audit: dict, repository_name: str | None = None) -> dict:
    started, completed = audit.get("started_at"), audit.get("completed_at")
    data = {
        "id": id_str(audit["_id"]),
        "display_id": f"AUD-{audit['audit_number']}",
        "repository_id": id_str(audit["repository_id"]),
        "branch": audit["branch"],
        "commit_hash": audit.get("commit_hash"),
        "audit_type": audit["audit_type"],
        "status": audit["status"],
        "error": audit.get("error"),
        "started_at": iso(started),
        "completed_at": iso(completed),
        "duration": int((completed - started).total_seconds()) if started and completed else None,
        "summary": audit.get("summary"),
        "is_final": audit["status"] in ("completed", "failed", "cancelled"),
        "created_at": iso(audit["created_at"]),
    }
    if repository_name is not None:
        data["repository_name"] = repository_name
    return data


# ---- queries ----

def list_repositories(org_id: ObjectId, page: int, per_page: int) -> tuple[list[dict], int]:
    col = get_db().repositories
    query = {"organization_id": org_id}
    total = col.count_documents(query)
    cursor = col.find(query).sort([("name", 1), ("_id", 1)]).skip((page - 1) * per_page).limit(per_page)
    return list(cursor), total


def get_repository(org_id: ObjectId, repo_id: ObjectId) -> dict:
    repo = get_db().repositories.find_one({"_id": repo_id, "organization_id": org_id})
    if repo is None:
        raise ApiError.not_found("Repository")
    return repo


def list_audits(org_id: ObjectId, repo_id: ObjectId, page: int, per_page: int) -> tuple[list[dict], int]:
    col = get_db().audits
    query = {"organization_id": org_id, "repository_id": repo_id}
    total = col.count_documents(query)
    cursor = col.find(query).sort([("created_at", -1), ("_id", -1)]).skip((page - 1) * per_page).limit(per_page)
    return list(cursor), total


# ---- GitHub ----

def _token(repo: dict) -> str | None:
    enc = (repo.get("credentials") or {}).get("encrypted_token")
    return decrypt_text(enc) if enc else None


def _remote(url: str, token: str | None) -> git_client.RemoteInfo:
    try:
        return git_client.ls_remote(url, token)
    except git_client.GitError as err:
        raise git_api_error(err)


def _require_branch(info: git_client.RemoteInfo, branch: str) -> None:
    if branch not in info.branches:
        raise ApiError(400, "branch_not_found", f"Branch '{branch}' does not exist in the repository",
                       {"default_branch": "not_found"})


def create_github_repository(org_id: ObjectId, user_id: ObjectId, url: str, branch: str | None,
                             name: str | None, access_token: str | None) -> dict:
    owner, repo_name = GITHUB_URL_RE.match(url).groups()
    url = f"https://github.com/{owner}/{repo_name}"
    col = get_db().repositories
    if col.find_one({"organization_id": org_id, "url": url}, {"_id": 1}):
        raise ApiError.conflict("This repository has already been added")

    # Verify access (and the branch) before saving anything.
    info = _remote(url, access_token)
    if not info.branches:
        raise ApiError(422, "empty_repository", "The repository has no branches")
    branch = branch or info.default_branch
    _require_branch(info, branch)

    now = utcnow()
    repo = {
        "organization_id": org_id,
        "name": name or f"{owner}/{repo_name}",
        "provider": "github",
        "url": url,
        "default_branch": branch,
        "language": None,
        "framework": None,
        "status": "active",
        "settings": _default_settings(),
        "credentials": {"encrypted_token": encrypt_text(access_token)} if access_token else None,
        "source": None,
        "last_audit": None,
        "created_by": user_id,
        "created_at": now,
        "updated_at": now,
    }
    try:
        repo["_id"] = col.insert_one(repo).inserted_id
    except DuplicateKeyError:
        raise ApiError.conflict("This repository has already been added")
    log_event("repository.added", org_id=org_id, user_id=user_id,
              details={"repository_id": id_str(repo["_id"]), "name": repo["name"], "provider": "github",
                       "private_access": bool(access_token)})
    return repo


def list_branches(repo: dict) -> tuple[str | None, list[str]]:
    if repo["provider"] != "github":
        raise ApiError(409, "not_supported", "Only GitHub repositories have branches")
    info = _remote(repo["url"], _token(repo))
    names = sorted(info.branches, key=lambda b: (b != info.default_branch, b.lower()))
    return info.default_branch, names


# ---- ZIP uploads ----

def create_zip_repository(org_id: ObjectId, user_id: ObjectId, fileobj: BinaryIO, filename: str,
                          name: str) -> dict:
    stats = source_archive.validate_upload(fileobj)
    repo_id = ObjectId()
    source = source_archive.store_archive(fileobj, org_id=org_id, repo_id=repo_id, filename=filename, stats=stats)
    now = utcnow()
    repo = {
        "_id": repo_id,
        "organization_id": org_id,
        "name": name,
        "provider": "zip",
        "url": None,
        "default_branch": None,
        "language": None,
        "framework": None,
        "status": "active",
        "settings": _default_settings(),
        "credentials": None,
        "source": source,
        "last_audit": None,
        "created_by": user_id,
        "created_at": now,
        "updated_at": now,
    }
    try:
        get_db().repositories.insert_one(repo)
    except Exception:
        source_archive.delete_archive(source["archive_id"])  # don't leave an orphaned archive
        raise
    log_event("repository.added", org_id=org_id, user_id=user_id,
              details={"repository_id": id_str(repo_id), "name": name, "provider": "zip",
                       "sha256": source["sha256"]})
    return repo


def replace_source(org_id: ObjectId, user_id: ObjectId, repo_id: ObjectId, fileobj: BinaryIO,
                   filename: str) -> dict:
    repo = get_repository(org_id, repo_id)
    if repo["provider"] != "zip":
        raise ApiError(409, "not_supported", "Only ZIP repositories accept uploads; GitHub repositories are cloned")
    stats = source_archive.validate_upload(fileobj)
    source = source_archive.store_archive(fileobj, org_id=org_id, repo_id=repo_id, filename=filename, stats=stats)
    old = repo.get("source")
    updated = get_db().repositories.find_one_and_update(
        {"_id": repo_id, "organization_id": org_id},
        {"$set": {"source": source, "updated_at": utcnow()}},
        return_document=True,
    )
    if updated is None:  # deleted meanwhile
        source_archive.delete_archive(source["archive_id"])
        raise ApiError.not_found("Repository")
    if old:
        source_archive.delete_archive(old["archive_id"])
    log_event("repository.source_uploaded", org_id=org_id, user_id=user_id,
              details={"repository_id": id_str(repo_id), "sha256": source["sha256"]})
    return updated


# ---- update / delete ----

_UNSET = object()


def update_repository(org_id: ObjectId, user_id: ObjectId, repo_id: ObjectId, *, name=_UNSET,
                      default_branch=_UNSET, access_token=_UNSET) -> dict:
    repo = get_repository(org_id, repo_id)
    changes, changed_fields = {}, []

    if name is not _UNSET:
        changes["name"] = name
        changed_fields.append("name")

    if default_branch is not _UNSET or access_token is not _UNSET:
        if repo["provider"] != "github":
            raise ApiError(409, "not_supported", "Branches and access tokens apply to GitHub repositories only")
        token = _token(repo) if access_token is _UNSET else access_token
        # Re-verify access with the new token and/or branch before saving.
        info = _remote(repo["url"], token)
        if default_branch is not _UNSET:
            _require_branch(info, default_branch)
            changes["default_branch"] = default_branch
            changed_fields.append("default_branch")
        if access_token is not _UNSET:
            changes["credentials"] = {"encrypted_token": encrypt_text(access_token)} if access_token else None
            changed_fields.append("access_token")

    if not changes:
        return repo
    changes["updated_at"] = utcnow()
    updated = get_db().repositories.find_one_and_update(
        {"_id": repo_id, "organization_id": org_id}, {"$set": changes}, return_document=True)
    if updated is None:
        raise ApiError.not_found("Repository")
    log_event("repository.updated", org_id=org_id, user_id=user_id,
              details={"repository_id": id_str(repo_id), "fields": changed_fields})
    return updated


def update_settings(org_id: ObjectId, user_id: ObjectId, repo_id: ObjectId, settings: dict) -> dict:
    get_repository(org_id, repo_id)
    updated = get_db().repositories.find_one_and_update(
        {"_id": repo_id, "organization_id": org_id},
        {"$set": {"settings": settings, "updated_at": utcnow()}}, return_document=True)
    if updated is None:
        raise ApiError.not_found("Repository")
    log_event("repository.settings_changed", org_id=org_id, user_id=user_id,
              details={"repository_id": id_str(repo_id), "ai_enabled": settings["ai_enabled"],
                       "enabled_scanners": settings["enabled_scanners"]})
    return updated


def delete_repository(org_id: ObjectId, user_id: ObjectId, repo_id: ObjectId) -> None:
    repo = get_repository(org_id, repo_id)
    db = get_db()

    def delete(session):
        scope = {"organization_id": org_id, "repository_id": repo_id}
        finding_ids = [f["_id"] for f in db.findings.find(scope, {"_id": 1}, session=session)]
        # Children first, repository last: without a transaction a failure part-way
        # leaves the repository in place and the delete can simply be retried.
        if finding_ids:
            db.finding_comments.delete_many({"organization_id": org_id, "finding_id": {"$in": finding_ids}}, session=session)
        db.findings.delete_many(scope, session=session)
        db.dependencies.delete_many(scope, session=session)
        db.audits.delete_many(scope, session=session)
        source_archive.delete_repository_archives(org_id, repo_id, session=session)
        db.repositories.delete_one({"_id": repo_id, "organization_id": org_id}, session=session)
        log_event("repository.deleted", org_id=org_id, user_id=user_id,
                  details={"repository_id": id_str(repo_id), "name": repo["name"]}, session=session)

    run_in_transaction(delete)
