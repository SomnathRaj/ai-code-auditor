import os

from flask import Blueprint, request
from werkzeug.utils import secure_filename

from ..constants import CAN_MANAGE_REPOS, CAN_RUN_AUDITS
from ..db.utils import parse_id
from ..errors import ApiError
from ..security import current_identity, login_required, require_role
from ..services import repository_service as repos
from ..services import audit_service, scan_service
from ..services.rate_limit import rate_limited
from .common import no_content, ok, paginated, pagination_args, parse_body
from .schemas import RepositoryCreateIn, RepositorySettingsIn, RepositoryUpdateIn, StartAuditIn, UploadNameIn

bp = Blueprint("repositories", __name__, url_prefix="/repositories")


def _created(repo: dict):
    return ok(repos.serialize_repository(repo, with_settings=True), 201,
              {"Location": f"/api/v1/repositories/{repo['_id']}"})


def _uploaded_zip():
    """Return (file storage, safe filename) from a multipart upload field named `file`."""
    if not request.content_type or not request.content_type.startswith("multipart/form-data"):
        raise ApiError(415, "unsupported_media_type", "Upload the archive as multipart/form-data")
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        raise ApiError(400, "validation_error", "Choose a .zip file to upload", {"file": "required"})
    filename = secure_filename(upload.filename) or "upload.zip"
    if not filename.lower().endswith(".zip"):
        raise ApiError(400, "validation_error", "Only .zip archives are supported", {"file": "must_be_zip"})
    return upload, filename


@bp.get("")
@login_required
def list_repositories():
    page, per_page = pagination_args()
    items, total = repos.list_repositories(current_identity().org_id, page, per_page)
    return paginated([repos.serialize_repository(r) for r in items], page, per_page, total)


@bp.post("")
@require_role(*CAN_MANAGE_REPOS)
def create_repository():
    body = parse_body(RepositoryCreateIn)
    identity = current_identity()
    repo = repos.create_github_repository(
        identity.org_id, identity.user_id, body.url, body.default_branch, body.name, body.access_token)
    return _created(repo)


def _org_key() -> str:
    return str(current_identity().org_id)


@bp.post("/uploads")
@require_role(*CAN_MANAGE_REPOS)
@rate_limited("upload", key=_org_key)
def upload_repository():
    upload, filename = _uploaded_zip()
    meta = UploadNameIn.model_validate({"name": request.form.get("name")})
    identity = current_identity()
    name = meta.name or os.path.splitext(filename)[0] or "Uploaded project"
    repo = repos.create_zip_repository(identity.org_id, identity.user_id, upload.stream, filename, name)
    return _created(repo)


@bp.get("/<repo_id>")
@login_required
def get_repository(repo_id: str):
    repo = repos.get_repository(current_identity().org_id, parse_id(repo_id, "Repository"))
    return ok(repos.serialize_repository(repo, with_settings=True))


@bp.patch("/<repo_id>")
@require_role(*CAN_MANAGE_REPOS)
def update_repository(repo_id: str):
    body = parse_body(RepositoryUpdateIn)
    identity = current_identity()
    fields = {f: getattr(body, f) for f in body.model_fields_set}
    repo = repos.update_repository(identity.org_id, identity.user_id, parse_id(repo_id, "Repository"), **fields)
    return ok(repos.serialize_repository(repo, with_settings=True))


@bp.delete("/<repo_id>")
@require_role(*CAN_MANAGE_REPOS)
def delete_repository(repo_id: str):
    identity = current_identity()
    repos.delete_repository(identity.org_id, identity.user_id, parse_id(repo_id, "Repository"))
    return no_content()


@bp.put("/<repo_id>/source")
@require_role(*CAN_RUN_AUDITS)
@rate_limited("upload", key=_org_key)
def replace_source(repo_id: str):
    """Upload a new version of a ZIP repository's source (e.g. after fixing findings)."""
    upload, filename = _uploaded_zip()
    identity = current_identity()
    repo = repos.replace_source(identity.org_id, identity.user_id, parse_id(repo_id, "Repository"),
                                upload.stream, filename)
    return ok(repos.serialize_repository(repo, with_settings=True))


@bp.get("/<repo_id>/branches")
@login_required
def list_branches(repo_id: str):
    repo = repos.get_repository(current_identity().org_id, parse_id(repo_id, "Repository"))
    page, per_page = pagination_args()
    default, names = repos.list_branches(repo)
    q = (request.args.get("q") or "").strip().lower()
    if q:
        names = [n for n in names if q in n.lower()]
    window = names[(page - 1) * per_page: page * per_page]
    return paginated([{"name": n, "default": n == default} for n in window], page, per_page, len(names))


@bp.get("/<repo_id>/settings")
@login_required
def get_settings(repo_id: str):
    repo = repos.get_repository(current_identity().org_id, parse_id(repo_id, "Repository"))
    return ok(repo["settings"])


@bp.post("/<repo_id>/audits")
@require_role(*CAN_RUN_AUDITS)
@rate_limited("audit_start", key=_org_key)
def start_audit(repo_id: str):
    """Queue an audit (PRD §40). 202 Accepted; poll the Location for progress."""
    body = parse_body(StartAuditIn)
    identity = current_identity()
    audit = audit_service.start_for_repository(
        identity.org_id, identity.user_id, parse_id(repo_id, "Repository"), body.branch, body.audit_type)
    return ok(audit_service.serialize_status(audit), 202, {"Location": f"/api/v1/audits/{audit['_id']}/status"})


@bp.put("/<repo_id>/settings")
@require_role(*CAN_MANAGE_REPOS)
def put_settings(repo_id: str):
    body = parse_body(RepositorySettingsIn)
    identity = current_identity()
    repo = repos.update_settings(identity.org_id, identity.user_id, parse_id(repo_id, "Repository"), body.model_dump())
    return ok(repo["settings"])


@bp.get("/<repo_id>/audits")
@login_required
def list_audits(repo_id: str):
    org_id = current_identity().org_id
    repo = repos.get_repository(org_id, parse_id(repo_id, "Repository"))
    page, per_page = pagination_args()
    items, total = repos.list_audits(org_id, repo["_id"], page, per_page)
    return paginated([repos.serialize_audit(a) for a in items], page, per_page, total)


@bp.get("/<repo_id>/dependencies")
@login_required
def list_dependencies(repo_id: str):
    """Dependencies from the latest completed audit; ?vulnerable=true|false, ?ecosystem=, ?q=."""
    org_id = current_identity().org_id
    repo = repos.get_repository(org_id, parse_id(repo_id, "Repository"))
    page, per_page = pagination_args()
    vulnerable = request.args.get("vulnerable")
    if vulnerable not in (None, "true", "false"):
        raise ApiError(400, "validation_error", "vulnerable must be true or false")
    audit, items, total = scan_service.list_dependencies(
        org_id, repo["_id"], vulnerable=None if vulnerable is None else vulnerable == "true",
        ecosystem=request.args.get("ecosystem") or None, q=(request.args.get("q") or "").strip() or None,
        page=page, per_page=per_page)
    return paginated([scan_service.serialize_dependency(d) for d in items], page, per_page, total, {
        "audit_id": str(audit["_id"]) if audit else None,
        "display_id": f"AUD-{audit['audit_number']}" if audit else None,
    })
