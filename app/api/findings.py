from flask import Blueprint

from ..constants import CAN_RUN_AUDITS
from ..db import get_db
from ..db.utils import parse_id
from ..security import current_identity, login_required, require_role
from ..services import finding_service as findings
from ..services.rate_limit import rate_limited
from .common import ok, paginated, pagination_args, parse_body
from .schemas import CommentIn, FindingUpdateIn

bp = Blueprint("findings", __name__, url_prefix="/findings")


def _detail(f: dict):
    db = get_db()
    audit = db.audits.find_one({"_id": f["audit_id"], "organization_id": f["organization_id"]},
                               {"audit_number": 1, "branch": 1, "commit_hash": 1})
    repo = db.repositories.find_one({"_id": f["repository_id"], "organization_id": f["organization_id"]},
                                    {"name": 1, "provider": 1, "url": 1})
    users = findings.user_names(h.get("user_id") for h in f.get("status_history") or [])
    return findings.serialize_detail(f, audit, repo, users)


@bp.get("/<finding_id>")
@login_required
def get_finding(finding_id: str):
    identity = current_identity()
    f = findings.get_finding(identity.org_id, parse_id(finding_id, "Finding"))
    findings.record_view(identity.org_id, identity.user_id, f["_id"])
    return ok(_detail(f))


@bp.patch("/<finding_id>")
@require_role(*CAN_RUN_AUDITS)
def update_finding(finding_id: str):
    """Change status (PRD §32). 409 for transitions the lifecycle doesn't allow."""
    body = parse_body(FindingUpdateIn)
    identity = current_identity()
    f = findings.change_status(identity.org_id, identity.user_id, parse_id(finding_id, "Finding"),
                               body.status, body.comment)
    return ok(_detail(f))


@bp.get("/<finding_id>/code")
@login_required
def get_code(finding_id: str):
    f = findings.get_finding(current_identity().org_id, parse_id(finding_id, "Finding"))
    return ok(findings.code_view(f))


@bp.get("/<finding_id>/comments")
@login_required
def list_comments(finding_id: str):
    identity = current_identity()
    f = findings.get_finding(identity.org_id, parse_id(finding_id, "Finding"))
    page, per_page = pagination_args()
    items, total = findings.list_comments(identity.org_id, f, page, per_page)
    users = findings.user_names(c["user_id"] for c in items)
    return paginated([findings.serialize_comment(c, users, f["_id"]) for c in items], page, per_page, total)


@bp.post("/<finding_id>/comments")
@require_role(*CAN_RUN_AUDITS)
@rate_limited("comment", key=lambda: str(current_identity().user_id))
def add_comment(finding_id: str):
    body = parse_body(CommentIn)
    identity = current_identity()
    c = findings.add_comment(identity.org_id, identity.user_id, parse_id(finding_id, "Finding"), body.body)
    users = findings.user_names([c["user_id"]])
    return ok(findings.serialize_comment(c, users, c["finding_id"]), 201)
