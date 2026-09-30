from bson import ObjectId
from flask import Blueprint, request

from ..constants import CAN_MANAGE_REPOS
from ..security import current_identity, login_required, require_role
from ..services import organization_service as orgs
from ..services.finding_service import user_names
from .common import no_content, ok, paginated, pagination_args, parse_body
from .schemas import MemberAddIn, MemberRoleIn, OrganizationUpdateIn

bp = Blueprint("organization", __name__, url_prefix="/organization")
logs_bp = Blueprint("audit_logs", __name__, url_prefix="/audit-logs")


@bp.get("")
@login_required
def get_organization():
    identity = current_identity()
    return ok(orgs.serialize_org(identity.org, identity))


@bp.patch("")
@require_role("owner")
def update_organization():
    """Rename, and set data retention (PRD §81): audit_days / source_days (0 = keep forever)."""
    body = parse_body(OrganizationUpdateIn)
    identity = current_identity()
    retention = body.retention.model_dump(exclude_none=True) if body.retention else None
    org = orgs.update_org(identity, body.name, retention)
    return ok(orgs.serialize_org(org, identity))


@bp.get("/members")
@require_role(*CAN_MANAGE_REPOS)
def list_members():
    return ok(orgs.list_members(current_identity().org))


@bp.post("/members")
@require_role(*CAN_MANAGE_REPOS)
def add_member():
    body = parse_body(MemberAddIn)
    return ok(orgs.add_member(current_identity(), body.email, body.role), 201)


@bp.patch("/members/<member_id>")
@require_role(*CAN_MANAGE_REPOS)
def change_role(member_id: str):
    body = parse_body(MemberRoleIn)
    return ok(orgs.change_role(current_identity(), member_id, body.role))


@bp.delete("/members/<member_id>")
@login_required
def remove_member(member_id: str):
    """Admins/owners remove members; anyone may remove themselves (leave)."""
    orgs.remove_member(current_identity(), member_id)
    return no_content()


@logs_bp.get("")
@require_role(*CAN_MANAGE_REPOS)
def list_audit_logs():
    """Activity log (PRD §57). Filters: event (exact or "audit.*"), user_id, since, until (ISO dates)."""
    identity = current_identity()
    page, per_page = pagination_args()
    items, total = orgs.list_audit_logs(identity.org_id, event=request.args.get("event") or None,
                                        user_id=request.args.get("user_id") or None,
                                        since=request.args.get("since") or None,
                                        until=request.args.get("until") or None, page=page, per_page=per_page)
    member_ids = [ObjectId(m) for d in items if ObjectId.is_valid(m := (d.get("details") or {}).get("member_id"))]
    users = user_names([d.get("user_id") for d in items] + member_ids)
    return paginated([orgs.serialize_log(d, users) for d in items], page, per_page, total)
