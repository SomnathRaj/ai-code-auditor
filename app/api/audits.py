import re

from flask import Blueprint, Response, request

from ..constants import CAN_MANAGE_REPOS, CAN_RUN_AUDITS
from ..db import get_db
from ..db.utils import parse_id
from ..security import current_identity, login_required, require_role
from ..errors import ApiError
from ..reports import model as report_model
from ..reports import render_csv, render_html, render_pdf
from ..services import audit_service, comparison_service
from ..services import finding_service as findings
from ..services.audit_log import log_event
from ..services.rate_limit import rate_limited
from .common import no_content, ok, paginated, pagination_args

bp = Blueprint("audits", __name__, url_prefix="/audits")


@bp.get("/<audit_id>")
@login_required
def get_audit(audit_id: str):
    identity = current_identity()
    audit = audit_service.get_audit(identity.org_id, parse_id(audit_id, "Audit"))
    repo = get_db().repositories.find_one({"_id": audit["repository_id"], "organization_id": identity.org_id},
                                          {"name": 1, "provider": 1})
    return ok(audit_service.serialize_detail(audit, repo))


@bp.get("/<audit_id>/status")
@login_required
def get_status(audit_id: str):
    """Lightweight progress payload, polled by the UI while an audit runs."""
    audit = audit_service.get_audit(current_identity().org_id, parse_id(audit_id, "Audit"))
    return ok(audit_service.serialize_status(audit))


@bp.get("/<audit_id>/findings")
@login_required
def list_findings(audit_id: str):
    """Filters: severity, status (or open/closed), category, scanner, ai_verdict, file, q; sort; paginated.
    meta.facets has counts per filter value for the whole audit."""
    identity = current_identity()
    audit = audit_service.get_audit(identity.org_id, parse_id(audit_id, "Audit"))
    page, per_page = pagination_args()
    items, total, facets = findings.list_findings(identity.org_id, audit, request.args, page, per_page)
    return paginated([findings.serialize_summary(f) for f in items], page, per_page, total, {"facets": facets})


REPORT_FORMATS = {
    "html": ("text/html; charset=utf-8", "html"),
    "pdf": ("application/pdf", "pdf"),
    "csv": ("text/csv; charset=utf-8", "csv"),
}


def _filename(audit: dict, repo_name: str, kind: str, ext: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", repo_name or "repository").strip("-")[:60] or "repository"
    return f"AUD-{audit['audit_number']}-{slug}-{kind}.{ext}"


def _user_key() -> str:
    return str(current_identity().user_id)


@bp.get("/<audit_id>/report")
@login_required
@rate_limited("report", key=_user_key)
def report(audit_id: str):
    """PRD §48. format=json|html|pdf|csv, type=technical|executive. Technical reports accept the
    findings-list filters (severity, status, …). Files are sent as attachments."""
    identity = current_identity()
    audit = audit_service.get_audit(identity.org_id, parse_id(audit_id, "Audit"))
    fmt = request.args.get("format", "json")
    kind = request.args.get("type", "technical")
    if fmt not in ("json", *REPORT_FORMATS):
        raise ApiError(400, "validation_error", "format must be json, html, pdf or csv", {"format": "invalid"})
    if kind not in ("technical", "executive"):
        raise ApiError(400, "validation_error", "type must be technical or executive", {"type": "invalid"})
    if fmt == "csv" and kind == "executive":
        raise ApiError(400, "validation_error", "CSV is available for the technical report", {"format": "csv_technical_only"})
    if audit["status"] != "completed":
        raise ApiError.conflict("Reports are available once the audit has completed")
    if kind == "technical":
        findings.build_query(identity.org_id, audit["_id"], request.args)  # validates filter values (400)
    comparison = None
    if kind == "executive":
        base = comparison_service.previous_completed(audit)
        comparison = comparison_service.compare(audit, base) if base else None
    data = report_model.build_report(audit, kind, request.args, comparison)
    log_event("report.downloaded", org_id=identity.org_id, user_id=identity.user_id,
              details={"audit_id": audit_id, "format": fmt, "type": kind})
    if fmt == "json":
        return ok(data)
    mimetype, ext = REPORT_FORMATS[fmt]
    body = {"html": render_html.render, "pdf": render_pdf.render, "csv": render_csv.render}[fmt](data)
    resp = Response(body, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{_filename(audit, data["repository"]["name"], kind, ext)}"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.get("/<audit_id>/comparison")
@login_required
def comparison(audit_id: str):
    """PRD §60: new / resolved / unchanged / reopened vs ?base= (default: the previous completed audit)."""
    identity = current_identity()
    target = audit_service.get_audit(identity.org_id, parse_id(audit_id, "Audit"))
    base_id = parse_id(request.args["base"], "Audit") if request.args.get("base") else None
    base = comparison_service.get_base(identity.org_id, target, base_id)
    return ok(comparison_service.compare(target, base))


@bp.post("/<audit_id>/cancel")
@require_role(*CAN_RUN_AUDITS)
def cancel_audit(audit_id: str):
    identity = current_identity()
    audit = audit_service.cancel(identity.org_id, identity.user_id, parse_id(audit_id, "Audit"))
    return ok(audit_service.serialize_status(audit), 202)


@bp.delete("/<audit_id>")
@require_role(*CAN_MANAGE_REPOS)
def delete_audit(audit_id: str):
    identity = current_identity()
    audit_service.delete(identity.org_id, identity.user_id, parse_id(audit_id, "Audit"))
    return no_content()
