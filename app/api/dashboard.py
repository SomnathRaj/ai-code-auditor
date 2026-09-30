from flask import Blueprint, request

from ..security import current_identity, login_required
from ..errors import ApiError
from ..services.dashboard_service import dashboard as build_dashboard
from ..services.dashboard_service import trends as build_trends
from .common import ok

bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@bp.get("")
@login_required
def dashboard():
    return ok(build_dashboard(current_identity().org_id))


@bp.get("/trends")
@login_required
def trends():
    """PRD §59: organization risk over time, resolved this month, recurring issues. ?days=30|90|365"""
    try:
        days = int(request.args.get("days", 90))
    except ValueError:
        days = 0
    if days not in (7, 30, 90, 180, 365):
        raise ApiError(400, "validation_error", "days must be 7, 30, 90, 180 or 365", {"days": "invalid"})
    return ok(build_trends(current_identity().org_id, days))
