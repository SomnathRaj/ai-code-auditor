from flask import Blueprint, current_app

from ..ai import providers
from ..security import current_identity, login_required
from ..services.auth_service import member_role, serialize_identity, serialize_org, user_organizations
from .common import ok

bp = Blueprint("me", __name__, url_prefix="/me")


@bp.get("")
@login_required
def me():
    return ok(serialize_identity(current_identity()))


@bp.get("/features")
@login_required
def features():
    """What the UI should disclose (PRD §52): whether code is sent to an AI provider, and which."""
    provider = providers.provider_from_config(current_app.config)
    return ok({
        "ai": {"configured": provider is not None, "provider": "Google Gemini" if provider else None,
               "model": provider.model if provider else None,
               "min_severity": current_app.config["AI_MIN_SEVERITY"],
               "max_findings": current_app.config["AI_MAX_FINDINGS"]},
        "osv": {"enabled": current_app.config["OSV_ENABLED"]},
    })


@bp.get("/organizations")
@login_required
def organizations():
    identity = current_identity()
    return ok([
        {**serialize_org(org), "role": member_role(org, identity.user_id), "current": org["_id"] == identity.org_id}
        for org in user_organizations(identity.user_id)
    ])
