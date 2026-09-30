from flask import Blueprint, current_app, request

from ..db import get_db
from ..db.utils import parse_id
from ..errors import ApiError
from ..security import check_cookie_request, current_identity, login_required
from ..services import auth_service, tokens
from ..services.audit_log import log_event
from ..services import rate_limit
from ..services.auth_service import Identity, serialize_identity
from ..services.rate_limit import RateLimited, rate_limited
from .common import no_content, ok, parse_body
from .schemas import LoginIn, RegisterIn, SwitchOrganizationIn

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _token_payload(identity: Identity) -> dict:
    access_token, expires_in = tokens.create_access_token(identity.user_id, identity.org_id, identity.role)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        **serialize_identity(identity),
    }


def _set_refresh_cookie(resp, raw: str):
    cfg = current_app.config
    resp.set_cookie(
        cfg["REFRESH_COOKIE_NAME"],
        raw,
        max_age=int(cfg["REFRESH_TOKEN_TTL"].total_seconds()),
        path=cfg["REFRESH_COOKIE_PATH"],
        secure=cfg["COOKIE_SECURE"],
        httponly=True,
        samesite="Strict",
    )
    return resp


def _clear_refresh_cookie(resp):
    cfg = current_app.config
    resp.delete_cookie(
        cfg["REFRESH_COOKIE_NAME"], path=cfg["REFRESH_COOKIE_PATH"],
        secure=cfg["COOKIE_SECURE"], httponly=True, samesite="Strict",
    )
    return resp


def _refresh_cookie() -> str | None:
    return request.cookies.get(current_app.config["REFRESH_COOKIE_NAME"])


def _start_session(identity: Identity, status: int = 200, headers: dict | None = None):
    raw = tokens.issue_refresh_token(identity.user_id, identity.org_id)
    return _set_refresh_cookie(ok(_token_payload(identity), status, headers), raw)


@bp.post("/register")
@rate_limited("register_ip")
def register():
    body = parse_body(RegisterIn)
    identity = auth_service.register(body.name, body.email, body.password, body.organization_name)
    return _start_session(identity, 201, {"Location": "/api/v1/me"})


@bp.post("/login")
@rate_limited("login_ip")
def login():
    body = parse_body(LoginIn)
    # Per-account cap on failed attempts (credential stuffing across many IPs). Only failures count.
    if current_app.config.get("RATE_LIMIT_ENABLED", True):
        failed, limit, retry_after = rate_limit.hit("login_fail", body.email, count=False)
        if failed >= limit:
            log_event("auth.login_throttled", details={"reason": "too_many_failures"})
            raise RateLimited(retry_after)
    try:
        identity = auth_service.login(body.email, body.password)
    except ApiError as err:
        if err.status == 401 and current_app.config.get("RATE_LIMIT_ENABLED", True):
            rate_limit.hit("login_fail", body.email)
        raise
    return _start_session(identity)


@bp.post("/refresh")
@rate_limited("refresh_ip")
def refresh():
    check_cookie_request()
    raw = _refresh_cookie()
    if not raw:
        raise ApiError.unauthorized("Not logged in")
    new_raw, doc = tokens.rotate_refresh_token(raw)
    identity = auth_service.load_identity(doc["user_id"], doc["organization_id"])
    if identity is None:
        # Removed from that organization: fall back to another one, if any.
        user = get_db().users.find_one({"_id": doc["user_id"], "status": "active"})
        identity = auth_service.default_identity(user) if user else None
        if identity is None:
            tokens.revoke_family(doc["family_id"])
            raise ApiError.unauthorized("Account or organization access is no longer valid")
        if new_raw:
            tokens.set_refresh_token_org(new_raw, identity.org_id)
    resp = ok(_token_payload(identity))
    return _set_refresh_cookie(resp, new_raw) if new_raw else resp


@bp.post("/logout")
def logout():
    check_cookie_request()
    raw = _refresh_cookie()
    if raw:
        doc = tokens.find_active_refresh_token(raw)
        if doc:
            tokens.revoke_family(doc["family_id"])
            log_event("user.logout", org_id=doc["organization_id"], user_id=doc["user_id"])
    return _clear_refresh_cookie(no_content())


@bp.post("/switch-organization")
@login_required
def switch_organization():
    body = parse_body(SwitchOrganizationIn)
    user = current_identity().user
    org_id = parse_id(body.organization_id, "Organization")
    identity = auth_service.load_identity(user["_id"], org_id)
    if identity is None:
        raise ApiError.not_found("Organization")
    raw = _refresh_cookie()
    if raw:
        tokens.set_refresh_token_org(raw, org_id)
    get_db().users.update_one({"_id": user["_id"]}, {"$set": {"last_organization_id": org_id}})
    log_event("user.switched_organization", org_id=org_id, user_id=user["_id"])
    return ok(_token_payload(identity))
