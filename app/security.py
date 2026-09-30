"""Bearer-token authentication, role checks and cookie-endpoint CSRF defence.

Every organization-owned query must use `current_identity().org_id` so tenant
isolation is enforced server-side (PRD §54).
"""
from functools import wraps

from bson import ObjectId
from flask import current_app, g, request

from .errors import ApiError
from .services.auth_service import Identity, load_identity
from .services import rate_limit
from .services.tokens import decode_access_token


def authenticate_request() -> Identity:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError.unauthorized("Missing bearer token")
    claims = decode_access_token(token.strip())
    identity = load_identity(ObjectId(claims["sub"]), ObjectId(claims["org"]))
    if identity is None:
        raise ApiError.unauthorized("Account or organization access is no longer valid")
    g.identity = identity
    rate_limit.check("api_user", str(identity.user_id))  # generous ceiling against scripted abuse
    return identity


def current_identity() -> Identity:
    identity = g.get("identity")
    if identity is None:
        raise ApiError.unauthorized()
    return identity


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        authenticate_request()
        return view(*args, **kwargs)

    return wrapped


def require_role(*roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            identity = authenticate_request()
            if identity.role not in roles:
                raise ApiError.forbidden()
            return view(*args, **kwargs)

        return wrapped

    return decorator


def allowed_origins() -> set[str]:
    return set(current_app.config["ALLOWED_ORIGINS"]) | {request.host_url.rstrip("/")}


def check_cookie_request() -> None:
    """CSRF defence for endpoints that read the refresh cookie (PRD §43.3)."""
    if request.headers.get("X-Requested-With") != "fetch":
        raise ApiError.forbidden("Missing X-Requested-With header", code="csrf_failed")
    if request.headers.get("Origin", "").rstrip("/") not in allowed_origins():
        raise ApiError.forbidden("Origin not allowed", code="csrf_failed")
