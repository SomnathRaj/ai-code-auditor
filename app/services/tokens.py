"""Access tokens (JWT) and rotating refresh tokens (PRD §43.3)."""
import hashlib
import secrets
import uuid

import jwt
from bson import ObjectId
from flask import current_app

from ..db import get_db
from ..db.utils import utcnow
from ..errors import ApiError
from .audit_log import log_event


def create_access_token(user_id: ObjectId, org_id: ObjectId, role: str) -> tuple[str, int]:
    cfg = current_app.config
    now = utcnow()
    ttl = cfg["ACCESS_TOKEN_TTL"]
    payload = {
        "sub": str(user_id),
        "org": str(org_id),
        "role": role,  # informational; the API re-reads the role from the database
        "type": "access",
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(8),
    }
    token = jwt.encode(payload, cfg["JWT_SECRET"], algorithm=cfg["JWT_ALGORITHM"])
    return token, int(ttl.total_seconds())


def decode_access_token(token: str) -> dict:
    cfg = current_app.config
    try:
        claims = jwt.decode(
            token,
            cfg["JWT_SECRET"],
            algorithms=[cfg["JWT_ALGORITHM"]],
            options={"require": ["exp", "iat", "sub", "org", "type"]},
        )
    except jwt.ExpiredSignatureError:
        raise ApiError(401, "token_expired", "Access token has expired")
    except jwt.InvalidTokenError:
        raise ApiError.unauthorized("Invalid access token")
    if claims.get("type") != "access" or not ObjectId.is_valid(claims["sub"]) or not ObjectId.is_valid(claims["org"]):
        raise ApiError.unauthorized("Invalid access token")
    return claims


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def issue_refresh_token(user_id: ObjectId, org_id: ObjectId, family_id: str | None = None, session=None) -> str:
    raw = secrets.token_urlsafe(48)
    now = utcnow()
    get_db().refresh_tokens.insert_one(
        {
            "user_id": user_id,
            "organization_id": org_id,
            "token_hash": _hash(raw),
            "family_id": family_id or uuid.uuid4().hex,
            "expires_at": now + current_app.config["REFRESH_TOKEN_TTL"],
            "rotated_at": None,
            "revoked_at": None,
            "created_at": now,
        },
        session=session,
    )
    return raw


def revoke_family(family_id: str) -> None:
    get_db().refresh_tokens.update_many(
        {"family_id": family_id, "revoked_at": None}, {"$set": {"revoked_at": utcnow()}}
    )


def rotate_refresh_token(raw: str) -> tuple[str | None, dict]:
    """Exchange a refresh token for a new one.

    Returns (new_raw_token, token_doc). new_raw_token is None when the token was
    rotated moments ago by a concurrent request from the same browser: the caller
    should issue an access token but leave the cookie alone (the browser already
    holds the replacement). Reuse outside that grace window is treated as theft
    and revokes the whole token family.
    """
    tokens = get_db().refresh_tokens
    now = utcnow()
    doc = tokens.find_one({"token_hash": _hash(raw)})
    if doc is None or doc["expires_at"] <= now or doc.get("revoked_at"):
        raise ApiError.unauthorized("Session expired, please log in again")

    grace = current_app.config["REFRESH_REUSE_GRACE"]
    if doc.get("rotated_at") is None:
        claimed = tokens.find_one_and_update(
            {"_id": doc["_id"], "rotated_at": None, "revoked_at": None},
            {"$set": {"rotated_at": now}},
        )
        if claimed is not None:
            new_raw = issue_refresh_token(doc["user_id"], doc["organization_id"], doc["family_id"])
            return new_raw, doc
        doc = tokens.find_one({"_id": doc["_id"]})  # lost a race with a concurrent refresh
        if doc.get("revoked_at"):
            raise ApiError.unauthorized("Session expired, please log in again")

    if now - doc["rotated_at"] <= grace:
        return None, doc

    revoke_family(doc["family_id"])
    log_event("auth.refresh_token_reuse", org_id=doc["organization_id"], user_id=doc["user_id"])
    raise ApiError.unauthorized("Session expired, please log in again")


def find_active_refresh_token(raw: str) -> dict | None:
    return get_db().refresh_tokens.find_one(
        {"token_hash": _hash(raw), "revoked_at": None, "expires_at": {"$gt": utcnow()}}
    )


def set_refresh_token_org(raw: str, org_id: ObjectId) -> None:
    get_db().refresh_tokens.update_one(
        {"token_hash": _hash(raw), "revoked_at": None}, {"$set": {"organization_id": org_id}}
    )
