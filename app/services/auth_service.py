from dataclasses import dataclass

from bson import ObjectId
from pymongo.errors import DuplicateKeyError
from werkzeug.security import check_password_hash, generate_password_hash

from ..db import get_db, run_in_transaction
from ..db.utils import id_str, iso, utcnow
from ..errors import ApiError
from .audit_log import log_event

# Used to equalize timing when the email doesn't exist.
_DUMMY_HASH = generate_password_hash("timing-equalizer")


@dataclass
class Identity:
    user: dict
    org: dict
    role: str

    @property
    def user_id(self) -> ObjectId:
        return self.user["_id"]

    @property
    def org_id(self) -> ObjectId:
        return self.org["_id"]


def member_role(org: dict, user_id: ObjectId) -> str | None:
    for m in org.get("members", []):
        if m["user_id"] == user_id:
            return m["role"]
    return None


def serialize_user(user: dict) -> dict:
    return {"id": id_str(user["_id"]), "name": user["name"], "email": user["email"], "created_at": iso(user["created_at"])}


def serialize_org(org: dict) -> dict:
    return {"id": id_str(org["_id"]), "name": org["name"], "plan": org["plan"]}


def serialize_identity(identity: Identity) -> dict:
    return {"user": serialize_user(identity.user), "organization": serialize_org(identity.org), "role": identity.role}


def load_identity(user_id: ObjectId, org_id: ObjectId) -> Identity | None:
    """Re-check on every request that the user is active and still a member (PRD §54)."""
    db = get_db()
    user = db.users.find_one({"_id": user_id, "status": "active"})
    if user is None:
        return None
    org = db.organizations.find_one({"_id": org_id, "members.user_id": user_id})
    if org is None:
        return None
    return Identity(user=user, org=org, role=member_role(org, user_id))


def user_organizations(user_id: ObjectId) -> list[dict]:
    return list(get_db().organizations.find({"members.user_id": user_id}).sort("_id", 1))


def default_identity(user: dict) -> Identity | None:
    """The organization the user last switched to (if still a member), else their own, else the oldest."""
    orgs = user_organizations(user["_id"])
    if not orgs:
        return None
    org = (next((o for o in orgs if o["_id"] == user.get("last_organization_id")), None)
           or next((o for o in orgs if o.get("owner_id") == user["_id"]), None) or orgs[0])
    return Identity(user=user, org=org, role=member_role(org, user["_id"]))


def register(name: str, email: str, password: str, org_name: str | None) -> Identity:
    db = get_db()
    if db.users.find_one({"email": email}, {"_id": 1}):
        raise ApiError.conflict("An account with this email already exists")

    now = utcnow()
    user = {
        "name": name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "status": "active",
        "email_verified_at": None,
        "created_at": now,
        "updated_at": now,
    }

    def create(session):
        user_doc = dict(user)
        user_doc["_id"] = db.users.insert_one(user_doc, session=session).inserted_id
        try:
            org = {
                "name": org_name or f"{name}'s Workspace",
                "owner_id": user_doc["_id"],
                "plan": "free",
                "members": [{"user_id": user_doc["_id"], "role": "owner", "joined_at": now}],
                "retention": {"audit_days": 90, "source_days": 0},
                "audit_counter": 0,
                "created_at": now,
                "updated_at": now,
            }
            org["_id"] = db.organizations.insert_one(org, session=session).inserted_id
            log_event("user.registered", org_id=org["_id"], user_id=user_doc["_id"], session=session)
        except Exception:
            if session is None:  # no transaction: undo the user insert ourselves
                db.users.delete_one({"_id": user_doc["_id"]})
            raise
        return Identity(user=user_doc, org=org, role="owner")

    try:
        return run_in_transaction(create)
    except DuplicateKeyError:
        raise ApiError.conflict("An account with this email already exists")


def login(email: str, password: str) -> Identity:
    user = get_db().users.find_one({"email": email})
    if user is None:
        check_password_hash(_DUMMY_HASH, password)
        raise ApiError.unauthorized("Invalid email or password")
    if not check_password_hash(user["password_hash"], password) or user["status"] != "active":
        log_event("user.login_failed", user_id=user["_id"])
        raise ApiError.unauthorized("Invalid email or password")

    identity = default_identity(user)
    if identity is None:
        raise ApiError.forbidden("This account does not belong to any organization")
    log_event("user.login", org_id=identity.org_id, user_id=identity.user_id)
    return identity
