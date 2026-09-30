"""Organization settings, members and the activity log (PRD §56, §57, §81).

Role rules (enforced here, server-side):
- owner: everything, including granting/removing owner and admin.
- admin: manage repositories and developer/viewer members; can't touch owners or admins.
- The last owner can't be removed or demoted. Anyone may leave (remove themselves) unless last owner.
"""
import re
from datetime import datetime

from bson import ObjectId
from pymongo import ReturnDocument

from ..constants import ROLES
from ..db import get_db
from ..db.utils import id_str, iso, parse_id, utcnow
from ..errors import ApiError
from .audit_log import log_event
from .auth_service import Identity

PRIVILEGED = ("owner", "admin")
RETENTION_CHOICES = (0, 7, 30, 90, 180, 365)  # days; 0 = keep forever


def serialize_org(org: dict, identity: Identity) -> dict:
    return {
        "id": id_str(org["_id"]), "name": org["name"], "plan": org.get("plan"),
        "retention": {"audit_days": 90, "source_days": 0, **(org.get("retention") or {})},
        "member_count": len(org.get("members") or []),
        "role": identity.role, "created_at": iso(org.get("created_at")),
    }


def update_org(identity: Identity, name: str | None, retention: dict | None) -> dict:
    changes, fields = {}, []
    if name is not None:
        changes["name"] = name
        fields.append("name")
    if retention is not None:
        for key in ("audit_days", "source_days"):
            if key in retention:
                changes[f"retention.{key}"] = retention[key]
                fields.append(f"retention.{key}")
    if not changes:
        return identity.org
    changes["updated_at"] = utcnow()
    org = get_db().organizations.find_one_and_update({"_id": identity.org_id}, {"$set": changes},
                                                     return_document=ReturnDocument.AFTER)
    log_event("organization.updated", org_id=identity.org_id, user_id=identity.user_id,
              details={"fields": fields, **({"retention": org.get("retention")} if retention else {})})
    return org


def list_members(org: dict) -> list[dict]:
    members = org.get("members") or []
    users = {u["_id"]: u for u in get_db().users.find({"_id": {"$in": [m["user_id"] for m in members]}},
                                                        {"name": 1, "email": 1, "status": 1})}
    rank = {r: i for i, r in enumerate(ROLES)}
    out = []
    for m in members:
        u = users.get(m["user_id"], {})
        out.append({"user_id": id_str(m["user_id"]), "name": u.get("name"), "email": u.get("email"),
                    "status": u.get("status"), "role": m["role"], "joined_at": iso(m.get("joined_at")),
                    "is_owner_of_record": m["user_id"] == org.get("owner_id")})
    return sorted(out, key=lambda m: (rank.get(m["role"], 9), (m["name"] or "").lower()))


def _check_can_manage(identity: Identity, target_role: str | None, new_role: str | None = None) -> None:
    if identity.role == "owner":
        return
    if identity.role != "admin":
        raise ApiError.forbidden()
    if target_role in PRIVILEGED or new_role in PRIVILEGED:
        raise ApiError.forbidden("Only an owner can add, change or remove owners and admins")


def _owners(org: dict) -> int:
    return sum(1 for m in org.get("members") or [] if m["role"] == "owner")


def add_member(identity: Identity, email: str, role: str) -> dict:
    """Add an existing user by email. (Without an email service there are no invitation mails:
    the person registers first, then an admin adds them.)"""
    _check_can_manage(identity, None, role)
    db = get_db()
    user = db.users.find_one({"email": email.strip().lower(), "status": "active"})
    if user is None:
        raise ApiError(404, "user_not_found", "No active account uses that email. Ask them to register first, then add them.")
    member = {"user_id": user["_id"], "role": role, "joined_at": utcnow()}
    org = db.organizations.find_one_and_update(
        {"_id": identity.org_id, "members.user_id": {"$ne": user["_id"]}},
        {"$push": {"members": member}, "$set": {"updated_at": utcnow()}}, return_document=ReturnDocument.AFTER)
    if org is None:
        raise ApiError.conflict("That person is already a member")
    log_event("member.added", org_id=identity.org_id, user_id=identity.user_id,
              details={"member_id": id_str(user["_id"]), "role": role})
    return next(m for m in list_members(org) if m["user_id"] == id_str(user["_id"]))


def _member(org: dict, user_id: ObjectId) -> dict:
    m = next((m for m in org.get("members") or [] if m["user_id"] == user_id), None)
    if m is None:
        raise ApiError.not_found("Member")
    return m


def change_role(identity: Identity, member_id: str, role: str) -> dict:
    uid = parse_id(member_id, "Member")
    db = get_db()
    org = db.organizations.find_one({"_id": identity.org_id})
    target = _member(org, uid)
    if target["role"] == role:
        return next(m for m in list_members(org) if m["user_id"] == member_id)
    _check_can_manage(identity, target["role"], role)
    if target["role"] == "owner" and _owners(org) <= 1:
        raise ApiError.conflict("An organization needs at least one owner; make someone else owner first")
    # Guard on the current role so concurrent changes can't both pass the last-owner check.
    org = db.organizations.find_one_and_update(
        {"_id": identity.org_id, "members": {"$elemMatch": {"user_id": uid, "role": target["role"]}}},
        {"$set": {"members.$.role": role, "updated_at": utcnow()}}, return_document=ReturnDocument.AFTER)
    if org is None:
        raise ApiError.conflict("The member was changed by someone else; reload and try again")
    if _owners(org) == 0:  # lost a race: restore
        db.organizations.update_one({"_id": identity.org_id, "members.user_id": uid}, {"$set": {"members.$.role": "owner"}})
        raise ApiError.conflict("An organization needs at least one owner")
    log_event("member.role_changed", org_id=identity.org_id, user_id=identity.user_id,
              details={"member_id": member_id, "from": target["role"], "to": role})
    return next(m for m in list_members(org) if m["user_id"] == member_id)


def remove_member(identity: Identity, member_id: str) -> None:
    uid = parse_id(member_id, "Member")
    db = get_db()
    org = db.organizations.find_one({"_id": identity.org_id})
    target = _member(org, uid)
    if uid != identity.user_id:  # leaving yourself is always allowed (except last owner)
        _check_can_manage(identity, target["role"])
    if target["role"] == "owner" and _owners(org) <= 1:
        raise ApiError.conflict("The last owner can't leave or be removed; make someone else owner first")
    db.organizations.update_one({"_id": identity.org_id}, {"$pull": {"members": {"user_id": uid}},
                                                           "$set": {"updated_at": utcnow()}})
    # Their access tokens stop working immediately (membership is checked per request); refresh
    # tokens pointing at this organization fall back to another one or end the session.
    log_event("member.removed" if uid != identity.user_id else "member.left", org_id=identity.org_id,
              user_id=identity.user_id, details={"member_id": member_id, "role": target["role"]})


# ---- activity log (PRD §57) ----

def list_audit_logs(org_id: ObjectId, *, event: str | None, user_id: str | None, since: str | None,
                    until: str | None, page: int, per_page: int) -> tuple[list[dict], int]:
    query: dict = {"organization_id": org_id}
    if event:  # exact ("audit.completed") or prefix ("audit.*")
        if not re.fullmatch(r"[a-z_]+(\.[a-z_]+|\.\*)?", event):
            raise ApiError(400, "validation_error", "Invalid event filter", {"event": "invalid"})
        query["event"] = {"$regex": "^" + re.escape(event[:-1])} if event.endswith(".*") else event
    if user_id:
        query["user_id"] = parse_id(user_id, "User")
    for key, value, op in (("since", since, "$gte"), ("until", until, "$lte")):
        if value:
            try:
                query.setdefault("created_at", {})[op] = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                raise ApiError(400, "validation_error", f"{key} must be an ISO date", {key: "invalid"})
    col = get_db().audit_logs
    total = col.count_documents(query)
    items = list(col.find(query).sort([("created_at", -1), ("_id", -1)]).skip((page - 1) * per_page).limit(per_page))
    return items, total


def serialize_log(doc: dict, users: dict) -> dict:
    details = dict(doc.get("details") or {})
    member_id = details.get("member_id")
    if ObjectId.is_valid(member_id) and ObjectId(member_id) in users:
        details["member"] = users[ObjectId(member_id)]  # readable name next to the id
    return {"id": id_str(doc["_id"]), "event": doc["event"], "at": iso(doc["created_at"]),
            "user": users.get(doc.get("user_id")) if doc.get("user_id") else None,
            "user_id": id_str(doc.get("user_id")), "ip_address": doc.get("ip_address"),
            "details": details}
