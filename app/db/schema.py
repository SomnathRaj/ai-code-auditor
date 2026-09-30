"""Collection validators and indexes (PRD §41.2). Applied by `flask init-db`; idempotent."""
from pymongo import ASCENDING as ASC
from pymongo import DESCENDING as DESC
from pymongo import IndexModel
from pymongo.database import Database

from ..constants import (
    AUDIT_STATUSES, AUDIT_TYPES, FINDING_STATUSES, REPOSITORY_PROVIDERS, ROLES, SEVERITIES,
)

OID = {"bsonType": "objectId"}
DATE = {"bsonType": "date"}
OPT_DATE = {"bsonType": ["date", "null"]}
STR = {"bsonType": "string"}
OPT_STR = {"bsonType": ["string", "null"]}


def _enum(values):
    return {"enum": list(values)}


def _schema(required: list[str], properties: dict) -> dict:
    return {"$jsonSchema": {"bsonType": "object", "required": required, "properties": properties}}


COLLECTIONS: dict[str, dict] = {
    "users": {
        "validator": _schema(
            ["name", "email", "password_hash", "status", "created_at", "updated_at"],
            {
                "name": {"bsonType": "string", "minLength": 1, "maxLength": 120},
                "email": {"bsonType": "string", "maxLength": 255},
                "password_hash": STR,
                "status": _enum(("active", "disabled")),
                "email_verified_at": OPT_DATE,
                "last_organization_id": {"bsonType": ["objectId", "null"]},
                "created_at": DATE,
                "updated_at": DATE,
            },
        ),
        "indexes": [IndexModel([("email", ASC)], unique=True, name="email_unique")],
    },
    "organizations": {
        "validator": _schema(
            ["name", "owner_id", "plan", "members", "audit_counter", "created_at", "updated_at"],
            {
                "name": {"bsonType": "string", "minLength": 1, "maxLength": 120},
                "owner_id": OID,
                "plan": STR,
                "members": {
                    "bsonType": "array",
                    "items": {
                        "bsonType": "object",
                        "required": ["user_id", "role", "joined_at"],
                        "properties": {"user_id": OID, "role": _enum(ROLES), "joined_at": DATE},
                    },
                },
                "audit_counter": {"bsonType": ["int", "long"], "minimum": 0},
                "created_at": DATE,
                "updated_at": DATE,
            },
        ),
        "indexes": [IndexModel([("members.user_id", ASC)], name="member_user")],
    },
    "repositories": {
        "validator": _schema(
            ["organization_id", "name", "provider", "default_branch", "status", "settings", "created_at", "updated_at"],
            {
                "organization_id": OID,
                "name": {"bsonType": "string", "minLength": 1, "maxLength": 200},
                "provider": _enum(REPOSITORY_PROVIDERS),
                "url": OPT_STR,
                "default_branch": OPT_STR,  # null for ZIP uploads
                "source": {"bsonType": ["object", "null"]},
                "credentials": {
                    "bsonType": ["object", "null"],
                    "properties": {"encrypted_token": STR},
                },
                "language": OPT_STR,
                "framework": OPT_STR,
                "status": STR,
                "settings": {
                    "bsonType": "object",
                    "required": ["enabled_scanners", "excluded_paths", "severity_threshold", "ai_enabled"],
                    "properties": {
                        "enabled_scanners": {"bsonType": "array", "items": STR},
                        "excluded_paths": {"bsonType": "array", "items": STR},
                        "severity_threshold": _enum(SEVERITIES),
                        "ai_enabled": {"bsonType": "bool"},
                    },
                },
                "last_audit": {"bsonType": ["object", "null"]},
                "created_at": DATE,
                "updated_at": DATE,
            },
        ),
        "indexes": [
            IndexModel([("organization_id", ASC), ("name", ASC)], name="org_name"),
            IndexModel(
                [("organization_id", ASC), ("url", ASC)],
                unique=True,
                partialFilterExpression={"url": {"$type": "string"}},  # ZIP repos have no URL
                name="org_url_unique",
            ),
        ],
    },
    "audits": {
        "validator": _schema(
            ["organization_id", "repository_id", "audit_number", "branch", "audit_type", "status",
             "created_at", "updated_at"],
            {
                "organization_id": OID,
                "repository_id": OID,
                "audit_number": {"bsonType": ["int", "long"]},
                "branch": STR,
                "audit_type": _enum(AUDIT_TYPES),
                "status": _enum(AUDIT_STATUSES),
                "started_at": OPT_DATE,
                "completed_at": OPT_DATE,
                "created_at": DATE,
                "updated_at": DATE,
            },
        ),
        "indexes": [
            IndexModel([("organization_id", ASC), ("repository_id", ASC), ("created_at", DESC)], name="org_repo_created"),
            IndexModel([("organization_id", ASC), ("created_at", DESC)], name="org_created"),
            IndexModel([("status", ASC), ("created_at", ASC)], name="queue"),
            IndexModel([("organization_id", ASC), ("audit_number", ASC)], unique=True, name="org_number_unique"),
            # At most one queued/running audit per repository (the flag is removed when it finishes).
            IndexModel([("repository_id", ASC)], unique=True, partialFilterExpression={"active": True},
                       name="one_active_per_repo"),
            IndexModel([("status", ASC), ("worker.heartbeat_at", ASC)], name="stale_scan"),
        ],
    },
    "findings": {
        "validator": _schema(
            ["organization_id", "repository_id", "audit_id", "fingerprint", "title", "severity", "status",
             "created_at", "updated_at"],
            {
                "organization_id": OID,
                "repository_id": OID,
                "audit_id": OID,
                "fingerprint": STR,
                "title": STR,
                "severity": _enum(SEVERITIES),
                "status": _enum(FINDING_STATUSES),
                "confidence": {"bsonType": ["double", "int", "null"], "minimum": 0, "maximum": 1},
                "created_at": DATE,
                "updated_at": DATE,
            },
        ),
        "indexes": [
            IndexModel(
                [("organization_id", ASC), ("audit_id", ASC), ("severity", ASC), ("status", ASC)],
                name="org_audit_sev_status",
            ),
            IndexModel([("organization_id", ASC), ("repository_id", ASC), ("fingerprint", ASC)], name="org_repo_fp"),
        ],
    },
    "finding_comments": {
        "validator": _schema(
            ["organization_id", "finding_id", "user_id", "body", "created_at"],
            {"organization_id": OID, "finding_id": OID, "user_id": OID, "body": STR, "created_at": DATE},
        ),
        "indexes": [
            IndexModel([("organization_id", ASC), ("finding_id", ASC), ("created_at", ASC)], name="org_finding"),
            IndexModel([("organization_id", ASC), ("repository_id", ASC), ("fingerprint", ASC)], name="org_repo_fp"),
        ],
    },
    "dependencies": {
        "validator": _schema(
            ["organization_id", "repository_id", "audit_id", "package_name", "ecosystem"],
            {"organization_id": OID, "repository_id": OID, "audit_id": OID, "package_name": STR, "ecosystem": STR},
        ),
        "indexes": [
            IndexModel([("organization_id", ASC), ("audit_id", ASC), ("vulnerable", DESC), ("package_name", ASC)],
                       name="org_audit_vuln_pkg"),
            IndexModel([("organization_id", ASC), ("repository_id", ASC), ("package_name", ASC)], name="org_repo_pkg"),
        ],
    },
    # AI analyses keyed by (organization, rule, file, code, model, prompt version) — never shared across tenants.
    "ai_cache": {
        "validator": _schema(["organization_id", "analysis", "created_at"],
                             {"organization_id": OID, "analysis": {"bsonType": "object"}, "created_at": DATE}),
        "indexes": [
            IndexModel([("organization_id", ASC)], name="org"),
            IndexModel([("created_at", ASC)], expireAfterSeconds=30 * 24 * 3600, name="created_ttl"),
        ],
    },
    # Rate-limit windows ("name:key:window_start" → count); expired windows removed by TTL.
    "rate_limits": {
        "validator": _schema(["count", "expires_at"], {"count": {"bsonType": ["int", "long"]}, "expires_at": DATE}),
        "indexes": [IndexModel([("expires_at", ASC)], expireAfterSeconds=0, name="expires_ttl")],
    },
    # OSV vulnerability details, shared across organizations (public data, no tenant info).
    "vuln_cache": {
        "validator": _schema(["data", "fetched_at"], {"data": {"bsonType": "object"}, "fetched_at": DATE}),
        "indexes": [IndexModel([("fetched_at", ASC)], expireAfterSeconds=7 * 24 * 3600, name="fetched_ttl")],
    },
    "refresh_tokens": {
        "validator": _schema(
            ["user_id", "organization_id", "token_hash", "family_id", "expires_at", "created_at"],
            {
                "user_id": OID,
                "organization_id": OID,
                "token_hash": STR,
                "family_id": STR,
                "expires_at": DATE,
                "rotated_at": OPT_DATE,
                "revoked_at": OPT_DATE,
                "created_at": DATE,
            },
        ),
        "indexes": [
            IndexModel([("token_hash", ASC)], unique=True, name="hash_unique"),
            IndexModel([("family_id", ASC)], name="family"),
            IndexModel([("expires_at", ASC)], expireAfterSeconds=0, name="expires_ttl"),
        ],
    },
    "audit_logs": {
        "validator": _schema(
            ["event", "created_at"],
            {"organization_id": {"bsonType": ["objectId", "null"]}, "user_id": {"bsonType": ["objectId", "null"]},
             "event": STR, "created_at": DATE},
        ),
        "indexes": [
            IndexModel([("organization_id", ASC), ("created_at", DESC)], name="org_created"),
            IndexModel([("organization_id", ASC), ("event", ASC)], name="org_event"),
        ],
    },
}


def ensure_schema(db: Database) -> list[str]:
    """Create collections with validators (or update them) and create indexes."""
    existing = set(db.list_collection_names())
    for name, spec in COLLECTIONS.items():
        if name in existing:
            db.command("collMod", name, validator=spec["validator"], validationLevel="strict")
        else:
            db.create_collection(name, validator=spec["validator"], validationLevel="strict")
        wanted = {ix.document["name"] for ix in spec["indexes"]}
        for existing_name in db[name].index_information():
            if existing_name != "_id_" and existing_name not in wanted:
                db[name].drop_index(existing_name)  # replaced by a renamed/changed index
        db[name].create_indexes(spec["indexes"])
    return list(COLLECTIONS)
