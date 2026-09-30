import re
from datetime import datetime, timezone

from bson import ObjectId

from ..errors import ApiError

_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{24}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_id(value: str, what: str = "Resource") -> ObjectId:
    """Parse an ID from a URL or body. Malformed IDs are reported as not found."""
    if not isinstance(value, str) or not _OBJECT_ID_RE.match(value):
        raise ApiError.not_found(what)
    return ObjectId(value)


def id_str(value) -> str | None:
    return str(value) if value is not None else None
