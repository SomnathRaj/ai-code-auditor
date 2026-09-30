from flask import has_request_context, request

from ..db import get_db
from ..db.utils import utcnow


def log_event(event: str, *, org_id=None, user_id=None, details: dict | None = None, session=None) -> None:
    """Record an activity-log event (PRD §57). Never pass secrets or credentials in `details`."""
    get_db().audit_logs.insert_one(
        {
            "organization_id": org_id,
            "user_id": user_id,
            "event": event,
            "details": details,
            "ip_address": request.remote_addr if has_request_context() else None,
            "created_at": utcnow(),
        },
        session=session,
    )
