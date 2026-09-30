"""Rate limiting backed by MongoDB (no Redis, PRD §79): fixed windows counted with one
atomic upsert per request; a TTL index removes old windows.

    @rate_limited("login_ip", key=client_ip)          # per IP
    check("login_fail", email, limit=10, window=900)  # per account, counted manually

Exceeding a limit returns 429 with Retry-After and X-RateLimit-* headers.
"""
import time
from datetime import timedelta
from functools import wraps

from flask import current_app, g, request
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from ..db import get_db
from ..db.utils import utcnow
from ..errors import ApiError

# name → (requests, window seconds). Override per deployment with RATE_LIMITS in config.
DEFAULT_LIMITS = {
    "login_ip": (20, 60),            # login attempts per IP per minute
    "login_fail": (10, 900),         # failed logins per account per 15 minutes (credential stuffing)
    "register_ip": (10, 3600),       # new accounts per IP per hour
    "refresh_ip": (120, 60),         # token refreshes per IP per minute
    "audit_start": (30, 3600),       # audits queued per organization per hour
    "upload": (30, 3600),            # ZIP uploads per organization per hour
    "report": (30, 600),             # report generations per user per 10 minutes (PDF is CPU-heavy)
    "comment": (60, 600),            # comments per user per 10 minutes
    "api_user": (1200, 60),          # any authenticated API call per user per minute
}


def client_ip() -> str:
    """Client address (behind Nginx set PROXY_FIX=1 so this is the real client, not the proxy)."""
    return request.remote_addr or "unknown"


def _limits() -> dict:
    return {**DEFAULT_LIMITS, **(current_app.config.get("RATE_LIMITS") or {})}


def hit(name: str, key: str, *, count: bool = True) -> tuple[int, int, int]:
    """Register one request (or just read the counter). Returns (used, limit, retry_after_seconds)."""
    limit, window = _limits()[name]
    now = int(time.time())
    window_start = now - now % window
    doc_id = f"{name}:{key}:{window_start}"
    col = get_db().rate_limits
    if count:
        try:
            doc = col.find_one_and_update(
                {"_id": doc_id},
                {"$inc": {"count": 1},
                 "$setOnInsert": {"expires_at": utcnow() + timedelta(seconds=window * 2)}},
                upsert=True, return_document=ReturnDocument.AFTER)
        except DuplicateKeyError:  # two first requests raced on the upsert
            doc = col.find_one_and_update({"_id": doc_id}, {"$inc": {"count": 1}}, return_document=ReturnDocument.AFTER)
    else:
        doc = col.find_one({"_id": doc_id}) or {"count": 0}
    return doc["count"], limit, window_start + window - now


def check(name: str, key: str, *, count: bool = True) -> None:
    """Raise 429 if the limit is exceeded."""
    if not current_app.config.get("RATE_LIMIT_ENABLED", True):
        return
    used, limit, retry_after = hit(name, key, count=count)
    g.rate_limit = (limit, max(limit - used, 0), retry_after)
    if used > limit:
        raise RateLimited(retry_after)


class RateLimited(ApiError):
    def __init__(self, retry_after: int):
        super().__init__(429, "rate_limited", f"Too many requests. Try again in {retry_after} seconds.",
                         {"retry_after": retry_after})
        self.retry_after = retry_after


def rate_limited(name: str, key=client_ip):
    """Decorator: count every call to the view against `name`, keyed by key() (default: client IP)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            check(name, key())
            return view(*args, **kwargs)
        return wrapped
    return decorator


def add_headers(resp):
    """after_request: expose the most recent limit that applied to this request."""
    info = g.get("rate_limit")
    if info:
        limit, remaining, retry_after = info
        resp.headers["X-RateLimit-Limit"] = str(limit)
        resp.headers["X-RateLimit-Remaining"] = str(remaining)
        if resp.status_code == 429:
            resp.headers["Retry-After"] = str(retry_after)
    return resp
