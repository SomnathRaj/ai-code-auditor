from flask import Blueprint
from pymongo.errors import PyMongoError

from ..db import get_db
from ..errors import error_response
from .common import ok
from .openapi import build_spec

bp = Blueprint("meta", __name__)


@bp.get("/health")
def health():
    try:
        get_db().command("ping")
    except PyMongoError:
        return error_response(503, "service_unavailable", "Database unavailable", {"database": "down"})
    return ok({"status": "ok", "database": "ok"})


@bp.get("/openapi.json")
def openapi():
    return build_spec()
