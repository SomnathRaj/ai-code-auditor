"""Response envelope, pagination and body validation helpers (PRD §43.2)."""
from typing import TypeVar

from flask import Response, jsonify, request
from pydantic import BaseModel

from ..errors import ApiError

MAX_PER_PAGE = 100
DEFAULT_PER_PAGE = 25

M = TypeVar("M", bound=BaseModel)


def ok(data, status: int = 200, headers: dict | None = None):
    resp = jsonify(data=data)
    resp.status_code = status
    for k, v in (headers or {}).items():
        resp.headers[k] = v
    return resp


def no_content() -> Response:
    return Response(status=204)


def pagination_args() -> tuple[int, int]:
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", DEFAULT_PER_PAGE))
    except ValueError:
        raise ApiError(400, "validation_error", "page and per_page must be integers")
    if page < 1 or not 1 <= per_page <= MAX_PER_PAGE:
        raise ApiError(400, "validation_error", f"page must be ≥ 1 and per_page between 1 and {MAX_PER_PAGE}")
    return page, per_page


def paginated(items: list, page: int, per_page: int, total: int, extra_meta: dict | None = None):
    meta = {"page": page, "per_page": per_page, "total": total, "total_pages": -(-total // per_page)}
    return jsonify(data=items, meta={**meta, **(extra_meta or {})})


def parse_body(model: type[M]) -> M:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError.bad_request("Expected a JSON object body")
    return model.model_validate(data)
