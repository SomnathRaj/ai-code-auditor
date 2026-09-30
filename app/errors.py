"""Standard error envelope for the REST API (PRD §43.2):

    {"error": {"code": "...", "message": "...", "details": {...}}}
"""
from flask import Flask, jsonify, request
from pydantic import ValidationError
from werkzeug.exceptions import HTTPException

HTTP_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "unprocessable_entity",
    429: "rate_limited",
    500: "internal_error",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details

    @classmethod
    def bad_request(cls, message: str, details: dict | None = None):
        return cls(400, "bad_request", message, details)

    @classmethod
    def unauthorized(cls, message: str = "Authentication required"):
        return cls(401, "unauthorized", message)

    @classmethod
    def forbidden(cls, message: str = "Your role does not allow this action", code: str = "forbidden"):
        return cls(403, code, message)

    @classmethod
    def not_found(cls, what: str = "Resource"):
        return cls(404, "not_found", f"{what} not found")

    @classmethod
    def conflict(cls, message: str):
        return cls(409, "conflict", message)


def error_response(status: int, code: str, message: str, details: dict | None = None):
    body = {"code": code, "message": message}
    if details:
        body["details"] = details
    return jsonify(error=body), status


def _is_api() -> bool:
    return request.path.startswith("/api/")


def _validation_details(err: ValidationError) -> tuple[str, dict]:
    details = {}
    first_message = None
    for e in err.errors():
        field = ".".join(str(p) for p in e["loc"]) or "body"
        custom = e["type"] == "value_error"
        msg = e["msg"].removeprefix("Value error, ")
        details.setdefault(field, msg)
        if first_message is None:
            first_message = msg if custom else f"{field}: {msg}"
    return first_message or "Invalid request", details


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        return error_response(err.status, err.code, err.message, err.details)

    @app.errorhandler(ValidationError)
    def _validation_error(err: ValidationError):
        message, details = _validation_details(err)
        return error_response(400, "validation_error", message, details)

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        if not _is_api():
            return err
        code = HTTP_ERROR_CODES.get(err.code, "error")
        return error_response(err.code, code, err.description or err.name)

    @app.errorhandler(Exception)
    def _unhandled(err: Exception):
        # Never leak stack traces or internal errors to clients (PRD §23).
        app.logger.exception("Unhandled error")
        if _is_api():
            return error_response(500, "internal_error", "Something went wrong")
        return "Internal Server Error", 500
