from flask import Flask, Response, abort, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .db import init_mongo
from .services.crypto import init_crypto
from .errors import register_error_handlers

CSP = (
    "default-src 'self'; img-src 'self' data:; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def create_app(overrides: dict | None = None) -> Flask:
    # static_folder=None: the frontend is served from frontend/ below (or by Nginx).
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    app.config.update(overrides or {})
    if len(app.config.get("JWT_SECRET") or "") < 32:
        raise RuntimeError("JWT_SECRET must be set to at least 32 characters. Copy .env.example to .env.")
    if app.config["PROXY_FIX"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    init_mongo(app)
    init_crypto(app)
    register_error_handlers(app)

    from .api import api_bp
    from .cli import register_cli

    app.register_blueprint(api_bp)
    register_cli(app)
    _register_cors(app)
    _register_frontend(app)

    if app.config["AUDIT_WORKER"] == "embedded" and not app.config.get("TESTING"):
        from .worker import ensure_embedded_worker

        @app.before_request
        def _start_worker():
            # Started lazily so CLI commands (init-db, worker, scan) never spawn an embedded worker.
            ensure_embedded_worker(app)

    from .services.rate_limit import add_headers as _rate_limit_headers
    app.after_request(_rate_limit_headers)

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.is_secure:  # behind Nginx: requires PROXY_FIX=1 so X-Forwarded-Proto is honoured
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    return app


def _register_cors(app: Flask) -> None:
    """Only needed when the frontend is served from another origin (ALLOWED_ORIGINS)."""
    allowed = set(app.config["ALLOWED_ORIGINS"])
    if not allowed:
        return

    @app.before_request
    def _preflight():
        if request.method == "OPTIONS" and request.path.startswith("/api/"):
            return Response(status=204)

    @app.after_request
    def _cors(resp):
        origin = request.headers.get("Origin", "").rstrip("/")
        if request.path.startswith("/api/") and origin in allowed:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Requested-With"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            resp.headers["Access-Control-Max-Age"] = "600"
            resp.headers.add("Vary", "Origin")
        return resp


def _register_frontend(app: Flask) -> None:
    """Development convenience: serve frontend/ as static files. Nginx does this in production."""
    if not app.config["SERVE_FRONTEND"]:
        return
    root = app.config["FRONTEND_DIR"]

    @app.get("/")
    def _index():
        return send_from_directory(root, "index.html")

    @app.get("/<path:filename>")
    def _static(filename: str):
        if filename.startswith("api/"):
            abort(404)  # unknown API route → JSON 404, not a file lookup
        return send_from_directory(root, filename)  # safe_join blocks traversal
