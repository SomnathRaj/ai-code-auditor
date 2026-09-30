from flask import Blueprint

from . import audits, auth, dashboard, findings, me, meta, organization, repositories

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")
for module in (auth, me, organization, dashboard, repositories, audits, findings, meta):
    api_bp.register_blueprint(module.bp)
api_bp.register_blueprint(organization.logs_bp)
