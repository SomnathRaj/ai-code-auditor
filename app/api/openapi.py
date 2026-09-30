"""OpenAPI 3 description of the implemented /api/v1 endpoints (PRD §43)."""
from ..constants import AUDIT_STATUSES, AUDIT_TYPES, FINDING_STATUSES, ROLES, SEVERITIES


def _ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def _data(schema):
    return {"type": "object", "properties": {"data": schema}, "required": ["data"]}


def _json(schema):
    return {"content": {"application/json": {"schema": schema}}}


def _resp(desc, schema=None):
    return {"description": desc, **(_json(schema) if schema else {})}


def _errors(*codes):
    return {str(c): {"$ref": f"#/components/responses/E{c}"} for c in codes}


def _op(summary, tag, responses, *, body=None, auth=True, params=None):
    op = {"summary": summary, "tags": [tag], "responses": responses}
    if body:
        op["requestBody"] = {"required": True, **_json(body)}
    if not auth:
        op["security"] = []
    if params:
        op["parameters"] = params
    return op


PAGE_PARAMS = [
    {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
    {"name": "per_page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}},
]
FINDING_ID = {"name": "finding_id", "in": "path", "required": True, "schema": {"type": "string", "pattern": "^[0-9a-f]{24}$"}}
AUDIT_ID = {"name": "audit_id", "in": "path", "required": True, "schema": {"type": "string", "pattern": "^[0-9a-f]{24}$"}}
REPO_ID = {"name": "repo_id", "in": "path", "required": True, "schema": {"type": "string", "pattern": "^[0-9a-f]{24}$"}}
MEMBER_ID = {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string", "pattern": "^[0-9a-f]{24}$"}}
COOKIE_NOTE = ("Reads the HttpOnly refresh cookie. Requires `X-Requested-With: fetch` and an allowed `Origin`.")

_counts = {"type": "object", "properties": {s: {"type": "integer"} for s in SEVERITIES}}

SCHEMAS = {
    "Error": {
        "type": "object",
        "properties": {"error": {"type": "object", "required": ["code", "message"], "properties": {
            "code": {"type": "string"}, "message": {"type": "string"}, "details": {"type": "object"}}}},
    },
    "PageMeta": {"type": "object", "properties": {k: {"type": "integer"} for k in ("page", "per_page", "total", "total_pages")}},
    "User": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"},
                                              "email": {"type": "string"}, "created_at": {"type": "string", "format": "date-time"}}},
    "Organization": {"type": "object", "properties": {"id": {"type": "string"}, "name": {"type": "string"}, "plan": {"type": "string"}}},
    "Identity": {"type": "object", "properties": {"user": _ref("User"), "organization": _ref("Organization"),
                                                  "role": {"type": "string", "enum": list(ROLES)}}},
    "TokenResponse": {"allOf": [_ref("Identity"), {"type": "object", "properties": {
        "access_token": {"type": "string"}, "token_type": {"type": "string", "enum": ["Bearer"]},
        "expires_in": {"type": "integer", "description": "Seconds"}}}]},
    "SeverityCounts": _counts,
    "AuditSettings": {"type": "object", "properties": {
        "enabled_scanners": {"type": "array", "items": {"type": "string"}},
        "excluded_paths": {"type": "array", "items": {"type": "string"}},
        "severity_threshold": {"type": "string", "enum": list(SEVERITIES)}, "ai_enabled": {"type": "boolean"}}},
    "Repository": {"type": "object", "properties": {
        "id": {"type": "string"}, "name": {"type": "string"}, "provider": {"type": "string", "enum": ["github", "zip"]},
        "url": {"type": "string", "nullable": True}, "default_branch": {"type": "string"},
        "language": {"type": "string", "nullable": True}, "framework": {"type": "string", "nullable": True},
        "status": {"type": "string"}, "has_access_token": {"type": "boolean"},
        "source": {"allOf": [_ref("SourceArchive")], "nullable": True},
        "counts": _ref("SeverityCounts"), "open_findings": {"type": "integer"},
        "security_score": {"type": "integer", "nullable": True},
        "last_audit": {"type": "object", "nullable": True},
        "settings": _ref("AuditSettings"),
        "created_at": {"type": "string", "format": "date-time"}, "updated_at": {"type": "string", "format": "date-time"}}},
    "Audit": {"type": "object", "properties": {
        "id": {"type": "string"}, "display_id": {"type": "string", "example": "AUD-10023"},
        "repository_id": {"type": "string"}, "branch": {"type": "string"},
        "audit_type": {"type": "string", "enum": list(AUDIT_TYPES)}, "status": {"type": "string", "enum": list(AUDIT_STATUSES)},
        "started_at": {"type": "string", "format": "date-time", "nullable": True},
        "completed_at": {"type": "string", "format": "date-time", "nullable": True},
        "duration": {"type": "integer", "nullable": True}, "created_at": {"type": "string", "format": "date-time"}}},
    "RegisterRequest": {"type": "object", "required": ["name", "email", "password"], "properties": {
        "name": {"type": "string", "maxLength": 120}, "email": {"type": "string", "format": "email"},
        "password": {"type": "string", "minLength": 10}, "organization_name": {"type": "string", "maxLength": 120}}},
    "LoginRequest": {"type": "object", "required": ["email", "password"], "properties": {
        "email": {"type": "string"}, "password": {"type": "string"}}},
    "RepositoryCreateRequest": {"type": "object", "required": ["url"], "properties": {
        "url": {"type": "string", "example": "https://github.com/owner/repo"},
        "default_branch": {"type": "string", "description": "Defaults to the repository's default branch"},
        "name": {"type": "string"},
        "access_token": {"type": "string", "writeOnly": True,
                         "description": "GitHub token for private repositories; stored encrypted, never returned"}}},
    "RepositoryUpdateRequest": {"type": "object", "properties": {
        "name": {"type": "string"}, "default_branch": {"type": "string", "description": "GitHub only; must exist"},
        "access_token": {"type": "string", "nullable": True, "writeOnly": True, "description": "null removes it"}}},
    "SourceArchive": {"type": "object", "properties": {
        "type": {"type": "string", "enum": ["zip"]}, "filename": {"type": "string"}, "size": {"type": "integer"},
        "sha256": {"type": "string"}, "file_count": {"type": "integer"}, "uncompressed_size": {"type": "integer"},
        "uploaded_at": {"type": "string", "format": "date-time"}}},
    "ZipUpload": {"type": "object", "required": ["file"], "properties": {
        "file": {"type": "string", "format": "binary"}, "name": {"type": "string"}}},
    "AuditStage": {"type": "object", "properties": {
        "name": {"type": "string", "enum": ["cloning", "detecting", "scanning", "dependency_analysis", "ai_analysis", "processing"]},
        "label": {"type": "string"},
        "status": {"type": "string", "enum": ["pending", "running", "completed", "failed", "skipped", "cancelled"]},
        "detail": {"type": "string", "nullable": True},
        "started_at": {"type": "string", "format": "date-time", "nullable": True},
        "completed_at": {"type": "string", "format": "date-time", "nullable": True}}},
    "AuditStatus": {"type": "object", "properties": {
        "id": {"type": "string"}, "display_id": {"type": "string"},
        "status": {"type": "string", "enum": list(AUDIT_STATUSES)}, "is_final": {"type": "boolean"},
        "progress": {"type": "integer", "minimum": 0, "maximum": 100},
        "stages": {"type": "array", "items": _ref("AuditStage")}, "cancel_requested": {"type": "boolean"},
        "error": {"type": "object", "nullable": True, "properties": {"code": {"type": "string"}, "message": {"type": "string"}}},
        "started_at": {"type": "string", "format": "date-time", "nullable": True},
        "completed_at": {"type": "string", "format": "date-time", "nullable": True}}},
    "AuditDetail": {"allOf": [_ref("Audit"), _ref("AuditStatus"), {"type": "object", "properties": {
        "repository": {"type": "object"}, "settings": {"type": "object"}, "scanner_versions": {"type": "object"},
        "summary": {"type": "object", "nullable": True}, "attempts": {"type": "integer"}}}]},
    "FindingSummary": {"type": "object", "properties": {
        "id": {"type": "string"}, "audit_id": {"type": "string"}, "title": {"type": "string"},
        "rule_id": {"type": "string"}, "scanner": {"type": "string", "enum": ["semgrep", "gitleaks", "osv"]},
        "category": {"type": "string"}, "severity": {"type": "string", "enum": list(SEVERITIES)},
        "confidence": {"type": "number"}, "status": {"type": "string", "enum": list(FINDING_STATUSES)},
        "file": {"type": "string"}, "line_start": {"type": "integer"}, "line_end": {"type": "integer"},
        "function": {"type": "string", "nullable": True}, "cwe": {"type": "string", "nullable": True},
        "ai": {"type": "object", "nullable": True, "properties": {
            "status": {"type": "string"}, "verdict": {"type": "string", "nullable": True},
            "confidence": {"type": "number", "nullable": True},
            "false_positive_probability": {"type": "number", "nullable": True}}}}},
    "FindingDetail": {"allOf": [_ref("FindingSummary"), {"type": "object", "properties": {
        "description": {"type": "string"}, "impact": {"type": "string", "nullable": True},
        "recommendation": {"type": "string"}, "owasp": {"type": "string"},
        "references": {"type": "array", "items": {"type": "object", "properties": {
            "label": {"type": "string"}, "url": {"type": "string"}}}},
        "evidence": {"type": "object", "description": "Scanner-specific (e.g. package, versions for dependencies)"},
        "ai_analysis": {"type": "object", "nullable": True,
                        "description": "verdict, confidence, explanation, impact, attack_scenario, recommendation, fixed_code, missing_context, evidence_lines, model"},
        "allowed_transitions": {"type": "array", "items": {"type": "string"}},
        "reason_required_for": {"type": "array", "items": {"type": "string"}},
        "status_history": {"type": "array", "items": {"type": "object"}},
        "audit": {"type": "object"}, "repository": {"type": "object"}}}]},
    "CodeView": {"type": "object", "properties": {
        "file": {"type": "string"}, "language": {"type": "string", "nullable": True},
        "line_start": {"type": "integer"}, "line_end": {"type": "integer"}, "available": {"type": "boolean"},
        "lines": {"type": "array", "items": {"type": "object", "properties": {
            "number": {"type": "integer"}, "text": {"type": "string"}, "highlight": {"type": "boolean"},
            "evidence": {"type": "boolean", "description": "Cited by the AI analysis"}}}},
        "marker": {"type": "object", "nullable": True}, "fixed_code": {"type": "string", "nullable": True}}},
    "Comment": {"type": "object", "properties": {
        "id": {"type": "string"}, "body": {"type": "string"}, "kind": {"type": "string", "enum": ["comment", "status_change"]},
        "status": {"type": "string", "nullable": True}, "user": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"}, "earlier_audit": {"type": "boolean"}}},
    "StartAuditRequest": {"type": "object", "properties": {
        "branch": {"type": "string", "description": "GitHub only; defaults to the repository's default branch"},
        "audit_type": {"type": "string", "enum": list(AUDIT_TYPES), "default": "full"}}},
    "Branch": {"type": "object", "properties": {"name": {"type": "string"}, "default": {"type": "boolean"}}},
    "Vulnerability": {"type": "object", "properties": {
        "id": {"type": "string", "example": "GHSA-9hjg-9r4m-mvj7"}, "aliases": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"}, "severity": {"type": "string", "enum": list(SEVERITIES)},
        "cvss_score": {"type": "number", "nullable": True}, "affected_range": {"type": "string", "example": "<2.32.4"},
        "fixed_versions": {"type": "array", "items": {"type": "string"}},
        "references": {"type": "array", "items": {"type": "string"}}}},
    "Dependency": {"type": "object", "properties": {
        "id": {"type": "string"}, "package_name": {"type": "string"},
        "version": {"type": "string", "nullable": True, "description": "Exact version; null when only a range is declared"},
        "declared": {"type": "string", "nullable": True, "description": "Declared range when not pinned"},
        "ecosystem": {"type": "string", "enum": ["PyPI", "npm", "Packagist", "Go", "Maven"]},
        "manifest": {"type": "string"}, "line": {"type": "integer", "nullable": True},
        "scope": {"type": "string", "enum": ["runtime", "dev"]}, "direct": {"type": "boolean"},
        "vulnerable": {"type": "boolean"}, "max_severity": {"type": "string", "nullable": True},
        "recommended_version": {"type": "string", "nullable": True},
        "vulnerabilities": {"type": "array", "items": _ref("Vulnerability")}}},
}

SCHEMAS.update({
    "Retention": {"type": "object", "properties": {
        "audit_days": {"type": "integer", "enum": [0, 7, 30, 90, 180, 365], "description": "0 = keep forever"},
        "source_days": {"type": "integer", "enum": [0, 7, 30, 90, 180, 365], "description": "0 = until replaced"}}},
    "OrganizationDetail": {"type": "object", "properties": {
        "id": {"type": "string"}, "name": {"type": "string"}, "plan": {"type": "string"}, "retention": _ref("Retention"),
        "member_count": {"type": "integer"}, "role": {"type": "string", "enum": list(ROLES)},
        "created_at": {"type": "string", "format": "date-time"}}},
    "Member": {"type": "object", "properties": {
        "user_id": {"type": "string"}, "name": {"type": "string"}, "email": {"type": "string"}, "status": {"type": "string"},
        "role": {"type": "string", "enum": list(ROLES)}, "joined_at": {"type": "string", "format": "date-time"},
        "is_owner_of_record": {"type": "boolean"}}},
    "AuditLogEntry": {"type": "object", "properties": {
        "id": {"type": "string"}, "event": {"type": "string"}, "at": {"type": "string", "format": "date-time"},
        "user": {"type": "string", "nullable": True}, "user_id": {"type": "string", "nullable": True},
        "ip_address": {"type": "string", "nullable": True}, "details": {"type": "object"}}},
})

_ERROR_DESCRIPTIONS = {
    400: "Validation error", 401: "Missing, invalid or expired token", 403: "Role not allowed / CSRF check failed",
    404: "Not found (or belongs to another organization)", 409: "Conflict", 413: "Upload too large",
    415: "Upload must be multipart/form-data", 422: "Repository inaccessible or archive unsafe/invalid",
    429: "Rate limited (see Retry-After and X-RateLimit-* headers)",
    502: "Git provider unreachable", 503: "Service unavailable", 504: "Git provider timed out",
}


def _page_of(schema):
    return {"type": "object", "properties": {"data": {"type": "array", "items": schema}, "meta": _ref("PageMeta")}}


PATHS = {
    "/auth/register": {"post": _op("Register a user and organization", "Auth", {
        "201": _resp("Registered; refresh cookie set", _data(_ref("TokenResponse"))), **_errors(400, 409)},
        body=_ref("RegisterRequest"), auth=False)},
    "/auth/login": {"post": _op("Log in", "Auth", {
        "200": _resp("Logged in; refresh cookie set", _data(_ref("TokenResponse"))), **_errors(400, 401)},
        body=_ref("LoginRequest"), auth=False)},
    "/auth/refresh": {"post": {**_op("Rotate refresh token and get a new access token", "Auth", {
        "200": _resp("New access token", _data(_ref("TokenResponse"))), **_errors(401, 403)}, auth=False),
        "description": COOKIE_NOTE}},
    "/auth/logout": {"post": {**_op("Log out (revoke refresh token)", "Auth", {
        "204": _resp("Logged out"), **_errors(403)}, auth=False), "description": COOKIE_NOTE}},
    "/auth/switch-organization": {"post": _op("Switch the current organization", "Auth", {
        "200": _resp("New access token", _data(_ref("TokenResponse"))), **_errors(401, 404)},
        body={"type": "object", "required": ["organization_id"], "properties": {"organization_id": {"type": "string"}}})},
    "/me": {"get": _op("Current user, organization and role", "Me", {
        "200": _resp("OK", _data(_ref("Identity"))), **_errors(401)})},
    "/me/features": {"get": _op("Server features the UI must disclose (AI provider, OSV)", "Me", {
        "200": _resp("OK", _data({"type": "object", "properties": {
            "ai": {"type": "object", "properties": {"configured": {"type": "boolean"}, "provider": {"type": "string"},
                                                   "model": {"type": "string"}, "min_severity": {"type": "string"},
                                                   "max_findings": {"type": "integer"}}},
            "osv": {"type": "object", "properties": {"enabled": {"type": "boolean"}}}}})), **_errors(401)})},
    "/me/organizations": {"get": _op("Organizations the user belongs to", "Me", {
        "200": _resp("OK", _data({"type": "array", "items": _ref("Organization")})), **_errors(401)})},
    "/dashboard": {"get": _op("Security overview for the organization", "Dashboard", {
        "200": _resp("OK", _data({"type": "object", "properties": {
            "counts": _ref("SeverityCounts"), "open_findings": {"type": "integer"},
            "security_score": {"type": "integer", "nullable": True}, "repository_count": {"type": "integer"},
            "audited_repository_count": {"type": "integer"},
            "recent_audits": {"type": "array", "items": _ref("Audit")}}})), **_errors(401)})},
    "/dashboard/trends": {"get": _op("Risk over time, resolved this month, recurring issues (PRD §59)", "Dashboard", {
        "200": _resp("OK", _data({"type": "object", "properties": {
            "points": {"type": "array", "items": {"type": "object", "properties": {
                "at": {"type": "string", "format": "date-time"}, "display_id": {"type": "string"},
                "repository": {"type": "string"}, "open_findings": {"type": "integer"},
                "counts": _ref("SeverityCounts"), "security_score": {"type": "integer"}}}},
            "resolved_this_month": {"type": "object", "properties": {
                "total": {"type": "integer"}, "triaged": {"type": "integer"}, "fixed_in_code": {"type": "integer"}}},
            "recurring": {"type": "array", "items": {"type": "object"}}}})), **_errors(400, 401)},
        params=[{"name": "days", "in": "query", "schema": {"type": "integer", "enum": [7, 30, 90, 180, 365], "default": 90}}])},
    "/repositories": {
        "get": _op("List repositories", "Repositories", {
            "200": _resp("OK", _page_of(_ref("Repository"))), **_errors(400, 401)}, params=PAGE_PARAMS),
        "post": _op("Add a GitHub repository (owner/admin)", "Repositories", {
            "201": _resp("Created", _data(_ref("Repository"))), **_errors(400, 401, 403, 409)},
            body=_ref("RepositoryCreateRequest")),
    },
    "/repositories/uploads": {"post": {**_op("Create a repository from a ZIP archive (owner/admin)", "Repositories", {
        "201": _resp("Created", _data(_ref("Repository"))), **_errors(400, 401, 403, 413, 415, 422)}),
        "requestBody": {"required": True, "content": {"multipart/form-data": {"schema": _ref("ZipUpload")}}}}},
    "/repositories/{repo_id}": {
        "get": _op("Repository details", "Repositories", {
            "200": _resp("OK", _data(_ref("Repository"))), **_errors(401, 404)}, params=[REPO_ID]),
        "patch": _op("Rename, change default branch, or set/remove the access token (owner/admin)", "Repositories", {
            "200": _resp("OK", _data(_ref("Repository"))), **_errors(400, 401, 403, 404, 409, 422, 502)},
            body=_ref("RepositoryUpdateRequest"), params=[REPO_ID]),
        "delete": _op("Delete repository with its audits, findings and archives (owner/admin)", "Repositories", {
            "204": _resp("Deleted"), **_errors(401, 403, 404)}, params=[REPO_ID]),
    },
    "/repositories/{repo_id}/source": {"put": {**_op("Upload a new version of a ZIP repository (developer+)",
        "Repositories", {"200": _resp("OK", _data(_ref("Repository"))), **_errors(400, 401, 403, 404, 409, 413, 415, 422)},
        params=[REPO_ID]),
        "requestBody": {"required": True, "content": {"multipart/form-data": {"schema": _ref("ZipUpload")}}}}},
    "/repositories/{repo_id}/branches": {"get": _op("Branches from GitHub, default first", "Repositories", {
        "200": _resp("OK", _page_of(_ref("Branch"))), **_errors(401, 404, 409, 422, 502)},
        params=[REPO_ID, {"name": "q", "in": "query", "schema": {"type": "string"}}, *PAGE_PARAMS])},
    "/repositories/{repo_id}/dependencies": {"get": _op(
        "Dependencies from the latest completed audit (vulnerable first)", "Repositories", {
            "200": _resp("OK; meta also has audit_id and display_id (null before the first audit)",
                         _page_of(_ref("Dependency"))), **_errors(400, 401, 404)},
        params=[REPO_ID, {"name": "vulnerable", "in": "query", "schema": {"type": "boolean"}},
                {"name": "ecosystem", "in": "query", "schema": {"type": "string"}},
                {"name": "q", "in": "query", "schema": {"type": "string"}}, *PAGE_PARAMS])},
    "/repositories/{repo_id}/settings": {
        "get": _op("Audit settings", "Repositories", {
            "200": _resp("OK", _data(_ref("AuditSettings"))), **_errors(401, 404)}, params=[REPO_ID]),
        "put": _op("Replace audit settings (owner/admin)", "Repositories", {
            "200": _resp("OK", _data(_ref("AuditSettings"))), **_errors(400, 401, 403, 404)},
            body=_ref("AuditSettings"), params=[REPO_ID]),
    },
    "/repositories/{repo_id}/audits": {
        "get": _op("Audit history", "Audits", {
            "200": _resp("OK", _page_of(_ref("Audit"))), **_errors(400, 401, 404)}, params=[REPO_ID, *PAGE_PARAMS]),
        "post": _op("Queue an audit (developer+). Poll the Location header for progress.", "Audits", {
            "202": _resp("Queued; Location: /api/v1/audits/{id}/status", _data(_ref("AuditStatus"))),
            **_errors(400, 401, 403, 404, 409)}, body=_ref("StartAuditRequest"), params=[REPO_ID]),
    },
    "/audits/{audit_id}": {
        "get": _op("Audit details, stages and summary", "Audits", {
            "200": _resp("OK", _data(_ref("AuditDetail"))), **_errors(401, 404)}, params=[AUDIT_ID]),
        "delete": _op("Delete a finished audit with its findings (owner/admin)", "Audits", {
            "204": _resp("Deleted"), **_errors(401, 403, 404, 409)}, params=[AUDIT_ID]),
    },
    "/audits/{audit_id}/findings": {"get": _op("Findings of an audit, filtered and paginated", "Findings", {
        "200": _resp("OK; meta.facets has counts per severity/status/category/scanner/ai_verdict",
                     _page_of(_ref("FindingSummary"))), **_errors(400, 401, 404)},
        params=[AUDIT_ID, *[{"name": n, "in": "query", "schema": {"type": "string"}, "description": d} for n, d in (
            ("severity", "Comma-separated severities"), ("status", "Comma-separated statuses, or open / closed"),
            ("category", "Comma-separated categories"), ("scanner", "semgrep, gitleaks, osv"),
            ("ai_verdict", "true_positive, false_positive, needs_more_context, none"),
            ("file", "Path contains"), ("q", "Title / rule contains"),
            ("sort", "severity | file | confidence | ai_false_positive | newest"))], *PAGE_PARAMS])},
    "/audits/{audit_id}/report": {"get": {**_op(
        "Technical or executive report (PRD §48). json returns the model; html/pdf/csv download as attachments",
        "Reports", {"200": {"description": "Report", "content": {
            "application/json": {"schema": _data({"type": "object"})},
            "text/html": {"schema": {"type": "string"}}, "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            "text/csv": {"schema": {"type": "string"}}}}, **_errors(400, 401, 404, 409)},
        params=[AUDIT_ID,
                {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["json", "html", "pdf", "csv"], "default": "json"}},
                {"name": "type", "in": "query", "schema": {"type": "string", "enum": ["technical", "executive"], "default": "technical"}},
                {"name": "severity", "in": "query", "schema": {"type": "string"}, "description": "Technical only; same filters as the findings list"},
                {"name": "status", "in": "query", "schema": {"type": "string"}}])}},
    "/audits/{audit_id}/comparison": {"get": _op("Compare with another completed audit of the same repository (PRD §60)",
        "Reports", {"200": _resp("new / resolved / unchanged / reopened counts and lists", _data({"type": "object", "properties": {
            "counts": {"type": "object", "properties": {k: {"type": "integer"} for k in (
                "new", "resolved", "unchanged", "reopened", "dismissed_no_longer_reported")}},
            "score_change": {"type": "integer", "nullable": True},
            "new": {"type": "array", "items": _ref("FindingSummary")}, "resolved": {"type": "array", "items": _ref("FindingSummary")},
            "reopened": {"type": "array", "items": _ref("FindingSummary")}, "unchanged": {"type": "array", "items": _ref("FindingSummary")},
            "base": {"type": "object"}, "target": {"type": "object"}}})), **_errors(400, 401, 404, 409)},
        params=[AUDIT_ID, {"name": "base", "in": "query", "schema": {"type": "string"},
                           "description": "Default: the previous completed audit"}])},
    "/audits/{audit_id}/status": {"get": _op("Progress (polled by the UI)", "Audits", {
        "200": _resp("OK", _data(_ref("AuditStatus"))), **_errors(401, 404)}, params=[AUDIT_ID])},
    "/audits/{audit_id}/cancel": {"post": _op("Cancel a queued or running audit (developer+)", "Audits", {
        "202": _resp("Cancelled (queued) or cancellation requested (running)", _data(_ref("AuditStatus"))),
        **_errors(401, 403, 404, 409)}, params=[AUDIT_ID])},
    "/findings/{finding_id}": {
        "get": _op("Finding detail", "Findings", {"200": _resp("OK", _data(_ref("FindingDetail"))), **_errors(401, 404)},
                   params=[FINDING_ID]),
        "patch": _op("Change status (developer+). Lifecycle per PRD §32; comment required for false_positive, "
                     "accepted_risk, ignored", "Findings", {
            "200": _resp("OK", _data(_ref("FindingDetail"))), **_errors(400, 401, 403, 404, 409)},
            body={"type": "object", "required": ["status"], "properties": {
                "status": {"type": "string", "enum": list(FINDING_STATUSES)}, "comment": {"type": "string"}}},
            params=[FINDING_ID]),
    },
    "/findings/{finding_id}/code": {"get": _op("Code viewer excerpt (masked, audited version)", "Findings", {
        "200": _resp("OK", _data(_ref("CodeView"))), **_errors(401, 404)}, params=[FINDING_ID])},
    "/findings/{finding_id}/comments": {
        "get": _op("Comments, including those on the same issue in earlier audits", "Findings", {
            "200": _resp("OK", _page_of(_ref("Comment"))), **_errors(401, 404)}, params=[FINDING_ID, *PAGE_PARAMS]),
        "post": _op("Add a comment (developer+)", "Findings", {
            "201": _resp("Created", _data(_ref("Comment"))), **_errors(400, 401, 403, 404)},
            body={"type": "object", "required": ["body"], "properties": {"body": {"type": "string", "maxLength": 5000}}},
            params=[FINDING_ID]),
    },
    "/organization": {
        "get": _op("Current organization, retention settings and your role", "Organization", {
            "200": _resp("OK", _data(_ref("OrganizationDetail"))), **_errors(401)}),
        "patch": _op("Rename or change retention (owner only)", "Organization", {
            "200": _resp("OK", _data(_ref("OrganizationDetail"))), **_errors(400, 401, 403)},
            body={"type": "object", "properties": {"name": {"type": "string", "maxLength": 120}, "retention": _ref("Retention")}}),
    },
    "/organization/members": {
        "get": _op("Members (admin+)", "Organization", {
            "200": _resp("OK", _data({"type": "array", "items": _ref("Member")})), **_errors(401, 403)}),
        "post": _op("Add an existing user by email (admin+; only owners add owners/admins)", "Organization", {
            "201": _resp("Added", _data(_ref("Member"))), **_errors(400, 401, 403, 404, 409)},
            body={"type": "object", "required": ["email"], "properties": {
                "email": {"type": "string", "format": "email"}, "role": {"type": "string", "enum": list(ROLES), "default": "developer"}}}),
    },
    "/organization/members/{user_id}": {
        "patch": _op("Change a member's role (admin+; the last owner can't be demoted)", "Organization", {
            "200": _resp("OK", _data(_ref("Member"))), **_errors(400, 401, 403, 404, 409)},
            body={"type": "object", "required": ["role"], "properties": {"role": {"type": "string", "enum": list(ROLES)}}},
            params=[MEMBER_ID]),
        "delete": _op("Remove a member (admin+), or leave (your own id). The last owner can't leave", "Organization", {
            "204": _resp("Removed"), **_errors(401, 403, 404, 409)}, params=[MEMBER_ID]),
    },
    "/audit-logs": {"get": _op("Activity log, newest first (admin+)", "Organization", {
        "200": _resp("OK", _page_of(_ref("AuditLogEntry"))), **_errors(400, 401, 403)}, params=[
            {"name": "event", "in": "query", "schema": {"type": "string"}, "description": 'Exact ("member.added") or prefix ("audit.*")'},
            {"name": "user_id", "in": "query", "schema": {"type": "string"}},
            {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"}},
            {"name": "until", "in": "query", "schema": {"type": "string", "format": "date-time"}}, *PAGE_PARAMS])},
    "/health": {"get": _op("Liveness / database check", "System", {
        "200": _resp("OK"), **_errors(503)}, auth=False)},
}


RATE_LIMITED_PUBLIC = {"/auth/register", "/auth/login", "/auth/refresh"}


def _with_rate_limits(paths: dict) -> dict:
    """Every bearer-authenticated call counts toward a per-user ceiling; some have tighter limits."""
    out = {}
    for path, ops in paths.items():
        out[path] = {}
        for method, op in ops.items():
            if op.get("security") != [] or path in RATE_LIMITED_PUBLIC:
                op = {**op, "responses": {**op["responses"], **_errors(429)}}
            out[path][method] = op
    return out


def build_spec() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "AI Code Auditor API", "version": "1.0.0"},
        "servers": [{"url": "/api/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": _with_rate_limits(PATHS),
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}},
            "schemas": SCHEMAS,
            "responses": {
                f"E{code}": {"description": desc, **_json(_ref("Error"))} for code, desc in _ERROR_DESCRIPTIONS.items()
            },
        },
    }
