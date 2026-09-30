from bson import ObjectId

from app.services.scoring import refresh_repository_snapshot

from .test_repositories import _create, _seed_audit


def test_dashboard_empty(owner):
    client, headers, _ = owner
    data = client.get("/api/v1/dashboard", headers=headers).get_json()["data"]
    assert data["security_score"] is None
    assert data["repository_count"] == 0 and data["recent_audits"] == []


def test_dashboard_uses_latest_audit_snapshot(app, owner, db):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    repo = _create(client, headers).get_json()["data"]
    repo_id = ObjectId(repo["id"])
    _seed_audit(db, org_id, repo_id, 1, severities=("critical",) * 5)  # older audit is ignored
    _seed_audit(db, org_id, repo_id, 2)
    # One finding marked false positive no longer counts as open
    db.findings.update_one({"audit_id": {"$exists": True}, "severity": "low"}, {"$set": {"status": "false_positive"}})
    with app.app_context():
        refresh_repository_snapshot(org_id, repo_id)

    dash = client.get("/api/v1/dashboard", headers=headers).get_json()["data"]
    assert dash["counts"] == {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}
    assert dash["security_score"] == 100 - 20 - 2 * 10
    assert dash["repository_count"] == 1
    assert [a["display_id"] for a in dash["recent_audits"]] == ["AUD-2", "AUD-1"]
    assert dash["recent_audits"][0]["repository_name"] == "pallets/flask"

    listed = client.get("/api/v1/repositories", headers=headers).get_json()["data"][0]
    assert listed["security_score"] == 60 and listed["last_audit"]["display_id"] == "AUD-2"


def test_health_and_openapi(client):
    health = client.get("/api/v1/health")
    assert health.status_code == 200 and health.get_json()["data"]["database"] == "ok"
    spec = client.get("/api/v1/openapi.json").get_json()
    assert spec["openapi"].startswith("3.")
    assert "/repositories/{repo_id}" in spec["paths"]


def test_unknown_api_routes_use_error_envelope(client):
    resp = client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404 and resp.get_json()["error"]["code"] == "not_found"
    resp = client.put("/api/v1/dashboard")
    assert resp.status_code == 405 and resp.get_json()["error"]["code"] == "method_not_allowed"


def test_frontend_served_with_security_headers(client):
    resp = client.get("/")
    assert resp.status_code == 200 and b"Security overview" in resp.data
    assert "script-src" not in resp.headers["Content-Security-Policy"]  # default-src 'self' only
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert client.get("/js/api.js").status_code == 200
    assert client.get("/../app/config.py").status_code == 404
    api = client.get("/api/v1/health")
    assert api.headers["Cache-Control"] == "no-store"
