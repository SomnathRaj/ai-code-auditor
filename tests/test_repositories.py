from bson import ObjectId

from app.db.utils import utcnow

from .conftest import bearer, register

URL = "https://github.com/pallets/flask"


def _create(client, headers, url=URL, **extra):
    return client.post("/api/v1/repositories", json={"url": url, **extra}, headers=headers)


def _seed_audit(db, org_id, repo_id, number=1, severities=("critical", "high", "high", "low")):
    now = utcnow()
    audit_id = db.audits.insert_one({
        "organization_id": org_id, "repository_id": repo_id, "audit_number": number, "branch": "main",
        "audit_type": "full", "status": "completed", "started_at": now, "completed_at": now,
        "created_at": now, "updated_at": now,
    }).inserted_id
    for i, sev in enumerate(severities):
        finding_id = db.findings.insert_one({
            "organization_id": org_id, "repository_id": repo_id, "audit_id": audit_id, "fingerprint": f"fp{i}",
            "title": "t", "severity": sev, "status": "new", "created_at": now, "updated_at": now,
        }).inserted_id
        db.finding_comments.insert_one({"organization_id": org_id, "finding_id": finding_id,
                                        "user_id": ObjectId(), "body": "c", "created_at": now})
    return audit_id


def test_create_repository(owner, db):
    client, headers, _ = owner
    resp = _create(client, headers, url=URL + ".git", default_branch="develop")
    assert resp.status_code == 201
    repo = resp.get_json()["data"]
    assert resp.headers["Location"] == f"/api/v1/repositories/{repo['id']}"
    assert repo["name"] == "pallets/flask" and repo["url"] == URL and repo["default_branch"] == "develop"
    assert repo["security_score"] is None and repo["open_findings"] == 0
    assert "node_modules/" in repo["settings"]["excluded_paths"]
    assert db.audit_logs.count_documents({"event": "repository.added"}) == 1


def test_create_repository_validation_and_duplicates(owner):
    client, headers, _ = owner
    bad = _create(client, headers, url="http://evil.example/x")
    assert bad.status_code == 400
    assert bad.get_json()["error"]["details"]["url"].startswith("Enter a GitHub URL")
    assert _create(client, headers, default_branch="--upload-pack=x").status_code == 400
    assert _create(client, headers).status_code == 201
    dup = _create(client, headers, url=URL + "/")
    assert dup.status_code == 409


def test_list_repositories_paginated(owner):
    client, headers, _ = owner
    for i in range(3):
        _create(client, headers, url=f"{URL}{i}")
    resp = client.get("/api/v1/repositories?per_page=2&page=2", headers=headers).get_json()
    assert resp["meta"] == {"page": 2, "per_page": 2, "total": 3, "total_pages": 2}
    assert [r["name"] for r in resp["data"]] == ["pallets/flask2"]
    assert client.get("/api/v1/repositories?per_page=500", headers=headers).status_code == 400
    assert client.get("/api/v1/repositories?page=x", headers=headers).status_code == 400


def test_get_settings_and_audits(owner, db):
    client, headers, data = owner
    repo = _create(client, headers).get_json()["data"]
    base = f"/api/v1/repositories/{repo['id']}"
    assert client.get(base, headers=headers).get_json()["data"]["name"] == "pallets/flask"
    assert client.get(f"{base}/settings", headers=headers).get_json()["data"]["ai_enabled"] is True

    org_id, repo_id = ObjectId(data["organization"]["id"]), ObjectId(repo["id"])
    _seed_audit(db, org_id, repo_id, 1)
    _seed_audit(db, org_id, repo_id, 2)
    audits = client.get(f"{base}/audits", headers=headers).get_json()
    assert audits["meta"]["total"] == 2
    assert [a["display_id"] for a in audits["data"]] == ["AUD-2", "AUD-1"]


def test_delete_repository_removes_children(owner, db):
    client, headers, data = owner
    repo = _create(client, headers).get_json()["data"]
    org_id, repo_id = ObjectId(data["organization"]["id"]), ObjectId(repo["id"])
    _seed_audit(db, org_id, repo_id)

    resp = client.delete(f"/api/v1/repositories/{repo['id']}", headers=headers)
    assert resp.status_code == 204 and resp.data == b""
    for col in ("repositories", "audits", "findings", "finding_comments"):
        assert db[col].count_documents({"organization_id": org_id}) == 0, col
    assert client.get(f"/api/v1/repositories/{repo['id']}", headers=headers).status_code == 404


def test_tenant_isolation(owner, app):
    client, headers, _ = owner
    repo = _create(client, headers).get_json()["data"]

    other = app.test_client()
    other_headers = bearer(register(other, email="bob@example.com", name="Bob"))
    path = f"/api/v1/repositories/{repo['id']}"
    for method in ("get", "delete"):
        resp = getattr(other, method)(path, headers=other_headers)
        assert resp.status_code == 404, method
    assert other.get(f"{path}/audits", headers=other_headers).status_code == 404
    assert other.get("/api/v1/repositories", headers=other_headers).get_json()["meta"]["total"] == 0
    assert client.get(path, headers=headers).status_code == 200


def test_malformed_id_is_404(owner):
    client, headers, _ = owner
    resp = client.get("/api/v1/repositories/not-an-id", headers=headers)
    assert resp.status_code == 404
    assert resp.get_json()["error"] == {"code": "not_found", "message": "Repository not found"}


def test_role_checks(owner, db):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    repo = _create(client, headers).get_json()["data"]

    for role in ("developer", "viewer"):
        member = client.application.test_client()
        member_data = register(member, email=f"{role}@example.com", name=role).get_json()["data"]
        db.organizations.update_one({"_id": org_id}, {"$push": {"members": {
            "user_id": ObjectId(member_data["user"]["id"]), "role": role, "joined_at": utcnow()}}})
        switched = member.post("/api/v1/auth/switch-organization", json={"organization_id": str(org_id)},
                               headers=bearer_from(member_data))
        h = bearer(switched)
        assert member.get("/api/v1/repositories", headers=h).get_json()["meta"]["total"] == 1
        assert _create(member, h, url=URL + "-x").status_code == 403
        assert member.delete(f"/api/v1/repositories/{repo['id']}", headers=h).status_code == 403


def bearer_from(data):
    return {"Authorization": f"Bearer {data['access_token']}"}
