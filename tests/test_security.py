"""Sprint 8: rate limiting, organization & members, activity log, retention, key rotation, headers."""
from datetime import timedelta

import pytest
from bson import ObjectId
from cryptography.fernet import Fernet

from app.db.utils import utcnow

from .conftest import COOKIE_HEADERS, bearer, register
from .test_zip_uploads import upload


@pytest.fixture
def limits(app):
    """Enable rate limiting with tiny limits so tests hit them quickly."""
    app.config["RATE_LIMIT_ENABLED"] = True
    app.config["RATE_LIMITS"] = {"login_ip": (5, 60), "login_fail": (3, 900), "register_ip": (3, 3600),
                                 "refresh_ip": (4, 60), "audit_start": (2, 3600), "api_user": (1000, 60)}
    yield app.config["RATE_LIMITS"]
    app.config["RATE_LIMIT_ENABLED"] = False


def join(app, db, org_id, email, role):
    c = app.test_client()
    data = register(c, email=email, name=email.split("@")[0]).get_json()["data"]
    db.organizations.update_one({"_id": org_id}, {"$push": {"members": {
        "user_id": ObjectId(data["user"]["id"]), "role": role, "joined_at": utcnow()}}})
    switched = c.post("/api/v1/auth/switch-organization", json={"organization_id": str(org_id)},
                      headers={"Authorization": f"Bearer {data['access_token']}"})
    return c, bearer(switched), data["user"]["id"]


# ---- rate limiting ----

def test_register_and_login_rate_limits(client, limits):
    for i in range(3):
        assert register(client, email=f"u{i}@example.com").status_code == 201
    blocked = register(client, email="u9@example.com")
    assert blocked.status_code == 429 and blocked.get_json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["Retry-After"]) > 0 and blocked.headers["X-RateLimit-Remaining"] == "0"


def test_failed_logins_lock_the_account_not_the_user(app, client, limits):
    register(client, email="ann@example.com")
    for _ in range(3):
        assert client.post("/api/v1/auth/login", json={"email": "ann@example.com", "password": "wrong-pass"}).status_code == 401
    # Correct password is now refused too, for this account only …
    locked = client.post("/api/v1/auth/login", json={"email": "ann@example.com", "password": "supersecret1"})
    assert locked.status_code == 429
    # … from another IP as well (the per-account limit is not per IP).
    other_ip = app.test_client()
    r = other_ip.post("/api/v1/auth/login", json={"email": "ann@example.com", "password": "supersecret1"},
                      environ_base={"REMOTE_ADDR": "10.9.9.9"})
    assert r.status_code == 429


def test_login_ip_limit(client, limits):
    register(client)
    codes = [client.post("/api/v1/auth/login", json={"email": "ann@example.com", "password": "supersecret1"}).status_code
             for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429


def test_refresh_and_audit_start_limits(owner, limits):
    client, headers, _ = owner
    codes = [client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS).status_code for _ in range(5)]
    assert codes[-1] == 429 and codes[0] == 200
    repo = upload(client, headers).get_json()["data"]
    first = client.post(f"/api/v1/repositories/{repo['id']}/audits", json={}, headers=headers)
    assert first.status_code == 202
    client.post(f"/api/v1/audits/{first.get_json()['data']['id']}/cancel", headers=headers)
    assert client.post(f"/api/v1/repositories/{repo['id']}/audits", json={}, headers=headers).status_code == 202
    third = client.post(f"/api/v1/repositories/{repo['id']}/audits", json={}, headers=headers)
    assert third.status_code == 429  # 2 per organization per hour in this test


# ---- organization & members ----

def test_organization_settings(owner, app, db):
    client, headers, data = owner
    org = client.get("/api/v1/organization", headers=headers).get_json()["data"]
    assert org["retention"] == {"audit_days": 90, "source_days": 0} and org["role"] == "owner"
    r = client.patch("/api/v1/organization", json={"name": "Acme Security", "retention": {"audit_days": 30, "source_days": 7}},
                     headers=headers)
    assert r.status_code == 200 and r.get_json()["data"]["retention"] == {"audit_days": 30, "source_days": 7}
    assert client.patch("/api/v1/organization", json={"retention": {"audit_days": 45}}, headers=headers).status_code == 400
    admin, ah, _ = join(app, db, ObjectId(data["organization"]["id"]), "admin@example.com", "admin")
    assert admin.patch("/api/v1/organization", json={"name": "x"}, headers=ah).status_code == 403  # owner only


def test_member_management_rules(owner, app, db):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    admin, ah, admin_id = join(app, db, org_id, "admin@example.com", "admin")
    register(app.test_client(), email="dev@example.com", name="Dev")
    register(app.test_client(), email="boss@example.com", name="Boss")

    added = admin.post("/api/v1/organization/members", json={"email": "DEV@example.com", "role": "developer"}, headers=ah)
    assert added.status_code == 201 and added.get_json()["data"]["role"] == "developer"
    dev_id = added.get_json()["data"]["user_id"]
    assert admin.post("/api/v1/organization/members", json={"email": "dev@example.com"}, headers=ah).status_code == 409
    assert admin.post("/api/v1/organization/members", json={"email": "nobody@example.com"}, headers=ah).status_code == 404
    # Admins can't create or touch privileged members …
    assert admin.post("/api/v1/organization/members", json={"email": "boss@example.com", "role": "admin"},
                      headers=ah).status_code == 403
    assert admin.patch(f"/api/v1/organization/members/{data['user']['id']}", json={"role": "viewer"},
                       headers=ah).status_code == 403
    # … but can manage developers/viewers.
    assert admin.patch(f"/api/v1/organization/members/{dev_id}", json={"role": "viewer"}, headers=ah).get_json()["data"]["role"] == "viewer"

    # The last owner can't be demoted or removed; promoting someone else first makes it possible.
    owner_id = data["user"]["id"]
    assert client.patch(f"/api/v1/organization/members/{owner_id}", json={"role": "admin"}, headers=headers).status_code == 409
    assert client.delete(f"/api/v1/organization/members/{owner_id}", headers=headers).status_code == 409
    assert client.patch(f"/api/v1/organization/members/{admin_id}", json={"role": "owner"}, headers=headers).status_code == 200
    assert client.patch(f"/api/v1/organization/members/{owner_id}", json={"role": "admin"}, headers=headers).status_code == 200

    members = admin.get("/api/v1/organization/members", headers=ah).get_json()["data"]
    assert [m["role"] for m in members] == ["owner", "admin", "viewer"]

    # Removing a member cuts access on their next request.
    dev = app.test_client()
    dh = bearer(dev.post("/api/v1/auth/login", json={"email": "dev@example.com", "password": "supersecret1"}))
    dh = bearer(dev.post("/api/v1/auth/switch-organization", json={"organization_id": str(org_id)}, headers=dh))
    assert dev.get("/api/v1/repositories", headers=dh).status_code == 200
    assert admin.delete(f"/api/v1/organization/members/{dev_id}", headers=ah).status_code == 204
    assert dev.get("/api/v1/repositories", headers=dh).status_code == 401
    events = {e["event"] for e in db.audit_logs.find({"organization_id": org_id})}
    assert {"member.added", "member.role_changed", "member.removed"} <= events


def test_members_can_leave_and_viewers_cant_manage(owner, app, db):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    viewer, vh, viewer_id = join(app, db, org_id, "viewer@example.com", "viewer")
    assert viewer.get("/api/v1/organization/members", headers=vh).status_code == 403
    assert viewer.delete(f"/api/v1/organization/members/{data['user']['id']}", headers=vh).status_code == 403
    assert viewer.delete(f"/api/v1/organization/members/{viewer_id}", headers=vh).status_code == 204  # leave
    assert db.audit_logs.count_documents({"event": "member.left"}) == 1


def test_default_workspace_on_login_and_after_leaving(owner, app, db):
    client, headers, data = owner
    org_id = data["organization"]["id"]
    login = {"email": "viewer@example.com", "password": "supersecret1"}
    # Added but never switched: login opens their own workspace, not the older one they joined.
    register(app.test_client(), email="viewer@example.com", name="Vi")
    client.post("/api/v1/organization/members", json={"email": "viewer@example.com", "role": "viewer"}, headers=headers)
    v = app.test_client()
    first = v.post("/api/v1/auth/login", json=login).get_json()["data"]
    assert first["organization"]["id"] != org_id
    # After switching, the next login remembers that workspace.
    vh = bearer(v.post("/api/v1/auth/switch-organization", json={"organization_id": org_id},
                       headers={"Authorization": f"Bearer {first['access_token']}"}))
    again = app.test_client().post("/api/v1/auth/login", json=login).get_json()["data"]
    assert again["organization"]["id"] == org_id
    # Leaving: the refresh cookie falls back to the remaining workspace instead of ending the session.
    assert v.delete(f"/api/v1/organization/members/{first['user']['id']}", headers=vh).status_code == 204
    refreshed = v.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS)
    assert refreshed.status_code == 200 and refreshed.get_json()["data"]["organization"]["id"] == first["organization"]["id"]
    # The activity log names the member, not just their id.
    logs = client.get("/api/v1/audit-logs?event=member.*", headers=headers).get_json()["data"]
    assert {(e["event"], e["details"].get("member")) for e in logs} == {("member.added", "Vi"), ("member.left", "Vi")}


# ---- activity log ----

def test_audit_log_endpoint(owner, app, db):
    client, headers, data = owner
    upload(client, headers)
    client.patch("/api/v1/organization", json={"name": "Renamed"}, headers=headers)
    logs = client.get("/api/v1/audit-logs", headers=headers).get_json()
    events = [e["event"] for e in logs["data"]]
    assert events[:2] == ["organization.updated", "repository.added"] and "user.registered" in events
    assert logs["data"][0]["user"] == "Ann"
    only_repo = client.get("/api/v1/audit-logs?event=repository.*", headers=headers).get_json()["data"]
    assert {e["event"] for e in only_repo} == {"repository.added"}
    since = (utcnow() + timedelta(minutes=1)).isoformat() + "Z"
    assert client.get(f"/api/v1/audit-logs?since={since}", headers=headers).get_json()["meta"]["total"] == 0
    for bad in ("event=DROP%20TABLE", "since=yesterday", "user_id=nope"):
        assert client.get(f"/api/v1/audit-logs?{bad}", headers=headers).status_code in (400, 404), bad
    dev, dh, _ = join(app, db, ObjectId(data["organization"]["id"]), "dev@example.com", "developer")
    assert dev.get("/api/v1/audit-logs", headers=dh).status_code == 403
    other = app.test_client()
    oh = bearer(register(other, email="bob@example.com", name="Bob"))
    assert all(e["event"] == "user.registered" for e in other.get("/api/v1/audit-logs", headers=oh).get_json()["data"])


# ---- retention ----

def _audit(db, org_id, repo_id, number, days_ago):
    when = utcnow() - timedelta(days=days_ago)
    aid = db.audits.insert_one({"organization_id": org_id, "repository_id": repo_id, "audit_number": number,
                                "branch": "upload", "audit_type": "full", "status": "completed", "stages": [],
                                "created_at": when, "updated_at": when, "completed_at": when,
                                "summary": {"counts": {}, "security_score": 100}}).inserted_id
    fid = db.findings.insert_one({"organization_id": org_id, "repository_id": repo_id, "audit_id": aid,
                                  "fingerprint": f"fp{number}", "title": "t", "severity": "low", "status": "new",
                                  "created_at": when, "updated_at": when}).inserted_id
    db.finding_comments.insert_one({"organization_id": org_id, "finding_id": fid, "user_id": ObjectId(),
                                    "body": "c", "created_at": when})
    return aid


def test_retention(owner, app, db):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    repo_id = ObjectId(upload(client, headers).get_json()["data"]["id"])
    old1, old2, recent = _audit(db, org_id, repo_id, 1, 200), _audit(db, org_id, repo_id, 2, 120), _audit(db, org_id, repo_id, 3, 5)
    db.audit_logs.insert_one({"organization_id": org_id, "event": "ancient", "created_at": utcnow() - timedelta(days=400)})
    from app.services import retention
    with app.app_context():
        preview = retention.apply(dry_run=True)
        assert preview["audits"] == 2 and db.audits.count_documents({"organization_id": org_id}) == 3
        assert retention.apply()["audits"] == 2
    assert [a["audit_number"] for a in db.audits.find({"organization_id": org_id})] == [3]
    assert db.findings.count_documents({"audit_id": {"$in": [old1, old2]}}) == 0
    assert db.finding_comments.count_documents({"organization_id": org_id}) == 1
    assert db.audit_logs.count_documents({"event": "ancient"}) == 0

    # The latest completed audit survives even when it's older than the retention period.
    db.audits.update_one({"_id": recent}, {"$set": {"created_at": utcnow() - timedelta(days=500)}})
    with app.app_context():
        assert retention.apply()["audits"] == 0

    # Source retention: old ZIP archives are deleted.
    client.patch("/api/v1/organization", json={"retention": {"source_days": 7}}, headers=headers)
    db.repositories.update_one({"_id": repo_id}, {"$set": {"source.uploaded_at": utcnow() - timedelta(days=10)}})
    with app.app_context():
        assert retention.apply()["archives"] == 1
    assert db.repositories.find_one({"_id": repo_id})["source"] is None
    assert db["source_archives.files"].count_documents({}) == 0
    started = client.post(f"/api/v1/repositories/{repo_id}/audits", json={}, headers=headers)
    assert started.status_code == 409 and started.get_json()["error"]["code"] == "no_source"


# ---- key rotation ----

def test_encryption_key_rotation(owner, app, db, remote):
    client, headers, _ = owner
    remote.add("https://github.com/acme/private", token="ghp_rotateme123")
    client.post("/api/v1/repositories", json={"url": "https://github.com/acme/private", "access_token": "ghp_rotateme123"},
                headers=headers)
    zip_repo = upload(client, headers).get_json()["data"]
    old_key = app.config["ENCRYPTION_KEYS"][0]
    new_key = Fernet.generate_key().decode()
    from app.services.crypto import init_crypto
    app.config["ENCRYPTION_KEYS"] = [new_key, old_key]
    init_crypto(app)
    result = app.test_cli_runner().invoke(args=["rotate-encryption-key"])
    assert result.exit_code == 0 and "1 access token(s) and 1 archive(s)" in result.output
    # Now only the new key is needed.
    app.config["ENCRYPTION_KEYS"] = [new_key]
    init_crypto(app)
    from app.services.crypto import decrypt_text
    from app.services.workspace import acquire_source
    with app.app_context():
        repo = db.repositories.find_one({"url": "https://github.com/acme/private"})
        assert decrypt_text(repo["credentials"]["encrypted_token"]) == "ghp_rotateme123"
        zrepo = db.repositories.find_one({"_id": ObjectId(zip_repo["id"])})
        with acquire_source(zrepo) as ws:
            assert ws.file_count == 2
    assert db["source_archives.files"].count_documents({}) == 1  # old archive removed


# ---- headers ----

def test_https_security_headers(app):
    app.config["PROXY_FIX"] = True
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    c = app.test_client()
    plain = c.get("/api/v1/health")
    assert "Strict-Transport-Security" not in plain.headers
    secure = c.get("/api/v1/health", headers={"X-Forwarded-Proto": "https"})
    assert secure.headers["Strict-Transport-Security"].startswith("max-age=31536000")
    for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
              "Permissions-Policy", "Cross-Origin-Opener-Policy"):
        assert h in secure.headers, h
