from datetime import timedelta

from bson import ObjectId
from pymongo.errors import WriteError

from .conftest import COOKIE_HEADERS, bearer, register


def _refresh_cookie(client):
    return client.get_cookie("aca_refresh", path="/api/v1/auth")


def test_register_returns_tokens_and_sets_refresh_cookie(client, db):
    resp = register(client, organization_name="Acme")
    assert resp.status_code == 201
    assert resp.headers["Location"] == "/api/v1/me"
    data = resp.get_json()["data"]
    assert data["token_type"] == "Bearer" and data["access_token"] and data["expires_in"] == 900
    assert data["role"] == "owner"
    assert data["organization"]["name"] == "Acme"
    assert "password_hash" not in data["user"]

    cookie_header = resp.headers["Set-Cookie"]
    for part in ("HttpOnly", "SameSite=Strict", "Path=/api/v1/auth"):
        assert part in cookie_header
    assert _refresh_cookie(client) is not None

    # Stored hashed, never the raw value
    assert db.refresh_tokens.count_documents({"token_hash": _refresh_cookie(client).value}) == 0
    assert db.audit_logs.count_documents({"event": "user.registered"}) == 1


def test_register_validation_errors_use_envelope(client):
    resp = register(client, email="not-an-email", password="short")
    assert resp.status_code == 400
    err = resp.get_json()["error"]
    assert err["code"] == "validation_error"
    assert set(err["details"]) == {"email", "password"}

    resp = client.post("/api/v1/auth/register", data="nope", content_type="text/plain")
    assert resp.status_code == 400 and resp.get_json()["error"]["code"] == "bad_request"


def test_register_duplicate_email_conflicts(client):
    assert register(client).status_code == 201
    resp = register(client, email="ANN@example.com")
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == "conflict"


def test_login(client, db):
    register(client)
    bad = client.post("/api/v1/auth/login", json={"email": "ann@example.com", "password": "wrong-password"})
    assert bad.status_code == 401
    assert bad.get_json()["error"]["message"] == "Invalid email or password"
    unknown = client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"})
    assert unknown.status_code == 401

    ok = client.post("/api/v1/auth/login", json={"email": " Ann@Example.com ", "password": "supersecret1"})
    assert ok.status_code == 200
    assert client.get("/api/v1/me", headers=bearer(ok)).status_code == 200
    assert db.audit_logs.count_documents({"event": "user.login_failed"}) == 1


def test_me_requires_valid_bearer_token(owner):
    client, headers, _ = owner
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Basic abc"}).status_code == 401
    resp = client.get("/api/v1/me", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["data"]["user"]["email"] == "ann@example.com"


def test_expired_access_token(app, owner):
    client, _, _ = owner
    with app.app_context():
        from app.services.tokens import create_access_token
        me = client.get("/api/v1/me", headers=owner[1]).get_json()["data"]
        app.config["ACCESS_TOKEN_TTL"] = timedelta(seconds=-1)
        token, _ = create_access_token(ObjectId(me["user"]["id"]), ObjectId(me["organization"]["id"]), "owner")
    resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "token_expired"


def test_disabled_user_token_rejected(owner, db):
    client, headers, data = owner
    db.users.update_one({"_id": ObjectId(data["user"]["id"])}, {"$set": {"status": "disabled"}})
    assert client.get("/api/v1/me", headers=headers).status_code == 401


def test_refresh_requires_csrf_headers(owner):
    client, _, _ = owner
    assert client.post("/api/v1/auth/refresh").status_code == 403
    assert client.post("/api/v1/auth/refresh", headers={"X-Requested-With": "fetch"}).status_code == 403
    evil = {"X-Requested-With": "fetch", "Origin": "https://evil.example"}
    resp = client.post("/api/v1/auth/refresh", headers=evil)
    assert resp.status_code == 403 and resp.get_json()["error"]["code"] == "csrf_failed"


def test_refresh_rotates_token(owner):
    client, _, _ = owner
    first = _refresh_cookie(client).value
    resp = client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS)
    assert resp.status_code == 200
    second = _refresh_cookie(client).value
    assert second != first
    assert client.get("/api/v1/me", headers=bearer(resp)).status_code == 200


def test_refresh_reuse_within_grace_is_allowed_without_new_cookie(owner):
    client, _, _ = owner
    old = _refresh_cookie(client).value
    client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS)
    new = _refresh_cookie(client).value

    # A second tab still holding the old cookie refreshes at the same moment
    client.set_cookie("aca_refresh", old, path="/api/v1/auth")
    resp = client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS)
    assert resp.status_code == 200
    assert "Set-Cookie" not in resp.headers
    # The real browser still holds the rotated token, which keeps working
    client.set_cookie("aca_refresh", new, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS).status_code == 200


def test_refresh_reuse_after_grace_revokes_family(app, owner, db):
    client, _, _ = owner
    app.config["REFRESH_REUSE_GRACE"] = timedelta(0)
    stolen = _refresh_cookie(client).value
    client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS)
    legit = _refresh_cookie(client).value

    client.set_cookie("aca_refresh", stolen, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS).status_code == 401
    # The whole family is revoked, including the legitimate latest token
    client.set_cookie("aca_refresh", legit, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS).status_code == 401
    assert db.audit_logs.count_documents({"event": "auth.refresh_token_reuse"}) == 1


def test_logout_revokes_refresh_token(owner):
    client, _, _ = owner
    cookie = _refresh_cookie(client).value
    assert client.post("/api/v1/auth/logout").status_code == 403  # CSRF headers required
    resp = client.post("/api/v1/auth/logout", headers=COOKIE_HEADERS)
    assert resp.status_code == 204
    assert _refresh_cookie(client) is None
    client.set_cookie("aca_refresh", cookie, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS).status_code == 401


def test_switch_organization(owner, db):
    client, headers, data = owner
    user_id = ObjectId(data["user"]["id"])
    other = db.organizations.find_one({"_id": ObjectId(data["organization"]["id"])})
    other.pop("_id")
    other.update(name="Second Org", members=[{"user_id": user_id, "role": "viewer", "joined_at": other["created_at"]}])
    other_id = db.organizations.insert_one(other).inserted_id

    orgs = client.get("/api/v1/me/organizations", headers=headers).get_json()["data"]
    assert [o["current"] for o in orgs] == [True, False]

    resp = client.post("/api/v1/auth/switch-organization", json={"organization_id": str(other_id)}, headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["data"]["role"] == "viewer"
    me = client.get("/api/v1/me", headers=bearer(resp)).get_json()["data"]
    assert me["organization"]["name"] == "Second Org"

    # The refresh cookie now resumes in the switched organization
    refreshed = client.post("/api/v1/auth/refresh", headers=COOKIE_HEADERS).get_json()["data"]
    assert refreshed["organization"]["id"] == str(other_id)

    stranger = db.organizations.insert_one({**other, "_id": ObjectId(), "members": []}).inserted_id
    assert client.post("/api/v1/auth/switch-organization", json={"organization_id": str(stranger)},
                       headers=headers).status_code == 404
    assert client.post("/api/v1/auth/switch-organization", json={"organization_id": "bad"},
                       headers=headers).status_code == 404


def test_schema_validators_are_enforced(db):
    try:
        db.users.insert_one({"email": "x@example.com"})
    except WriteError:
        pass
    else:
        raise AssertionError("validator should reject incomplete user")
