from bson import ObjectId

from app.services import git_client
from app.services.crypto import decrypt_text

from .conftest import bearer, register
from .test_repositories import URL, _create


def test_create_uses_remote_default_branch(owner, remote):
    client, headers, _ = owner
    remote.add("https://github.com/acme/legacy", default="master", branches=["master", "dev"])
    repo = _create(client, headers, url="https://github.com/acme/legacy").get_json()["data"]
    assert repo["default_branch"] == "master"
    assert repo["has_access_token"] is False


def test_create_rejects_missing_branch_and_inaccessible_repo(owner, remote):
    client, headers, _ = owner
    resp = _create(client, headers, default_branch="nope")
    assert resp.status_code == 400 and resp.get_json()["error"]["code"] == "branch_not_found"

    resp = _create(client, headers, url="https://github.com/acme/private")
    assert resp.status_code == 422
    assert "access token" in resp.get_json()["error"]["message"]


def test_create_network_error_is_502(owner, monkeypatch):
    client, headers, _ = owner

    def down(url, token=None):
        raise git_client.GitError("network_error", "Could not reach the Git provider")

    monkeypatch.setattr(git_client, "ls_remote", down)
    resp = _create(client, headers)
    assert resp.status_code == 502 and resp.get_json()["error"]["code"] == "network_error"


def test_private_repository_token_encrypted(owner, remote, db):
    client, headers, _ = owner
    url = "https://github.com/acme/private"
    remote.add(url, token="ghp_abc123")
    resp = _create(client, headers, url=url, access_token="ghp_abc123")
    assert resp.status_code == 201, resp.get_json()
    repo = resp.get_json()["data"]
    assert repo["has_access_token"] is True
    assert "ghp_abc123" not in resp.get_data(as_text=True)
    assert remote.calls[-1] == (url, "ghp_abc123")

    stored = db.repositories.find_one({"_id": ObjectId(repo["id"])})
    enc = stored["credentials"]["encrypted_token"]
    assert "ghp_abc123" not in str(stored) and decrypt_text_in_app(client, enc) == "ghp_abc123"
    assert "ghp_abc123" not in str(list(db.audit_logs.find()))

    # Branch listing uses the stored token
    branches = client.get(f"/api/v1/repositories/{repo['id']}/branches", headers=headers).get_json()
    assert [b["name"] for b in branches["data"]] == ["main", "develop"]
    assert remote.calls[-1] == (url, "ghp_abc123")


def decrypt_text_in_app(client, token):
    with client.application.app_context():
        return decrypt_text(token)


def test_invalid_token_format(owner):
    client, headers, _ = owner
    resp = _create(client, headers, access_token="bad token with spaces")
    assert resp.status_code == 400 and "access_token" in resp.get_json()["error"]["details"]


def test_branches_endpoint(owner, remote):
    client, headers, _ = owner
    remote.add(URL, default="develop", branches=["main", "develop", "feature/a", "feature/b"])
    repo = _create(client, headers).get_json()["data"]
    path = f"/api/v1/repositories/{repo['id']}/branches"
    data = client.get(path, headers=headers).get_json()
    assert data["data"][0] == {"name": "develop", "default": True}
    assert data["meta"]["total"] == 4
    filtered = client.get(f"{path}?q=FEATURE&per_page=1&page=2", headers=headers).get_json()
    assert filtered["data"] == [{"name": "feature/b", "default": False}]
    assert filtered["meta"]["total"] == 2


def test_branches_for_zip_repo_is_409(owner):
    from .test_zip_uploads import upload
    client, headers, _ = owner
    repo = upload(client, headers).get_json()["data"]
    resp = client.get(f"/api/v1/repositories/{repo['id']}/branches", headers=headers)
    assert resp.status_code == 409


def test_patch_repository(owner, remote, db):
    client, headers, _ = owner
    repo = _create(client, headers).get_json()["data"]
    path = f"/api/v1/repositories/{repo['id']}"

    resp = client.patch(path, json={"name": "Flask core", "default_branch": "develop"}, headers=headers)
    assert resp.status_code == 200
    body = resp.get_json()["data"]
    assert body["name"] == "Flask core" and body["default_branch"] == "develop"

    assert client.patch(path, json={"default_branch": "ghost"}, headers=headers).status_code == 400
    assert client.patch(path, json={"name": ""}, headers=headers).status_code == 400
    assert client.patch(path, json={"name": None}, headers=headers).status_code == 400

    # Add then remove a token; a wrong token is rejected before saving.
    remote.add(URL, token="ghp_good")
    assert client.patch(path, json={"access_token": "ghp_wrong"}, headers=headers).status_code == 422
    assert client.patch(path, json={"access_token": "ghp_good"}, headers=headers).get_json()["data"]["has_access_token"]
    remote.add(URL)
    resp = client.patch(path, json={"access_token": None}, headers=headers)
    assert resp.get_json()["data"]["has_access_token"] is False
    assert db.repositories.find_one({"_id": ObjectId(repo["id"])})["credentials"] is None
    assert db.audit_logs.count_documents({"event": "repository.updated"}) == 3


def test_patch_rules(owner, app, db):
    from .test_zip_uploads import upload
    client, headers, data = owner
    zip_repo = upload(client, headers).get_json()["data"]
    zpath = f"/api/v1/repositories/{zip_repo['id']}"
    assert client.patch(zpath, json={"default_branch": "main"}, headers=headers).status_code == 409
    assert client.patch(zpath, json={"name": "Renamed"}, headers=headers).status_code == 200

    other = app.test_client()
    oh = bearer(register(other, email="bob@example.com", name="Bob"))
    assert other.patch(zpath, json={"name": "x"}, headers=oh).status_code == 404
    assert other.get(f"{zpath}/branches", headers=oh).status_code == 404
