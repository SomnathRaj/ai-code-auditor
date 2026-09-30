import io
import os
import stat
import zipfile

import pytest
from bson import ObjectId

from app.services import source_archive
from app.services.workspace import acquire_source, purge_stale_workspaces

from .conftest import bearer, register
from .test_repositories import _create

UPLOAD = "/api/v1/repositories/uploads"


def make_zip(entries: dict | list, *, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        items = entries.items() if isinstance(entries, dict) else entries
        for name, content in items:
            zf.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


PROJECT = make_zip({"myproj-main/app.py": "print('hello')\n", "myproj-main/lib/util.py": "X = 1\n"})


def upload(client, headers, data=PROJECT, filename="myproj-main.zip", name=None, url=UPLOAD, method="post"):
    form = {"file": (io.BytesIO(data), filename)}
    if name:
        form["name"] = name
    return getattr(client, method)(url, data=form, headers=headers, content_type="multipart/form-data")


def test_upload_creates_zip_repository(owner, db, app):
    client, headers, data = owner
    resp = upload(client, headers)
    assert resp.status_code == 201, resp.get_json()
    repo = resp.get_json()["data"]
    assert repo["provider"] == "zip" and repo["name"] == "myproj-main" and repo["default_branch"] is None
    assert repo["source"]["file_count"] == 2 and repo["source"]["filename"] == "myproj-main.zip"
    assert resp.headers["Location"] == f"/api/v1/repositories/{repo['id']}"

    # Stored encrypted: the GridFS chunks never contain the plaintext archive.
    files = db["source_archives.files"].find_one({"metadata.repository_id": ObjectId(repo["id"])})
    assert files["metadata"]["encrypted"] is True
    raw = b"".join(c["data"] for c in db["source_archives.chunks"].find({"files_id": files["_id"]}))
    assert b"print('hello')" not in raw and b"PK\x03\x04" not in raw

    # The audit workspace gets the decrypted, extracted tree with the top folder stripped.
    stored = db.repositories.find_one({"_id": ObjectId(repo["id"])})
    with app.app_context(), acquire_source(stored) as ws:
        assert open(os.path.join(ws.source_dir, "app.py")).read() == "print('hello')\n"
        assert os.path.isfile(os.path.join(ws.source_dir, "lib", "util.py"))
        assert ws.file_count == 2 and ws.commit_hash == repo["source"]["sha256"][:12]
        mode = os.stat(os.path.join(ws.source_dir, "app.py")).st_mode & 0o777
        assert mode == 0o600


def test_upload_custom_name(owner):
    client, headers, _ = owner
    assert upload(client, headers, name="Billing API").get_json()["data"]["name"] == "Billing API"


@pytest.mark.parametrize("entries,symlink,expected", [
    ({"../evil.py": "x"}, None, "Path traversal"),
    ({"a/../../evil.py": "x"}, None, "Path traversal"),
    ({"/etc/cron.d/x": "x"}, None, "Absolute paths"),
    ({"C:\\Windows\\x": "x"}, None, "Absolute paths"),
    ({"ok.py": "x"}, "link", "Symbolic links"),
    ({}, None, "no files"),
    ([("a.py", "1"), ("A.py", "2")], None, "Duplicate"),
])
def test_unsafe_archives_rejected(owner, db, entries, symlink, expected):
    client, headers, _ = owner
    resp = upload(client, headers, data=make_zip(entries, symlink=symlink))
    assert resp.status_code == 422, resp.get_json()
    err = resp.get_json()["error"]
    assert err["code"] == "unsafe_archive" and expected in err["message"]
    assert db.repositories.count_documents({}) == 0
    assert db["source_archives.files"].count_documents({}) == 0  # nothing stored


def test_limits(owner, app):
    client, headers, _ = owner
    app.config["MAX_SOURCE_FILES"] = 3
    resp = upload(client, headers, data=make_zip({f"f{i}.py": "x" for i in range(4)}))
    assert resp.status_code == 422 and "more than 3 files" in resp.get_json()["error"]["message"]

    app.config["MAX_SOURCE_FILES"] = 50000
    app.config["MAX_SOURCE_BYTES"] = 1000
    resp = upload(client, headers, data=make_zip({"big.txt": "x" * 2000}))
    assert resp.status_code == 422 and "expands to more than" in resp.get_json()["error"]["message"]


def test_zip_bomb_ratio(owner):
    client, headers, _ = owner
    resp = upload(client, headers, data=make_zip({"bomb.txt": "\0" * (5 * 1024 * 1024)}))
    assert resp.status_code == 422 and "compression ratio" in resp.get_json()["error"]["message"]


def test_not_a_zip_and_bad_requests(owner, app):
    client, headers, _ = owner
    resp = upload(client, headers, data=b"not a zip at all")
    assert resp.status_code == 422 and resp.get_json()["error"]["code"] == "invalid_archive"
    assert upload(client, headers, filename="project.tar.gz").status_code == 400
    missing = client.post(UPLOAD, data={}, headers=headers, content_type="multipart/form-data")
    assert missing.status_code == 400 and missing.get_json()["error"]["details"] == {"file": "required"}
    assert client.post(UPLOAD, json={"file": "x"}, headers=headers).status_code == 415

    app.config["MAX_CONTENT_LENGTH"] = 1024
    too_big = upload(client, headers, data=make_zip({"a.txt": os.urandom(4096).hex()}))
    assert too_big.status_code == 413 and too_big.get_json()["error"]["code"] == "payload_too_large"


def test_safe_extract_enforces_real_bytes(app, tmp_path):
    """Headers can lie; extraction counts bytes actually written."""
    zpath = tmp_path / "a.zip"
    zpath.write_bytes(make_zip({"a.txt": "x" * 5000}))
    dest = tmp_path / "out"
    dest.mkdir()
    with app.app_context(), pytest.raises(source_archive.UnsafeArchive):
        source_archive.safe_extract(str(zpath), str(dest), max_bytes=1000)


def test_tampered_archive_fails_integrity_check(owner, db, app):
    client, headers, _ = owner
    repo = upload(client, headers).get_json()["data"]
    stored = db.repositories.find_one({"_id": ObjectId(repo["id"])})
    stored["source"]["sha256"] = "0" * 64
    with app.app_context(), pytest.raises(Exception) as exc:
        with acquire_source(stored):
            pass
    assert "integrity" in str(exc.value)
    assert os.listdir(app.config["WORK_DIR"]) == []


def test_replace_source(owner, db):
    client, headers, _ = owner
    repo = upload(client, headers).get_json()["data"]
    old_archive = db.repositories.find_one({"_id": ObjectId(repo["id"])})["source"]["archive_id"]

    v2 = make_zip({"app.py": "print('v2')\n"})
    resp = upload(client, headers, data=v2, filename="v2.zip", url=f"/api/v1/repositories/{repo['id']}/source",
                  method="put")
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["data"]["source"]["filename"] == "v2.zip"
    assert db["source_archives.files"].count_documents({"_id": old_archive}) == 0
    assert db["source_archives.files"].count_documents({}) == 1


def test_replace_source_rules(owner, db, app):
    client, headers, data = owner
    github = _create(client, headers).get_json()["data"]
    resp = upload(client, headers, url=f"/api/v1/repositories/{github['id']}/source", method="put")
    assert resp.status_code == 409

    repo = upload(client, headers).get_json()["data"]
    org_id = ObjectId(data["organization"]["id"])
    from app.db.utils import utcnow
    for role, expected in (("developer", 200), ("viewer", 403)):
        member = app.test_client()
        m = register(member, email=f"{role}@example.com", name=role).get_json()["data"]
        db.organizations.update_one({"_id": org_id}, {"$push": {"members": {
            "user_id": ObjectId(m["user"]["id"]), "role": role, "joined_at": utcnow()}}})
        h = bearer(member.post("/api/v1/auth/switch-organization", json={"organization_id": str(org_id)},
                               headers={"Authorization": f"Bearer {m['access_token']}"}))
        resp = upload(member, h, url=f"/api/v1/repositories/{repo['id']}/source", method="put")
        assert resp.status_code == expected, role
        assert upload(member, h).status_code == 403  # creating repositories stays owner/admin

    other = app.test_client()
    oh = bearer(register(other, email="bob@example.com", name="Bob"))
    assert upload(other, oh, url=f"/api/v1/repositories/{repo['id']}/source", method="put").status_code == 404


def test_delete_removes_archives(owner, db):
    client, headers, _ = owner
    repo = upload(client, headers).get_json()["data"]
    assert client.delete(f"/api/v1/repositories/{repo['id']}", headers=headers).status_code == 204
    assert db["source_archives.files"].count_documents({}) == 0
    assert db["source_archives.chunks"].count_documents({}) == 0


def test_purge_stale_workspaces(app):
    with app.app_context():
        from app.services.workspace import work_root
        root = work_root()
        old = os.path.join(root, "ws-old")
        new = os.path.join(root, "ws-new")
        os.mkdir(old)
        os.mkdir(new)
        os.utime(old, (0, 0))
        assert purge_stale_workspaces(3600) == 1
        assert not os.path.exists(old) and os.path.exists(new)
        assert oct(os.stat(root).st_mode & 0o777) == "0o700"
