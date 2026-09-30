"""API tests run against a real MongoDB given by TEST_MONGODB_URI (read from .env
or the environment). Each test gets its own throwaway `aca_test_*` database,
dropped afterwards; the app's own MONGODB_DATABASE is never touched.
"""
import os
import uuid

import pytest
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from cryptography.fernet import Fernet

from app import create_app
from app.db import get_db
from app.db.schema import ensure_schema
from app.services import git_client

TEST_MONGODB_URI = os.environ.get("TEST_MONGODB_URI")
ORIGIN = "http://localhost"


def _mongo_available() -> bool:
    if not TEST_MONGODB_URI:
        return False
    try:
        MongoClient(TEST_MONGODB_URI, serverSelectionTimeoutMS=2000).admin.command("ping")
        return True
    except PyMongoError:
        return False


MONGO_AVAILABLE = _mongo_available()


@pytest.fixture(autouse=True)
def _require_mongo():
    if not MONGO_AVAILABLE:
        pytest.skip("TEST_MONGODB_URI not set or MongoDB unreachable")


@pytest.fixture
def app(tmp_path):
    db_name = f"aca_test_{uuid.uuid4().hex[:10]}"
    app = create_app({
        "ENCRYPTION_KEYS": [Fernet.generate_key().decode()],
        "GEMINI_API_KEY": None,  # never call a real AI provider from tests
        "RATE_LIMIT_ENABLED": False,  # many tests register from the same IP; test_security enables it
        "WORK_DIR": str(tmp_path / "work"),
        "TESTING": True,
        "JWT_SECRET": "test-secret-" + "x" * 32,
        "MONGODB_URI": TEST_MONGODB_URI,
        "MONGODB_DATABASE": db_name,
        "COOKIE_SECURE": False,
        "ALLOWED_ORIGINS": [],
        "SERVE_FRONTEND": True,
    })
    with app.app_context():
        ensure_schema(get_db())
    yield app
    client = app.extensions["mongo_client"]
    client.drop_database(db_name)
    client.close()


class FakeRemote:
    """Stands in for GitHub in API tests (tests marked `real_git` use real git)."""

    def __init__(self):
        self.repos = {}  # url -> (default_branch, [branches], required_token or None)
        self.calls = []

    def add(self, url, default="main", branches=("main", "develop"), token=None):
        self.repos[url] = (default, list(branches), token)

    def ls_remote(self, url, token=None):
        self.calls.append((url, token))
        if url not in self.repos:
            raise git_client.GitError("repository_inaccessible",
                                      "Repository not found or not accessible. Private repositories need an access token.")
        default, branches, required = self.repos[url]
        if required and token != required:
            raise git_client.GitError("repository_inaccessible",
                                      "Repository not found or not accessible. Private repositories need an access token.")
        return git_client.RemoteInfo(default_branch=default, branches={b: "0" * 40 for b in branches})


@pytest.fixture(autouse=True)
def remote(request, monkeypatch):
    fake = FakeRemote()
    for suffix in ("", "0", "1", "2", "-x"):
        fake.add(f"https://github.com/pallets/flask{suffix}")
    if "real_git" not in request.keywords:
        monkeypatch.setattr(git_client, "ls_remote", fake.ls_remote)
    return fake


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    with app.app_context():
        yield get_db()


COOKIE_HEADERS = {"X-Requested-With": "fetch", "Origin": ORIGIN}


def register(client, email="ann@example.com", name="Ann", password="supersecret1", **extra):
    return client.post("/api/v1/auth/register", json={"name": name, "email": email, "password": password, **extra})


def bearer(resp) -> dict:
    return {"Authorization": f"Bearer {resp.get_json()['data']['access_token']}"}


@pytest.fixture
def owner(client):
    """A registered owner: (client, auth headers, response data)."""
    resp = register(client)
    assert resp.status_code == 201, resp.get_json()
    return client, bearer(resp), resp.get_json()["data"]


def run_audit(app, repo: dict, branch=None, audit_type="full") -> dict:
    """Queue an audit for `repo` and process it with a real worker, synchronously."""
    from app.services.audit_service import enqueue
    from app.worker import AuditWorker

    with app.app_context():
        audit = enqueue(repo, None, branch, audit_type)
        AuditWorker(app, worker_id="test-worker").run_once(audit["_id"])
        return get_db().audits.find_one({"_id": audit["_id"]})
