"""Audit pipeline: queue API, worker claim/stages, cancellation, timeouts, recovery."""
import threading
import time
from datetime import timedelta

import pytest
from bson import ObjectId

from app import worker as worker_mod
from app.db.utils import utcnow
from app.scanners.models import Finding, ProjectInfo, ScanResult
from app.scanners.runner import RunnerConfig, run_tool
from app.worker import AuditWorker

from .conftest import bearer, register
from .test_zip_uploads import upload

FAST = {"WORKER_POLL_SECONDS": 0.05, "WORKER_HEARTBEAT_SECONDS": 0.1, "WORKER_STALE_SECONDS": 1,
        "AUDIT_TIMEOUT_SECONDS": 60, "AUDIT_MAX_ATTEMPTS": 2, "WORKER_CONCURRENCY": 1}


@pytest.fixture(autouse=True)
def fast_worker(app):
    app.config.update(FAST)


def fake_result(n_findings=1, failed=(), enabled=("semgrep", "gitleaks", "dependencies")):
    project = ProjectInfo(languages=[{"name": "Python", "files": 1, "bytes": 10, "percent": 100.0, "supported": True}],
                          primary_language="Python", frameworks=["Flask"], manifests=[], file_count=1, total_bytes=10)
    findings = [Finding(scanner="semgrep", rule_id=f"aca-test-{i}", title="t", category="Injection", severity="high",
                        confidence=0.7, file="app.py", line_start=i + 1, line_end=i + 1, message=f"m{i}")
                for i in range(n_findings)]
    return ScanResult(project=project, findings=findings, dependencies=[], scanner_versions={"rules": "test"},
                      errors=[{"scanner": s, "message": f"{s} broke"} for s in failed],
                      failed_scanners=sorted(failed), enabled_scanners=sorted(enabled))


class FakeScan:
    """Stands in for run_scan: reports stages, optionally blocks until released or cancelled."""

    def __init__(self, result=None, block=False):
        self.result = result or fake_result()
        self.block = block
        self.started = threading.Event()
        self.release = threading.Event()
        self.settings = None

    def __call__(self, source_dir, work_dir, settings, cfg, *, progress, cancel):
        self.settings = settings
        progress("detecting", "running")
        progress("detecting", "completed", "Flask / Python")
        progress("scanning", "running")
        self.started.set()
        while self.block and not self.release.is_set():
            cancel.raise_if_cancelled()
            time.sleep(0.02)
        progress("scanning", "completed", "1 issues found")
        progress("dependency_analysis", "completed", "0 dependencies, 0 vulnerable")
        return self.result


@pytest.fixture
def fake_scan(monkeypatch):
    scan = FakeScan()
    monkeypatch.setattr(worker_mod, "run_scan", scan)
    return scan


@pytest.fixture
def repo(owner):
    client, headers, _ = owner
    return upload(client, headers).get_json()["data"]


def start(client, headers, repo_id, **body):
    return client.post(f"/api/v1/repositories/{repo_id}/audits", json=body, headers=headers)


def in_thread(fn):
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    return t


def wait_for(predicate, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


# ---- API ----

def test_start_returns_202_and_status(owner, repo):
    client, headers, _ = owner
    resp = start(client, headers, repo["id"])
    assert resp.status_code == 202
    data = resp.get_json()["data"]
    assert resp.headers["Location"] == f"/api/v1/audits/{data['id']}/status"
    assert data["status"] == "queued" and data["display_id"] == "AUD-1" and data["progress"] == 0
    assert [s["name"] for s in data["stages"]] == ["cloning", "detecting", "scanning", "dependency_analysis",
                                                   "ai_analysis", "processing"]
    assert data["stages"][0]["label"] == "Extract archive" and not data["is_final"]

    detail = client.get(f"/api/v1/audits/{data['id']}", headers=headers).get_json()["data"]
    assert detail["repository"]["name"] == "myproj-main" and detail["settings"]["enabled_scanners"]
    assert client.get(f"/api/v1/audits/{data['id']}/status", headers=headers).get_json()["data"]["status"] == "queued"


def test_one_active_audit_per_repository(owner, repo, app, fake_scan):
    client, headers, _ = owner
    assert start(client, headers, repo["id"]).status_code == 202
    again = start(client, headers, repo["id"])
    assert again.status_code == 409 and "already queued or running" in again.get_json()["error"]["message"]
    assert AuditWorker(app).run_once() == "completed"
    assert start(client, headers, repo["id"]).status_code == 202  # allowed again once finished


def test_audit_types_and_validation(owner, repo, db, fake_scan, app):
    client, headers, _ = owner
    assert start(client, headers, repo["id"], audit_type="bogus").status_code == 400
    resp = start(client, headers, repo["id"], audit_type="quick")
    assert resp.status_code == 202
    AuditWorker(app).run_once()
    assert fake_scan.settings["enabled_scanners"] == ["gitleaks", "semgrep"]
    assert fake_scan.settings["severity_threshold"] == "high"

    db.repositories.update_one({"_id": ObjectId(repo["id"])}, {"$set": {"settings.enabled_scanners": ["dependencies"]}})
    bad = start(client, headers, repo["id"], audit_type="secret")
    assert bad.status_code == 400 and bad.get_json()["error"]["details"] == {"audit_type": "no_enabled_scanners"}
    assert start(client, headers, repo["id"], audit_type="dependency").status_code == 202


def test_roles_and_tenant_isolation(owner, repo, app, db, fake_scan):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]

    other = app.test_client()
    oh = bearer(register(other, email="bob@example.com", name="Bob"))
    for method, path in (("get", f"/api/v1/audits/{audit_id}"), ("get", f"/api/v1/audits/{audit_id}/status"),
                         ("post", f"/api/v1/audits/{audit_id}/cancel"), ("delete", f"/api/v1/audits/{audit_id}"),
                         ("post", f"/api/v1/repositories/{repo['id']}/audits")):
        kwargs = {"json": {}} if method == "post" else {}
        assert getattr(other, method)(path, headers=oh, **kwargs).status_code == 404, path
    assert other.get("/api/v1/audits/not-an-id", headers=oh).status_code == 404

    AuditWorker(app).run_once()
    for role, can_start, can_delete in (("viewer", 403, 403), ("developer", 202, 403)):
        member = app.test_client()
        m = register(member, email=f"{role}@example.com", name=role).get_json()["data"]
        db.organizations.update_one({"_id": org_id}, {"$push": {"members": {
            "user_id": ObjectId(m["user"]["id"]), "role": role, "joined_at": utcnow()}}})
        h = bearer(member.post("/api/v1/auth/switch-organization", json={"organization_id": str(org_id)},
                               headers={"Authorization": f"Bearer {m['access_token']}"}))
        assert member.get(f"/api/v1/audits/{audit_id}", headers=h).status_code == 200
        assert start(member, h, repo["id"]).status_code == can_start, role
        assert member.delete(f"/api/v1/audits/{audit_id}", headers=h).status_code == can_delete, role


# ---- worker ----

def test_worker_stages_and_results(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]
    assert AuditWorker(app, worker_id="w1").run_once() == "completed"
    status = client.get(f"/api/v1/audits/{audit_id}/status", headers=headers).get_json()["data"]
    assert status["status"] == "completed" and status["progress"] == 100 and status["is_final"]
    detail = client.get(f"/api/v1/audits/{audit_id}", headers=headers).get_json()["data"]
    assert detail["started_at"] and detail["duration"] is not None  # regression: $min on a null started_at
    stages = {s["name"]: s for s in status["stages"]}
    assert stages["cloning"]["status"] == "completed" and stages["cloning"]["detail"].startswith("2 files")
    assert stages["detecting"]["detail"] == "Flask / Python"
    assert stages["ai_analysis"]["status"] == "skipped" and stages["processing"]["status"] == "completed"
    audit = db.audits.find_one({"_id": ObjectId(audit_id)})
    assert "active" not in audit and audit["attempts"] == 1 and audit["worker"]["id"] == "w1"
    assert db.findings.count_documents({"audit_id": audit["_id"]}) == 1
    events = {e["event"] for e in db.audit_logs.find()}
    assert {"audit.queued", "audit.started", "audit.completed"} <= events


def test_claim_is_atomic(owner, app, db, fake_scan):
    client, headers, _ = owner
    from .test_zip_uploads import make_zip
    ids = []
    for i in range(6):
        rid = upload(client, headers, data=make_zip({"a.py": f"x={i}"}), filename=f"p{i}.zip").get_json()["data"]["id"]
        ids.append(start(client, headers, rid).get_json()["data"]["id"])
    claimed, lock = [], threading.Lock()

    def grab(n):
        w = AuditWorker(app, worker_id=f"w{n}")
        with app.app_context():
            while (a := w.claim()) is not None:
                with lock:
                    claimed.append(str(a["_id"]))

    threads = [in_thread(lambda n=n: grab(n)) for n in range(4)]
    for t in threads:
        t.join(10)
    assert sorted(claimed) == sorted(ids)  # every audit claimed exactly once


def test_cancel_queued(owner, repo, db):
    client, headers, _ = owner
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]
    resp = client.post(f"/api/v1/audits/{audit_id}/cancel", headers=headers)
    assert resp.status_code == 202 and resp.get_json()["data"]["status"] == "cancelled"
    assert all(s["status"] == "cancelled" for s in resp.get_json()["data"]["stages"])
    assert client.post(f"/api/v1/audits/{audit_id}/cancel", headers=headers).status_code == 409
    assert start(client, headers, repo["id"]).status_code == 202  # repository free again


def test_cancel_running_audit(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    fake_scan.block = True
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]
    result = {}
    t = in_thread(lambda: result.setdefault("status", AuditWorker(app).run_once()))
    assert fake_scan.started.wait(10)
    status = client.get(f"/api/v1/audits/{audit_id}/status", headers=headers).get_json()["data"]
    assert status["status"] == "scanning" and 0 < status["progress"] < 100

    assert client.post(f"/api/v1/audits/{audit_id}/cancel", headers=headers).status_code == 202
    t.join(10)
    assert result["status"] == "cancelled"
    audit = db.audits.find_one({"_id": ObjectId(audit_id)})
    assert audit["status"] == "cancelled" and audit["error"]["code"] == "cancelled" and "active" not in audit
    assert {s["name"]: s["status"] for s in audit["stages"]}["scanning"] == "cancelled"
    assert db.findings.count_documents({"audit_id": audit["_id"]}) == 0


def test_cancel_kills_running_scanner_process(owner, repo, app, monkeypatch, tmp_path):
    """Cancellation reaches real subprocesses: a 30 s tool stops within a second or two."""
    client, headers, _ = owner
    cfg = RunnerConfig(bin_dirs=[], cpu_seconds=60, memory_mb=1024, max_output_mb=16, scanner_user=None)
    began = threading.Event()

    def slow_scan(source_dir, work_dir, settings, scan_cfg, *, progress, cancel):
        progress("scanning", "running")
        began.set()
        run_tool("sleeper", ["/bin/sh", "-c", "sleep 30 & sleep 30"], cwd=str(tmp_path), work_dir=str(tmp_path),
                 timeout=60, cfg=cfg, cancel=cancel)
        return fake_result()

    monkeypatch.setattr(worker_mod, "run_scan", slow_scan)
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]
    result = {}
    t = in_thread(lambda: result.setdefault("status", AuditWorker(app).run_once()))
    assert began.wait(10)
    t0 = time.monotonic()
    client.post(f"/api/v1/audits/{audit_id}/cancel", headers=headers)
    t.join(10)
    assert result["status"] == "cancelled" and time.monotonic() - t0 < 5


def test_timeout(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    app.config["AUDIT_TIMEOUT_SECONDS"] = 0.3
    fake_scan.block = True
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]
    assert AuditWorker(app).run_once() == "failed"
    audit = db.audits.find_one({"_id": ObjectId(audit_id)})
    assert audit["error"]["code"] == "timeout" and "time limit" in audit["error"]["message"]


def test_all_scanners_failed(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    fake_scan.result = fake_result(failed=("semgrep", "gitleaks", "dependencies"))
    audit_id = start(client, headers, repo["id"]).get_json()["data"]["id"]
    assert AuditWorker(app).run_once() == "failed"
    err = db.audits.find_one({"_id": ObjectId(audit_id)})["error"]
    assert err["code"] == "scanner_failed" and "semgrep broke" in err["message"]

    fake_scan.result = fake_result(failed=("semgrep",))  # partial failure → completed with warnings
    start(client, headers, repo["id"])
    assert AuditWorker(app).run_once() == "completed"


def test_partial_results_from_earlier_attempt_are_replaced(owner, repo, app, db, fake_scan):
    client, headers, data = owner
    audit_id = ObjectId(start(client, headers, repo["id"]).get_json()["data"]["id"])
    db.findings.insert_one({"organization_id": ObjectId(data["organization"]["id"]), "repository_id": ObjectId(repo["id"]),
                            "audit_id": audit_id, "fingerprint": "stale", "title": "left over", "severity": "low",
                            "status": "new", "created_at": utcnow(), "updated_at": utcnow()})
    AuditWorker(app).run_once()
    assert [f["title"] for f in db.findings.find({"audit_id": audit_id})] == ["t"]


def test_stale_recovery(owner, repo, app, db):
    client, headers, _ = owner
    audit_id = ObjectId(start(client, headers, repo["id"]).get_json()["data"]["id"])
    old = utcnow() - timedelta(minutes=10)
    stuck = {"status": "scanning", "attempts": 1, "worker": {"id": "dead", "heartbeat_at": old}}
    import os
    import socket
    with app.app_context():
        from app.services.workspace import work_root
        leftover = os.path.join(work_root(), "ws-crashed")
    os.makedirs(os.path.join(leftover, "src"))
    db.audits.update_one({"_id": audit_id}, {"$set": {**stuck, "worker": {**stuck["worker"], "workspace": leftover,
                                                                          "host": socket.gethostname()}}})
    with app.app_context():
        assert AuditWorker(app).recover_stale() == {"requeued": 1, "failed": 0, "cancelled": 0}
    assert not os.path.exists(leftover)  # the crashed attempt's workspace is cleaned up
    audit = db.audits.find_one({"_id": audit_id})
    assert audit["status"] == "queued" and audit["worker"] is None and audit["active"] is True
    assert all(s["status"] == "pending" for s in audit["stages"])

    db.audits.update_one({"_id": audit_id}, {"$set": {**stuck, "attempts": 2}})
    with app.app_context():
        assert AuditWorker(app).recover_stale()["failed"] == 1
    audit = db.audits.find_one({"_id": audit_id})
    assert audit["status"] == "failed" and audit["error"]["code"] == "worker_lost" and "active" not in audit

    audit_id2 = ObjectId(start(client, headers, repo["id"]).get_json()["data"]["id"])
    db.audits.update_one({"_id": audit_id2}, {"$set": {**stuck, "cancel_requested": True}})
    with app.app_context():
        assert AuditWorker(app).recover_stale()["cancelled"] == 1

    # A live heartbeat is left alone.
    audit_id3 = ObjectId(start(client, headers, repo["id"]).get_json()["data"]["id"])
    db.audits.update_one({"_id": audit_id3}, {"$set": {**stuck, "worker": {"id": "alive", "heartbeat_at": utcnow()}}})
    with app.app_context():
        assert AuditWorker(app).recover_stale() == {"requeued": 0, "failed": 0, "cancelled": 0}


def test_lost_ownership_stops_writes(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    fake_scan.block = True
    audit_id = ObjectId(start(client, headers, repo["id"]).get_json()["data"]["id"])
    result = {}
    t = in_thread(lambda: result.setdefault("status", AuditWorker(app, worker_id="old").run_once()))
    assert fake_scan.started.wait(10)
    db.audits.update_one({"_id": audit_id}, {"$set": {"worker.id": "new-owner", "status": "detecting"}})
    t.join(10)
    assert result["status"] == "lost"
    audit = db.audits.find_one({"_id": audit_id})
    assert audit["status"] == "detecting" and audit["worker"]["id"] == "new-owner"  # untouched by the old worker


def test_shutdown_requeues_running_audit(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    fake_scan.block = True
    audit_id = ObjectId(start(client, headers, repo["id"]).get_json()["data"]["id"])
    w = AuditWorker(app)
    w.start()
    assert fake_scan.started.wait(10)
    w.stop(timeout=10)
    audit = db.audits.find_one({"_id": audit_id})
    assert audit["status"] == "queued" and audit["attempts"] == 0 and audit["active"] is True


def test_delete_audit(owner, repo, app, db, fake_scan):
    client, headers, _ = owner
    first = start(client, headers, repo["id"]).get_json()["data"]["id"]
    AuditWorker(app).run_once()
    second = start(client, headers, repo["id"]).get_json()["data"]["id"]
    assert client.delete(f"/api/v1/audits/{second}", headers=headers).status_code == 409  # still queued
    AuditWorker(app).run_once()

    repo_doc = db.repositories.find_one({"_id": ObjectId(repo["id"])})
    assert repo_doc["last_audit"]["audit_number"] == 2
    assert client.delete(f"/api/v1/audits/{second}", headers=headers).status_code == 204
    assert db.findings.count_documents({"audit_id": ObjectId(second)}) == 0
    assert db.repositories.find_one({"_id": ObjectId(repo["id"])})["last_audit"]["audit_number"] == 1
    assert client.delete(f"/api/v1/audits/{first}", headers=headers).status_code == 204
    assert db.repositories.find_one({"_id": ObjectId(repo["id"])})["last_audit"] is None
    assert client.get(f"/api/v1/audits/{first}", headers=headers).status_code == 404


def test_embedded_worker_end_to_end_with_real_scanners(owner, app, db):
    """Background threads + REST only: start, poll status, see results on the dashboard."""
    from .test_scanner_engine import HAVE_TOOLS, FakeOSVClient, _zip_project
    if not HAVE_TOOLS:
        pytest.skip("scanners not installed")
    from app.scanners import engine as engine_mod
    orig = engine_mod.OSVClient
    engine_mod.OSVClient = FakeOSVClient
    client, headers, _ = owner
    archive, _secrets = _zip_project()
    repo_id = upload(client, headers, data=archive).get_json()["data"]["id"]
    w = AuditWorker(app, concurrency=2)
    w.start()
    try:
        audit_id = start(client, headers, repo_id).get_json()["data"]["id"]
        seen = set()

        def done():
            st = client.get(f"/api/v1/audits/{audit_id}/status", headers=headers).get_json()["data"]
            seen.add(st["status"])
            return st["is_final"]

        wait_for(done, timeout=120)
    finally:
        w.stop(timeout=10)
        engine_mod.OSVClient = orig
    detail = client.get(f"/api/v1/audits/{audit_id}", headers=headers).get_json()["data"]
    assert detail["status"] == "completed", detail["error"]
    assert detail["summary"]["total_findings"] > 5 and detail["scanner_versions"]["semgrep"]
    assert seen & {"cloning", "scanning", "detecting", "dependency_analysis", "processing", "queued"}
    dash = client.get("/api/v1/dashboard", headers=headers).get_json()["data"]
    assert dash["recent_audits"][0]["id"] == audit_id and dash["security_score"] is not None


def test_osv_phase_is_cancellable():
    """Regression: cancelling during dependency analysis waited for every OSV request (18 s live)."""
    from app.scanners.cancel import Cancelled, CancelToken
    from app.scanners.dependencies.osv import enrich
    from app.scanners.models import Dependency

    token = CancelToken()

    class SlowOSV:
        def query_batch(self, deps, cancel=None):
            return [[f"GHSA-{i}"] for i, _ in enumerate(deps)]

        def vulnerability(self, vid):
            time.sleep(2)
            return {"id": vid, "affected": []}

    deps = [Dependency("npm", f"pkg{i}", "1.0.0", "package-lock.json") for i in range(40)]
    threading.Timer(0.3, token.cancel).start()
    t0 = time.monotonic()
    with pytest.raises(Cancelled):
        enrich(deps, SlowOSV(), token)
    assert time.monotonic() - t0 < 1.5  # 40 × 2 s of requests would take ~10 s with 8 workers


def test_scanner_does_not_outlive_a_killed_worker(tmp_path):
    """The limits wrapper kills its scanner child when the parent (the app) dies, even on SIGKILL."""
    import os
    import signal
    import subprocess
    import sys
    from app.scanners.runner import LIMITS_SCRIPT
    marker = tmp_path / "child.pid"
    # A stand-in "app" process that launches a long-running scanner through the wrapper.
    app_proc = subprocess.Popen([sys.executable, "-c", f"""
import subprocess, sys
subprocess.Popen([sys.executable, "-I", "-S", {LIMITS_SCRIPT!r}, "--cpu", "60", "--",
                  "/bin/sh", "-c", "echo $$ > {marker}; exec sleep 60"])
import time; time.sleep(60)
"""])
    wait_for(lambda: marker.exists() and marker.read_text().strip(), timeout=10)
    scanner_pid = int(marker.read_text())
    os.kill(app_proc.pid, signal.SIGKILL)
    app_proc.wait()

    def gone():
        try:
            os.kill(scanner_pid, 0)
            return False
        except ProcessLookupError:
            return True
    wait_for(gone, timeout=5)
