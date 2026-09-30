"""Scanner engine with the real tools (Semgrep, Gitleaks). OSV is faked (no network)."""
import json
import os
import secrets
import string
import subprocess
import sys

import pytest
from bson import ObjectId

from app.scanners import engine as engine_mod
from app.scanners.engine import ScanConfig, run_scan
from app.scanners.runner import RunnerConfig, ScannerError, find_tool, run_tool

from .conftest import bearer, register, run_audit
from .test_zip_uploads import make_zip, upload

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = RunnerConfig(bin_dirs=[os.path.join(ROOT, ".tools", "bin"), os.path.join(sys.prefix, "bin")],
                     cpu_seconds=600, memory_mb=4096, max_output_mb=256, scanner_user=None)
HAVE_TOOLS = bool(find_tool("semgrep", TOOLS) and find_tool("gitleaks", TOOLS))
pytestmark = pytest.mark.skipif(not HAVE_TOOLS, reason="run scripts/install-scanners.sh")

RULE_TESTS = [("python.yml", "python.py"), ("javascript.yml", "javascript.js"), ("javascript.yml", "react.jsx"),
              ("php.yml", "php.php"), ("java.yml", "java.java"), ("go.yml", "go.go")]


def _rand(n, alphabet=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alphabet) for _ in range(n))


@pytest.mark.parametrize("rules,target", RULE_TESTS)
def test_semgrep_rule_suites(rules, target):
    out = subprocess.run(
        [find_tool("semgrep", TOOLS), "--test", "--metrics=off", "--disable-version-check",
         "--config", os.path.join(ROOT, "app/scanners/rules", rules), os.path.join(ROOT, "tests/semgrep_rules", target)],
        capture_output=True, text=True, timeout=600, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
    assert "All tests passed" in out.stdout + out.stderr, out.stdout[-3000:] + out.stderr[-2000:]


class FakeOSVClient:
    """Replaces OSV: requests 2.25.0 is vulnerable, everything else clean."""

    def __init__(self, *args, **kwargs):
        pass

    def query_batch(self, deps, cancel=None):
        return [["GHSA-fake-0001"] if (d.name, d.version) == ("requests", "2.25.0") else [] for d in deps]

    def vulnerability(self, vid):
        return {"id": vid, "aliases": ["CVE-2099-0001"], "summary": "Credentials leak in requests",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}],
                "references": [{"url": "https://example.com/advisory"}]}


@pytest.fixture(autouse=True)
def fake_osv(monkeypatch):
    monkeypatch.setattr(engine_mod, "OSVClient", FakeOSVClient)


def project_files():
    aws_key = "AKIA" + _rand(16, string.ascii_uppercase + "234567")
    gh_token = "ghp_" + _rand(36)
    files = {
        "app/views.py": (
            "from flask import Flask, request\nimport sqlite3, os\napp = Flask(__name__)\n\n"
            "@app.route('/u')\ndef u():\n    db = sqlite3.connect('x.db')\n"
            "    return str(db.execute(f\"SELECT * FROM users WHERE id = {request.args['id']}\").fetchall())\n\n"
            "def cmd(host):\n    os.system('ping ' + host)  # nosemgrep\n"),
        "app/settings.py": "DEBUG = True\nSESSION_COOKIE_SECURE = False\n",
        "app/config.py": f'GITHUB_TOKEN = "{gh_token}"\n',
        "resources/views/profile.blade.php": "<div>{!! $user->bio !!}</div>\n<p>{{ $user->name }}</p>\n",
        "routes/web.php": "<?php\n$id = $_GET['id'];\nmysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $id);\n",
        ".env": f"APP_DEBUG=true\nAWS_ACCESS_KEY_ID={aws_key}\n",
        ".env.example": "APP_DEBUG=true\nAWS_ACCESS_KEY_ID=\n",
        "requirements.txt": "flask==3.0.0\nrequests==2.25.0\njinja2>=3\n",
        "node_modules/evil/index.js": "require('child_process').exec(process.argv[2]);\n",
        ".semgrepignore": "app/\n",
        ".gitleaksignore": "app/config.py:github-pat:1\n.env:aws-access-token:2\n",
    }
    return files, {"aws": aws_key, "github": gh_token}


def test_engine_end_to_end(app, tmp_path):
    files, secrets_ = project_files()
    src = tmp_path / "src"
    for rel, content in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(content)
    settings = {"enabled_scanners": ["semgrep", "gitleaks", "dependencies"], "excluded_paths": ["node_modules/"],
                "severity_threshold": "low"}
    with app.app_context():
        result = run_scan(str(src), str(tmp_path), settings, ScanConfig.from_app(app))

    assert result.errors == []
    assert result.removed_control_files == [".gitleaksignore", ".semgrepignore"]
    assert result.project.primary_language == "Python" and result.project.frameworks == ["Flask"]
    assert {"semgrep", "gitleaks", "rules", "osv"} <= set(result.scanner_versions)

    got = {(f.rule_id, f.file) for f in result.findings}
    expected = {
        ("aca-python-sqli-string-built-query", "app/views.py"),
        ("aca-python-command-injection", "app/views.py"),       # `# nosemgrep` is ignored
        ("aca-python-django-debug-enabled", "app/settings.py"),
        ("aca-config-insecure-session-cookie", "app/settings.py"),
        ("aca-php-blade-unescaped-output", "resources/views/profile.blade.php"),
        ("aca-php-sqli-string-built-query", "routes/web.php"),
        ("aca-config-debug-enabled", ".env"),
        ("aws-access-token", ".env"),                            # .gitleaksignore was removed
        ("github-pat", "app/config.py"),
        ("GHSA-fake-0001", "requirements.txt"),
    }
    assert expected <= got, expected - got
    assert not any(f.file.startswith("node_modules/") for f in result.findings)
    assert ("aca-config-debug-enabled", ".env.example") not in got
    # Semgrep's hard-coded credential on the same line as Gitleaks' finding is deduplicated.
    assert ("aca-python-hardcoded-credential", "app/config.py") not in got

    blob = json.dumps([f.to_dict() for f in result.findings])
    for value in secrets_.values():
        assert value not in blob
    aws = next(f for f in result.findings if f.rule_id == "aws-access-token")
    assert aws.severity == "critical" and "AWS_ACCESS_KEY_ID=****" in aws.code_snippet

    dep = next(f for f in result.findings if f.scanner == "osv")
    assert dep.severity == "high" and dep.extra["recommended_version"] == "2.31.0" and dep.line_start == 2
    assert {d.name: d.declared for d in result.dependencies}["jinja2"] == ">=3"

    sqli = next(f for f in result.findings if f.rule_id == "aca-python-sqli-string-built-query")
    assert sqli.cwe == "CWE-89" and sqli.owasp == "A03:2021" and "SELECT" in sqli.code_snippet


def test_severity_threshold_and_disabled_scanners(app, tmp_path):
    files, _ = project_files()
    src = tmp_path / "src"
    for rel, content in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(content)
    with app.app_context():
        result = run_scan(str(src), str(tmp_path), {"enabled_scanners": ["semgrep"], "excluded_paths": [],
                                                   "severity_threshold": "high"}, ScanConfig.from_app(app))
    assert result.findings and all(f.severity in ("high", "critical") for f in result.findings)
    assert {f.scanner for f in result.findings} == {"semgrep"}
    assert "node_modules/evil/index.js" in {f.file for f in result.findings}  # not excluded this time


def test_runner_isolation(app, tmp_path, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "super-secret-jwt")
    monkeypatch.setenv("MONGODB_URI", "mongodb://root:pw@db")
    res = run_tool("env", ["/usr/bin/env"], cwd=str(tmp_path), work_dir=str(tmp_path), timeout=30, cfg=TOOLS)
    env = open(res.stdout_path).read()
    assert "super-secret-jwt" not in env and "MONGODB_URI" not in env and "ENCRYPTION_KEYS" not in env
    assert f"HOME={tmp_path}/home-env" in env

    with pytest.raises(ScannerError, match="timed out"):
        run_tool("sleeper", ["/bin/sh", "-c", "sleep 30 & sleep 30"], cwd=str(tmp_path), work_dir=str(tmp_path),
                 timeout=1, cfg=TOOLS)
    cpu_limited = RunnerConfig(**{**TOOLS.__dict__, "cpu_seconds": 1})
    with pytest.raises(ScannerError, match="killed by signal"):
        run_tool("spin", [sys.executable, "-c", "while True: pass"], cwd=str(tmp_path), work_dir=str(tmp_path),
                 timeout=30, cfg=cpu_limited)


def test_missing_tool_is_reported_not_fatal(app, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("eval(x)\n")
    cfg = ScanConfig.from_app(app)
    cfg.runner = RunnerConfig(**{**cfg.runner.__dict__, "bin_dirs": [str(tmp_path / "nothing")]})
    import shutil
    orig_which = shutil.which
    with app.app_context():
        shutil.which = lambda name: None
        try:
            result = run_scan(str(tmp_path / "src"), str(tmp_path), {}, cfg)
        finally:
            shutil.which = orig_which
    assert {e["scanner"] for e in result.errors} == {"semgrep", "gitleaks"}
    assert all("not installed" in e["message"] for e in result.errors)


# ---- persistence, API and CLI ----

def _zip_project():
    files, secrets_ = project_files()
    return make_zip({f"proj/{k}": v for k, v in files.items()}), secrets_


def test_audit_persisted_and_triage_remembered(owner, db, app):
    client, headers, data = owner
    archive, secrets_ = _zip_project()
    repo_id = upload(client, headers, data=archive).get_json()["data"]["id"]
    repo = db.repositories.find_one({"_id": ObjectId(repo_id)})

    audit = run_audit(app, repo)
    assert audit["status"] == "completed", audit.get("error")
    assert audit["audit_number"] == 1 and audit["scanner_versions"]["gitleaks"]
    s = audit["summary"]
    assert s["primary_language"] == "Python" and s["dependency_count"] == 3 and s["vulnerable_dependency_count"] == 1
    assert s["removed_control_files"] == [".gitleaksignore", ".semgrepignore"]

    stored = list(db.findings.find({"audit_id": audit["_id"]}))
    assert len(stored) == s["total_findings"] > 5
    assert all(len(f["fingerprint"]) == 64 and f["status"] == "new" for f in stored)
    blob = json.dumps([{k: v for k, v in f.items() if k not in ("_id", "organization_id", "repository_id", "audit_id",
                                                                "created_at", "updated_at")} for f in stored])
    for value in secrets_.values():
        assert value not in blob

    updated = db.repositories.find_one({"_id": ObjectId(repo_id)})
    assert updated["language"] == "Python" and updated["framework"] == "Flask"
    assert updated["last_audit"]["security_score"] == s["security_score"]

    # Mark one finding as a false positive; the next audit remembers it.
    fp = next(f for f in stored if f["rule_id"] == "aca-python-django-debug-enabled")
    db.findings.update_one({"_id": fp["_id"]}, {"$set": {"status": "false_positive"},
                                                "$push": {"status_history": {"status": "false_positive"}}})
    audit2 = run_audit(app, db.repositories.find_one({"_id": ObjectId(repo_id)}))
    assert audit2["audit_number"] == 2 and audit2["summary"]["carried_over"] == 1
    again = db.findings.find_one({"audit_id": audit2["_id"], "fingerprint": fp["fingerprint"]})
    assert again["status"] == "false_positive"
    assert audit2["summary"]["counts"]["medium"] == s["counts"]["medium"] - 1

    dash = client.get("/api/v1/dashboard", headers=headers).get_json()["data"]
    assert dash["security_score"] == audit2["summary"]["security_score"]
    assert [a["display_id"] for a in dash["recent_audits"]] == ["AUD-2", "AUD-1"]


def test_dependencies_endpoint(owner, db, app):
    client, headers, _ = owner
    archive, _ = _zip_project()
    repo_id = upload(client, headers, data=archive).get_json()["data"]["id"]
    path = f"/api/v1/repositories/{repo_id}/dependencies"

    before = client.get(path, headers=headers).get_json()
    assert before["data"] == [] and before["meta"]["audit_id"] is None

    run_audit(app, db.repositories.find_one({"_id": ObjectId(repo_id)}))
    body = client.get(path, headers=headers).get_json()
    assert body["meta"]["total"] == 3 and body["meta"]["display_id"] == "AUD-1"
    first = body["data"][0]
    assert first["package_name"] == "requests" and first["vulnerable"] and first["max_severity"] == "high"
    assert first["recommended_version"] == "2.31.0" and first["vulnerabilities"][0]["id"] == "GHSA-fake-0001"
    assert client.get(f"{path}?vulnerable=true", headers=headers).get_json()["meta"]["total"] == 1
    assert client.get(f"{path}?q=JIN", headers=headers).get_json()["data"][0]["declared"] == ">=3"
    assert client.get(f"{path}?ecosystem=npm", headers=headers).get_json()["meta"]["total"] == 0
    assert client.get(f"{path}?vulnerable=maybe", headers=headers).status_code == 400

    other = app.test_client()
    assert other.get(path, headers=bearer(register(other, email="bob@example.com", name="Bob"))).status_code == 404


def test_cli_scan(owner, db, app):
    client, headers, _ = owner
    archive, _ = _zip_project()
    repo_id = upload(client, headers, data=archive).get_json()["data"]["id"]
    runner = app.test_cli_runner()
    out = runner.invoke(args=["scan", repo_id])
    assert out.exit_code == 0, out.output
    assert "AUD-1 completed" in out.output and "✓ Detect project  (Flask / Python)" in out.output
    assert runner.invoke(args=["scan", "nope"]).exit_code != 0


def test_failed_audit_recorded(owner, db, app):
    client, headers, _ = owner
    repo_id = upload(client, headers).get_json()["data"]["id"]
    db.repositories.update_one({"_id": ObjectId(repo_id)}, {"$set": {"source.sha256": "0" * 64}})  # tampered
    audit = run_audit(app, db.repositories.find_one({"_id": ObjectId(repo_id)}))
    assert audit["status"] == "failed" and audit["error"]["code"] == "unsafe_archive"
    assert db.audit_logs.count_documents({"event": "audit.failed"}) == 1
