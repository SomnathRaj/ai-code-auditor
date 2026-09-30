"""Findings API: list/filters/facets, detail, code viewer, lifecycle, comments, isolation."""
import pytest
from bson import ObjectId

from app.db.utils import utcnow

from .conftest import bearer, register
from .test_zip_uploads import upload


def seed(db, org_id, repo_id, audit_id, **kw):
    now = utcnow()
    doc = {"organization_id": org_id, "repository_id": repo_id, "audit_id": audit_id,
           "fingerprint": kw.pop("fingerprint", ObjectId().binary.hex()), "rule_id": "aca-python-sqli-string-built-query",
           "scanner": "semgrep", "title": "SQL query built from strings", "category": "Injection", "severity": "high",
           "confidence": 0.7, "status": "new",
           "location": {"file": "app/views.py", "line_start": 12, "line_end": 12, "function": "user"},
           "code_snippet": "l11\nl12\nl13", "snippet_start_line": 11,
           "code_context": "\n".join(f"line {n}" for n in range(1, 25)), "context_start_line": 1,
           "description": "desc", "impact": None, "recommendation": "Use parameters", "cwe": "CWE-89",
           "owasp": "A03:2021", "references": ["https://example.com/advisory", "javascript:alert(1)"],
           "raw": {}, "ai_analysis": None, "status_history": [], "created_at": now, "updated_at": now}
    doc.update(kw)
    return db.findings.insert_one(doc).inserted_id


@pytest.fixture
def audit(owner, db):
    """A completed audit with a mix of findings."""
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    repo_id = ObjectId(upload(client, headers).get_json()["data"]["id"])
    now = utcnow()
    audit_id = db.audits.insert_one({
        "organization_id": org_id, "repository_id": repo_id, "audit_number": 1, "branch": "upload",
        "audit_type": "full", "status": "completed", "stages": [], "created_at": now, "updated_at": now,
        "started_at": now, "completed_at": now,
        "summary": {"counts": {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0}, "security_score": 56}}).inserted_id
    ai = {"status": "completed", "verdict": "false_positive", "confidence": 0.9, "false_positive_probability": 0.9,
          "explanation": "Constant value", "impact": "None", "recommendation": "No change", "fixed_code": "safe()",
          "evidence_lines": [12], "missing_context": [], "severity": "low", "title": "t", "provider": "gemini",
          "model": "gemini-3.5-flash-lite", "prompt_version": "x", "analyzed_at": now}
    ids = {
        "sqli": seed(db, org_id, repo_id, audit_id, ai_analysis=ai),
        "rce": seed(db, org_id, repo_id, audit_id, severity="critical", rule_id="aca-python-command-injection",
                    title="Command injection risk", location={"file": "app/cmd.py", "line_start": 5, "line_end": 5}),
        "xss": seed(db, org_id, repo_id, audit_id, category="XSS", title="Auto-escaping bypassed",
                    location={"file": "templates/x.py", "line_start": 3, "line_end": 3}),
        "secret": seed(db, org_id, repo_id, audit_id, scanner="gitleaks", category="Secrets", severity="medium",
                       rule_id="aws-access-token", title="Exposed secret: AWS access token",
                       location={"file": ".env", "line_start": 2, "line_end": 2}),
    }
    from app.services.scoring import refresh_repository_snapshot
    with client.application.app_context():
        refresh_repository_snapshot(org_id, repo_id)
    return client, headers, org_id, repo_id, audit_id, ids


def test_list_filters_sort_and_facets(audit):
    client, headers, _, _, audit_id, ids = audit
    base = f"/api/v1/audits/{audit_id}/findings"
    body = client.get(base, headers=headers).get_json()
    assert body["meta"]["total"] == 4
    assert body["data"][0]["severity"] == "critical"  # severity sort
    assert "code_context" not in body["data"][0]
    facets = body["meta"]["facets"]
    assert facets["severity"] == {"critical": 1, "high": 2, "medium": 1}
    assert facets["scanner"] == {"semgrep": 3, "gitleaks": 1}
    assert facets["ai_verdict"] == {"false_positive": 1, "none": 3}

    get = lambda qs: client.get(f"{base}?{qs}", headers=headers).get_json()
    assert get("severity=critical,medium")["meta"]["total"] == 2
    assert get("category=XSS")["data"][0]["id"] == str(ids["xss"])
    assert get("scanner=gitleaks")["data"][0]["title"].startswith("Exposed secret")
    assert get("ai_verdict=false_positive")["data"][0]["ai"]["verdict"] == "false_positive"
    assert get("ai_verdict=none")["meta"]["total"] == 3
    assert get("file=CMD")["data"][0]["id"] == str(ids["rce"])
    assert get("q=command")["meta"]["total"] == 1
    assert get("q=.*")["meta"]["total"] == 0  # regex characters are escaped
    assert get("status=open")["meta"]["total"] == 4 and get("status=closed")["meta"]["total"] == 0
    assert get("sort=file")["data"][0]["file"] == ".env"
    assert get("per_page=2&page=2")["meta"]["total_pages"] == 2
    for bad in ("severity=urgent", "status=done", "sort=random", "scanner=trivy"):
        assert client.get(f"{base}?{bad}", headers=headers).status_code == 400, bad


def test_detail_and_code_view(audit, db):
    client, headers, _, _, _, ids = audit
    f = client.get(f"/api/v1/findings/{ids['sqli']}", headers=headers).get_json()["data"]
    assert f["title"] == "SQL query built from strings" and f["function"] == "user"
    assert f["ai_analysis"]["verdict"] == "false_positive" and f["ai_analysis"]["fixed_code"] == "safe()"
    assert "prompt_version" not in f["ai_analysis"]
    assert {r["label"] for r in f["references"]} == {"CWE-89", "OWASP A03:2021", "https://example.com/advisory"}
    assert f["allowed_transitions"][:2] == ["confirmed", "in_progress"] and f["repository"]["name"] == "myproj-main"
    assert f["audit"]["display_id"] == "AUD-1"

    code = client.get(f"/api/v1/findings/{ids['sqli']}/code", headers=headers).get_json()["data"]
    assert code["available"] and code["language"] == "Python" and len(code["lines"]) == 24
    line12 = next(l for l in code["lines"] if l["number"] == 12)
    assert line12["highlight"] and line12["evidence"] and line12["text"] == "line 12"
    assert code["marker"] == {"line": 12, "message": "SQL query built from strings"} and code["fixed_code"] == "safe()"

    # Findings stored before the code viewer existed fall back to the short snippet.
    db.findings.update_one({"_id": ids["rce"]}, {"$unset": {"code_context": "", "context_start_line": ""}})
    code = client.get(f"/api/v1/findings/{ids['rce']}/code", headers=headers).get_json()["data"]
    assert [l["number"] for l in code["lines"]] == [11, 12, 13]

    for _ in range(3):
        client.get(f"/api/v1/findings/{ids['sqli']}", headers=headers)
    assert db.audit_logs.count_documents({"event": "finding.viewed"}) == 1  # throttled


def test_lifecycle_rules(audit, db):
    client, headers, _, _, _, ids = audit
    path = f"/api/v1/findings/{ids['sqli']}"
    patch = lambda body: client.patch(path, json=body, headers=headers)

    need_reason = patch({"status": "false_positive"})
    assert need_reason.status_code == 400 and need_reason.get_json()["error"]["details"] == {"comment": "required"}
    assert patch({"status": "verified"}).status_code == 409  # new → verified isn't allowed
    assert patch({"status": "bogus"}).status_code == 400

    for status in ("confirmed", "in_progress", "resolved", "verified"):
        r = patch({"status": status})
        assert r.status_code == 200 and r.get_json()["data"]["status"] == status, status
    assert patch({"status": "verified"}).status_code == 409  # same status
    bad = patch({"status": "false_positive", "comment": "x"})
    assert bad.status_code == 409 and bad.get_json()["error"]["details"]["allowed"] == ["new"]
    reopened = patch({"status": "new", "comment": "Came back after refactor"}).get_json()["data"]
    assert reopened["status"] == "new"
    history = reopened["status_history"]
    assert [h["status"] for h in history] == ["confirmed", "in_progress", "resolved", "verified", "new"]
    assert history[-1]["from"] == "verified" and history[-1]["user"] == "Ann"
    assert db.audit_logs.count_documents({"event": "finding.status_changed"}) == 5


def test_triage_updates_scores(audit, db):
    client, headers, _, repo_id, audit_id, ids = audit
    before = client.get("/api/v1/dashboard", headers=headers).get_json()["data"]
    r = client.patch(f"/api/v1/findings/{ids['rce']}", json={"status": "accepted_risk", "comment": "Internal tool only"},
                     headers=headers)
    assert r.status_code == 200
    summary = db.audits.find_one({"_id": audit_id})["summary"]
    assert summary["counts"]["critical"] == 0 and summary["security_score"] > 56
    after = client.get("/api/v1/dashboard", headers=headers).get_json()["data"]
    assert after["counts"]["critical"] == before["counts"]["critical"] - 1
    assert after["security_score"] == before["security_score"] + 20
    comments = client.get(f"/api/v1/findings/{ids['rce']}/comments", headers=headers).get_json()["data"]
    assert comments[0]["kind"] == "status_change" and comments[0]["status"] == "accepted_risk"


def test_comments(audit, db):
    client, headers, org_id, repo_id, _, ids = audit
    path = f"/api/v1/findings/{ids['xss']}/comments"
    assert client.post(path, json={"body": "  "}, headers=headers).status_code == 400
    assert client.post(path, json={"body": "x" * 5001}, headers=headers).status_code == 400
    created = client.post(path, json={"body": "<script>alert(1)</script> check this"}, headers=headers)
    assert created.status_code == 201 and created.get_json()["data"]["user"] == "Ann"
    # A comment on the same issue in an earlier audit shows up too.
    fp = db.findings.find_one({"_id": ids["xss"]})["fingerprint"]
    db.finding_comments.insert_one({"organization_id": org_id, "finding_id": ObjectId(), "repository_id": repo_id,
                                    "fingerprint": fp, "user_id": ObjectId(), "body": "old note", "kind": "comment",
                                    "created_at": utcnow()})
    items = client.get(path, headers=headers).get_json()["data"]
    assert [c["body"] for c in items] == ["<script>alert(1)</script> check this", "old note"]
    assert [c["earlier_audit"] for c in items] == [False, True]


def test_roles_and_isolation(audit, db, app):
    client, headers, org_id, _, audit_id, ids = audit
    viewer = app.test_client()
    v = register(viewer, email="viewer@example.com", name="Viewer").get_json()["data"]
    db.organizations.update_one({"_id": org_id}, {"$push": {"members": {
        "user_id": ObjectId(v["user"]["id"]), "role": "viewer", "joined_at": utcnow()}}})
    vh = bearer(viewer.post("/api/v1/auth/switch-organization", json={"organization_id": str(org_id)},
                            headers={"Authorization": f"Bearer {v['access_token']}"}))
    assert viewer.get(f"/api/v1/findings/{ids['sqli']}", headers=vh).status_code == 200
    assert viewer.patch(f"/api/v1/findings/{ids['sqli']}", json={"status": "confirmed"}, headers=vh).status_code == 403
    assert viewer.post(f"/api/v1/findings/{ids['sqli']}/comments", json={"body": "hi"}, headers=vh).status_code == 403

    other = app.test_client()
    oh = bearer(register(other, email="bob@example.com", name="Bob"))
    for method, path, body in (("get", f"/api/v1/findings/{ids['sqli']}", None),
                               ("get", f"/api/v1/findings/{ids['sqli']}/code", None),
                               ("get", f"/api/v1/findings/{ids['sqli']}/comments", None),
                               ("patch", f"/api/v1/findings/{ids['sqli']}", {"status": "confirmed"}),
                               ("post", f"/api/v1/findings/{ids['sqli']}/comments", {"body": "x"}),
                               ("get", f"/api/v1/audits/{audit_id}/findings", None)):
        kwargs = {"json": body} if body else {}
        assert getattr(other, method)(path, headers=oh, **kwargs).status_code == 404, path
    assert other.get("/api/v1/findings/nope", headers=oh).status_code == 404


def test_concurrent_status_change_is_rejected(audit, db, app):
    client, headers, _, _, _, ids = audit
    from app.services import finding_service
    with app.app_context():
        f = finding_service.get_finding(db.findings.find_one({"_id": ids["sqli"]})["organization_id"], ids["sqli"])
        db.findings.update_one({"_id": ids["sqli"]}, {"$set": {"status": "confirmed"}})  # someone else changed it
        orig = finding_service.get_finding
        finding_service.get_finding = lambda *_a: f  # stale read
        try:
            with pytest.raises(Exception) as exc:
                finding_service.change_status(f["organization_id"], ObjectId(), ids["sqli"], "resolved", None)
        finally:
            finding_service.get_finding = orig
    assert "changed by someone else" in str(exc.value)
