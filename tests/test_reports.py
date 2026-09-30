"""Reports (JSON/HTML/PDF/CSV, technical/executive), audit comparison, dashboard trends."""
import csv
import io
from datetime import timedelta

import pytest
from bson import ObjectId

from app.db.utils import utcnow

from .conftest import bearer, register
from .test_zip_uploads import upload

EVIL = '<script>alert("x")</script>'


def make_audit(db, org_id, repo_id, number, when=None, status="completed"):
    when = when or utcnow()
    return db.audits.insert_one({
        "organization_id": org_id, "repository_id": repo_id, "audit_number": number, "branch": "upload",
        "audit_type": "full", "status": status, "stages": [], "created_at": when, "updated_at": when,
        "started_at": when, "completed_at": when, "commit_hash": "abcdef1234567890",
        "summary": {"counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "security_score": 100,
                    "frameworks": ["Flask"], "primary_language": "Python", "dependency_count": 3,
                    "vulnerable_dependency_count": 1},
        "scanner_versions": {"semgrep": "1.178.0"}, "settings": {"enabled_scanners": ["semgrep"]}}).inserted_id


def add_finding(db, org_id, repo_id, audit_id, fp, line=10, text="db.execute(q)", **kw):
    now = utcnow()
    doc = {"organization_id": org_id, "repository_id": repo_id, "audit_id": audit_id, "fingerprint": fp,
           "rule_id": kw.pop("rule_id", "aca-python-sqli"), "scanner": "semgrep", "title": "SQL query built from strings",
           "category": "Injection", "severity": "high", "confidence": 0.7, "status": "new",
           "location": {"file": "app.py", "line_start": line, "line_end": line, "function": "f"},
           "code_snippet": f"a\n{text}\nb", "snippet_start_line": line - 1, "description": "d",
           "recommendation": "Use parameters", "cwe": "CWE-89", "owasp": "A03:2021", "references": [],
           "raw": {}, "ai_analysis": None, "status_history": [], "created_at": now, "updated_at": now}
    doc.update(kw)
    return db.findings.insert_one(doc).inserted_id


def recount(app, db, org_id, repo_id, audit_id):
    from app.services.finding_service import _recount_audit
    with app.app_context():
        _recount_audit(audit_id, org_id)


@pytest.fixture
def ctx(owner, db, app):
    client, headers, data = owner
    org_id = ObjectId(data["organization"]["id"])
    repo_id = ObjectId(upload(client, headers).get_json()["data"]["id"])
    a1 = make_audit(db, org_id, repo_id, 1, when=utcnow() - timedelta(days=2))
    add_finding(db, org_id, repo_id, a1, "fp-sqli")
    add_finding(db, org_id, repo_id, a1, "fp-moved", line=20, text="os.system(cmd)", rule_id="aca-python-cmd",
                title="Command injection risk", severity="critical")
    add_finding(db, org_id, repo_id, a1, "fp-fixed", line=30, text="yaml.load(x)", rule_id="aca-python-yaml")
    add_finding(db, org_id, repo_id, a1, "fp-reopen", line=40, text="md5(p)", rule_id="aca-python-md5",
                severity="medium", status="resolved")
    add_finding(db, org_id, repo_id, a1, "fp-dismissed", line=50, text="eval(s)", rule_id="aca-python-eval",
                status="false_positive")
    recount(app, db, org_id, repo_id, a1)

    a2 = make_audit(db, org_id, repo_id, 2)
    add_finding(db, org_id, repo_id, a2, "fp-sqli")                                   # unchanged
    add_finding(db, org_id, repo_id, a2, "fp-moved-new-line", line=23, text="os.system(cmd)",
                rule_id="aca-python-cmd", title="Command injection risk", severity="critical")  # moved → unchanged
    add_finding(db, org_id, repo_id, a2, "fp-reopen", line=40, text="md5(p)", rule_id="aca-python-md5",
                severity="medium")                                                    # was resolved → reopened
    add_finding(db, org_id, repo_id, a2, "fp-new", line=60, text=f"print('{EVIL}')", rule_id="aca-python-xss",
                title=f"XSS {EVIL}", category="XSS", severity="low",
                ai_analysis={"status": "completed", "verdict": "true_positive", "confidence": 0.9,
                             "false_positive_probability": 0.1, "explanation": f"because {EVIL}", "model": "gemini-x",
                             "fixed_code": "print(escape(v))"})
    add_finding(db, org_id, repo_id, a2, "fp-formula", line=70, title="=HYPERLINK(\"http://evil\")", severity="low",
                rule_id="aca-python-formula")
    db.dependencies.insert_one({"organization_id": org_id, "repository_id": repo_id, "audit_id": a2,
                                "package_name": "requests", "version": "2.25.0", "ecosystem": "PyPI",
                                "manifest": "requirements.txt", "vulnerable": True, "max_severity": "high",
                                "recommended_version": "2.32.4", "vulnerabilities": [{"id": "GHSA-1"}]})
    recount(app, db, org_id, repo_id, a2)
    return client, headers, org_id, repo_id, a1, a2


def test_comparison(ctx):
    client, headers, _, _, a1, a2 = ctx
    body = client.get(f"/api/v1/audits/{a2}/comparison", headers=headers).get_json()["data"]
    assert body["base"]["display_id"] == "AUD-1" and body["target"]["display_id"] == "AUD-2"
    assert body["counts"] == {"new": 2, "resolved": 1, "unchanged": 2, "reopened": 1, "dismissed_no_longer_reported": 1}
    assert [f["title"] for f in body["resolved"]] == ["SQL query built from strings"]  # the yaml one (same title)
    assert body["reopened"][0]["previous_status"] == "resolved"
    assert {f["file"] + ":" + str(f["line_start"]) for f in body["unchanged"]} == {"app.py:10", "app.py:23"}
    assert body["new_by_severity"]["low"] == 2
    explicit = client.get(f"/api/v1/audits/{a2}/comparison?base={a1}", headers=headers).get_json()["data"]
    assert explicit["counts"] == body["counts"]
    assert client.get(f"/api/v1/audits/{a1}/comparison", headers=headers).status_code == 404  # nothing earlier
    assert client.get(f"/api/v1/audits/{a2}/comparison?base={a2}", headers=headers).status_code == 400


def test_json_reports(ctx):
    client, headers, _, _, _, a2 = ctx
    tech = client.get(f"/api/v1/audits/{a2}/report", headers=headers).get_json()["data"]
    assert tech["report"]["type"] == "technical" and len(tech["findings"]) == 5
    assert tech["findings"][0]["severity"] == "critical"
    assert tech["summary"]["open_counts"] == {"critical": 1, "high": 1, "medium": 1, "low": 2, "info": 0}
    assert tech["vulnerable_dependencies"][0]["package"] == "requests"
    assert any("not proof" in n for n in tech["notes"])
    filtered = client.get(f"/api/v1/audits/{a2}/report?severity=low", headers=headers).get_json()["data"]
    assert {f["severity"] for f in filtered["findings"]} == {"low"} and filtered["filters"] == {"severity": "low"}

    exe = client.get(f"/api/v1/audits/{a2}/report?type=executive", headers=headers).get_json()["data"]
    assert "findings" not in exe
    assert [r["severity"] for r in exe["top_risks"]] == ["critical", "high"]
    assert exe["recommendations"][0]["severity"] == "critical" and exe["recommendations"][0]["count"] == 1
    assert [t["audit"] for t in exe["trend"]] == ["AUD-1", "AUD-2"]
    assert exe["change_since_previous"]["reopened"] == 1 and exe["previous_audit"] == "AUD-1"


def test_html_report_escapes_everything(ctx):
    client, headers, _, _, _, a2 = ctx
    for kind in ("technical", "executive"):
        r = client.get(f"/api/v1/audits/{a2}/report?format=html&type={kind}", headers=headers)
        assert r.status_code == 200 and r.mimetype == "text/html"
        assert r.headers["Content-Disposition"].startswith('attachment; filename="AUD-2-myproj-main-')
        html = r.get_data(as_text=True)
        assert "<script" not in html.lower()  # no executable markup in either report
        assert "default-src 'none'" in html
    tech = client.get(f"/api/v1/audits/{a2}/report?format=html", headers=headers).get_data(as_text=True)
    assert "print(escape(v))" in tech and "Vulnerable dependencies" in tech
    assert "XSS &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in tech  # title, escaped
    assert "because &lt;script&gt;" in tech  # AI explanation, escaped


def test_pdf_report(ctx):
    client, headers, _, _, _, a2 = ctx
    for kind in ("technical", "executive"):
        r = client.get(f"/api/v1/audits/{a2}/report?format=pdf&type={kind}", headers=headers)
        assert r.status_code == 200 and r.mimetype == "application/pdf"
        assert r.data.startswith(b"%PDF") and len(r.data) > 2000
        assert r.headers["Content-Disposition"].endswith(f'-{kind}.pdf"')


def test_csv_report_neutralises_formulas(ctx):
    client, headers, _, _, _, a2 = ctx
    r = client.get(f"/api/v1/audits/{a2}/report?format=csv", headers=headers)
    assert r.status_code == 200 and r.mimetype == "text/csv"
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True).lstrip("﻿"))))
    assert len(rows) == 5 and rows[0]["severity"] == "critical"
    formula = next(row for row in rows if "HYPERLINK" in row["title"])
    assert formula["title"].startswith("'=")
    assert client.get(f"/api/v1/audits/{a2}/report?format=csv&type=executive", headers=headers).status_code == 400


def test_report_validation_and_isolation(ctx, db, app):
    client, headers, org_id, repo_id, _, a2 = ctx
    for qs in ("format=docx", "type=summary", "severity=urgent"):
        assert client.get(f"/api/v1/audits/{a2}/report?{qs}", headers=headers).status_code == 400, qs
    running = make_audit(db, org_id, repo_id, 3, status="scanning")
    assert client.get(f"/api/v1/audits/{running}/report", headers=headers).status_code == 409
    other = app.test_client()
    oh = bearer(register(other, email="bob@example.com", name="Bob"))
    for path in (f"/api/v1/audits/{a2}/report?format=pdf", f"/api/v1/audits/{a2}/comparison"):
        assert other.get(path, headers=oh).status_code == 404
    client.get(f"/api/v1/audits/{a2}/report?format=pdf", headers=headers)
    assert db.audit_logs.count_documents({"event": "report.downloaded", "details.format": "pdf"}) == 1


def test_trends(ctx, db, app):
    client, headers, org_id, repo_id, a1, a2 = ctx
    from app.services.scoring import refresh_repository_snapshot
    with app.app_context():
        refresh_repository_snapshot(org_id, repo_id)
    # A triage decision this month.
    fid = db.findings.find_one({"audit_id": a2, "fingerprint": "fp-sqli"})["_id"]
    client.patch(f"/api/v1/findings/{fid}", json={"status": "resolved"}, headers=headers)

    t = client.get("/api/v1/dashboard/trends?days=30", headers=headers).get_json()["data"]
    assert [p["display_id"] for p in t["points"]] == ["AUD-1", "AUD-2"]
    assert t["points"][0]["open_findings"] == 3 and t["points"][1]["counts"]["critical"] == 1
    rtm = t["resolved_this_month"]
    assert rtm["triaged"] == 1 and rtm["fixed_in_code"] == 1 and rtm["total"] == 2
    # fp-reopen is still open in AUD-2 and was already reported in AUD-1 (fp-sqli is resolved now).
    assert [(r["title"], r["audits"]) for r in t["recurring"]] == [("SQL query built from strings", 2)]
    assert t["recurring"][0]["line_start"] == 40
    assert client.get("/api/v1/dashboard/trends?days=12", headers=headers).status_code == 400


def test_executive_groups_dependency_advisories(ctx, db):
    client, headers, org_id, repo_id, _, a2 = ctx
    for n, vid in enumerate(("GHSA-a", "GHSA-b", "GHSA-c")):
        add_finding(db, org_id, repo_id, a2, f"dep-{n}", line=2, scanner="osv", rule_id=vid, category="Dependencies",
                    title=f"Vulnerable dependency: requests 2.25.0 ({vid})", severity="medium",
                    location={"file": "requirements.txt", "line_start": 2, "line_end": 2},
                    raw={"package": "requests", "ecosystem": "PyPI", "current_version": "2.25.0",
                         "recommended_version": "2.32.4"})
    exe = client.get(f"/api/v1/audits/{a2}/report?type=executive", headers=headers).get_json()["data"]
    deps = [r for r in exe["recommendations"] if r["category"] == "Dependencies"]
    assert len(deps) == 1 and deps[0]["title"] == "Upgrade requests 2.25.0 to 2.32.4" and deps[0]["count"] == 3
    assert deps[0]["recommendation"].startswith("Fixes 3 known advisories")
