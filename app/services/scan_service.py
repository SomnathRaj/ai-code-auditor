"""Persisting scanner results: findings (with fingerprints and remembered triage),
dependencies, audit summary. Called by the audit worker (app/worker.py).
"""
import hashlib
import re
from datetime import timedelta

from bson import ObjectId
from flask import current_app

from ..db import get_db
from ..db.utils import id_str, utcnow
from ..scanners.engine import ScanConfig
from ..scanners.models import SEVERITY_ORDER, Dependency, Finding, ScanResult
from .audit_log import log_event
from .scoring import empty_counts, refresh_repository_snapshot, security_score

# Triage decisions remembered across audits (PRD §31).
REMEMBERED_STATUSES = ("false_positive", "accepted_risk", "ignored")


def fingerprint(repo_id: ObjectId, f: Finding) -> str:
    """SHA-256(repository + file + line + rule + normalized message) — PRD §42."""
    message = re.sub(r"\s+", " ", (f.message or "").strip().lower())
    raw = "\x1f".join([str(repo_id), f.file or "", str(f.line_start or ""), f.rule_id, message])
    return hashlib.sha256(raw.encode()).hexdigest()


# ---- OSV cache ----

def osv_cache():
    col = get_db().vuln_cache
    max_age = timedelta(hours=current_app.config["OSV_CACHE_HOURS"])

    def get(vuln_id: str):
        doc = col.find_one({"_id": vuln_id})
        if doc and utcnow() - doc["fetched_at"] < max_age:
            return doc["data"]
        return None

    def put(vuln_id: str, data: dict):
        col.replace_one({"_id": vuln_id}, {"_id": vuln_id, "data": data, "fetched_at": utcnow()}, upsert=True)

    return get, put


# ---- AI ----

def ai_config(org_id: ObjectId):
    """AIConfig for this organization, or None when no provider is configured."""
    from ..ai.analyzer import AIConfig
    from ..ai.providers import provider_from_config

    cfg = current_app.config
    provider = provider_from_config(cfg)
    if provider is None:
        return None
    col = get_db().ai_cache
    max_age = timedelta(days=cfg["AI_CACHE_DAYS"])

    def get(key: str):
        doc = col.find_one({"_id": key, "organization_id": org_id})
        return doc["analysis"] if doc and utcnow() - doc["created_at"] < max_age else None

    def put(key: str, analysis: dict):
        col.replace_one({"_id": key}, {"_id": key, "organization_id": org_id, "analysis": analysis,
                                       "created_at": utcnow()}, upsert=True)

    return AIConfig(provider=provider, scope=str(org_id), min_severity=cfg["AI_MIN_SEVERITY"],
                    max_findings=cfg["AI_MAX_FINDINGS"], concurrency=cfg["AI_CONCURRENCY"],
                    max_retries=cfg["AI_MAX_RETRIES"], context_max_lines=cfg["AI_CONTEXT_MAX_LINES"],
                    requests_per_minute=cfg["AI_REQUESTS_PER_MINUTE"],
                    cache_get=get, cache_put=put)


def scan_config() -> ScanConfig:
    get, put = osv_cache()
    return ScanConfig.from_app(current_app, osv_cache_get=get, osv_cache_put=put)


# ---- results ----

def clear_partial_results(audit: dict) -> None:
    """Remove findings/dependencies left by an earlier, interrupted attempt of this audit."""
    db = get_db()
    scope = {"organization_id": audit["organization_id"], "audit_id": audit["_id"]}
    db.findings.delete_many(scope)
    db.dependencies.delete_many(scope)


def _finding_doc(audit: dict, f: Finding, now) -> dict:
    return {
        "organization_id": audit["organization_id"],
        "repository_id": audit["repository_id"],
        "audit_id": audit["_id"],
        "fingerprint": fingerprint(audit["repository_id"], f),
        "rule_id": f.rule_id,
        "scanner": f.scanner,
        "title": f.title,
        "category": f.category,
        "severity": f.severity,
        "confidence": float(f.confidence),
        "status": "new",
        "location": {"file": f.file, "line_start": f.line_start, "line_end": f.line_end, "function": f.function},
        "code_snippet": f.code_snippet,
        "snippet_start_line": f.snippet_start_line,
        "code_context": f.code_context,
        "context_start_line": f.context_start_line,
        "description": f.description or f.message,
        "impact": (f.ai or {}).get("impact") if (f.ai or {}).get("status") == "completed" else None,
        "recommendation": f.recommendation,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "references": f.references,
        "raw": f.extra,
        "ai_analysis": {**f.ai, "analyzed_at": now} if f.ai else None,
        "status_history": [],
        "created_at": now,
        "updated_at": now,
    }


def _carry_over(docs: list[dict], repo_id: ObjectId, org_id: ObjectId) -> int:
    """Re-apply false-positive / accepted-risk / ignored decisions from earlier audits."""
    if not docs:
        return 0
    previous = {}
    cursor = get_db().findings.find(
        {"organization_id": org_id, "repository_id": repo_id,
         "fingerprint": {"$in": [d["fingerprint"] for d in docs]}, "status": {"$in": list(REMEMBERED_STATUSES)}},
        {"fingerprint": 1, "status": 1, "status_history": 1, "audit_id": 1},
    ).sort("created_at", 1)
    for prev in cursor:
        previous[prev["fingerprint"]] = prev  # latest decision wins
    carried = 0
    for doc in docs:
        prev = previous.get(doc["fingerprint"])
        if prev:
            doc["status"] = prev["status"]
            doc["status_history"] = list(prev.get("status_history") or []) + [{
                "status": prev["status"], "user_id": None, "at": doc["created_at"],
                "comment": f"Carried over from an earlier audit ({prev['audit_id']})"}]
            carried += 1
    return carried


def _dependency_doc(audit: dict, d: Dependency) -> dict:
    vulns = [
        {"id": v.id, "aliases": v.aliases, "summary": v.summary, "severity": v.severity, "cvss_score": v.cvss_score,
         "affected_range": v.affected_range, "fixed_versions": v.fixed_versions, "references": v.references}
        for v in d.vulnerabilities
    ]
    max_sev = max((v["severity"] for v in vulns), key=lambda s: SEVERITY_ORDER.get(s, 0), default=None)
    return {
        "organization_id": audit["organization_id"],
        "repository_id": audit["repository_id"],
        "audit_id": audit["_id"],
        "package_name": d.name,
        "version": d.version,
        "declared": d.declared,
        "ecosystem": d.ecosystem,
        "manifest": d.manifest,
        "line": d.line,
        "scope": d.scope,
        "direct": d.direct,
        "vulnerabilities": vulns,
        "vulnerable": bool(vulns),
        "max_severity": max_sev,
        "recommended_version": d.recommended_version,
    }


def store_results(audit: dict, result: ScanResult, stages: list[dict] | None = None,
                  ai_stats: dict | None = None) -> dict:
    """Write findings and dependencies for an audit and mark it completed. Returns the summary."""
    db = get_db()
    now = utcnow()
    docs = [_finding_doc(audit, f, now) for f in result.findings]
    carried = _carry_over(docs, audit["repository_id"], audit["organization_id"])
    if docs:
        db.findings.insert_many(docs, ordered=False)
    dep_docs = [_dependency_doc(audit, d) for d in result.dependencies]
    if dep_docs:
        db.dependencies.insert_many(dep_docs, ordered=False)

    counts = empty_counts()
    for d in docs:
        if d["status"] in ("new", "confirmed", "in_progress"):
            counts[d["severity"]] += 1
    project = result.project
    summary = {
        "counts": counts,
        "security_score": security_score(counts),
        "total_findings": len(docs),
        "carried_over": carried,
        "by_scanner": {s: sum(1 for d in docs if d["scanner"] == s) for s in ("semgrep", "gitleaks", "osv")},
        "languages": project.languages,
        "primary_language": project.primary_language,
        "frameworks": project.frameworks,
        "manifests": project.manifests,
        "file_count": project.file_count,
        "total_bytes": project.total_bytes,
        "dependency_count": len(dep_docs),
        "vulnerable_dependency_count": sum(1 for d in dep_docs if d["vulnerable"]),
        "scanner_errors": result.errors,
        "enabled_scanners": result.enabled_scanners,
        "failed_scanners": result.failed_scanners,
        "removed_control_files": result.removed_control_files,
        "vendored_files_skipped": len(project.vendored_files),
        "durations": result.durations,
        "ai": ai_stats,
    }
    final = {"status": "completed", "completed_at": now, "updated_at": now,
             "summary": summary, "scanner_versions": result.scanner_versions}
    if stages is not None:
        final["stages"] = stages
    db.audits.update_one({"_id": audit["_id"]}, {"$set": final, "$unset": {"active": ""}})
    db.repositories.update_one({"_id": audit["repository_id"], "organization_id": audit["organization_id"]}, {"$set": {
        "language": project.primary_language,
        "framework": project.frameworks[0] if project.frameworks else None,
        "frameworks": project.frameworks,
        "languages": project.languages,
        "updated_at": now}})
    refresh_repository_snapshot(audit["organization_id"], audit["repository_id"])
    log_event("audit.completed", org_id=audit["organization_id"], user_id=audit.get("created_by"),
              details={"audit_id": id_str(audit["_id"]), "findings": len(docs)})
    return summary


# ---- dependencies API ----

def latest_completed_audit(org_id: ObjectId, repo_id: ObjectId) -> dict | None:
    return get_db().audits.find_one({"organization_id": org_id, "repository_id": repo_id, "status": "completed"},
                                    sort=[("created_at", -1), ("_id", -1)])


def list_dependencies(org_id: ObjectId, repo_id: ObjectId, *, vulnerable: bool | None, ecosystem: str | None,
                      q: str | None, page: int, per_page: int) -> tuple[dict | None, list[dict], int]:
    audit = latest_completed_audit(org_id, repo_id)
    if audit is None:
        return None, [], 0
    query: dict = {"organization_id": org_id, "audit_id": audit["_id"]}
    if vulnerable is not None:
        query["vulnerable"] = vulnerable
    if ecosystem:
        query["ecosystem"] = ecosystem
    if q:
        query["package_name"] = {"$regex": re.escape(q), "$options": "i"}
    col = get_db().dependencies
    total = col.count_documents(query)
    cursor = col.find(query).sort([("vulnerable", -1), ("package_name", 1), ("_id", 1)]) \
        .skip((page - 1) * per_page).limit(per_page)
    return audit, list(cursor), total


def serialize_dependency(d: dict) -> dict:
    return {
        "id": id_str(d["_id"]),
        "package_name": d["package_name"],
        "version": d.get("version"),
        "declared": d.get("declared"),
        "ecosystem": d["ecosystem"],
        "manifest": d["manifest"],
        "line": d.get("line"),
        "scope": d.get("scope"),
        "direct": d.get("direct"),
        "vulnerable": d.get("vulnerable", False),
        "max_severity": d.get("max_severity"),
        "recommended_version": d.get("recommended_version"),
        "vulnerabilities": d.get("vulnerabilities", []),
    }

