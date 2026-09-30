"""Audit comparison (PRD §60): new / resolved / unchanged / reopened between two audits
of the same repository.

Findings are matched by fingerprint first. Fingerprints include the line number
(PRD §42), so a second pass matches the rest on (rule, file, text of the flagged line):
code that merely moved isn't reported as "resolved + new".
"""
import hashlib
import re

from bson import ObjectId

from ..constants import OPEN_FINDING_STATUSES
from ..db import get_db
from ..db.utils import id_str, iso
from ..errors import ApiError
from .finding_service import serialize_summary

DISMISSED = ("false_positive", "accepted_risk", "ignored")
FIXED = ("resolved", "verified")
LIST_LIMIT = 500
_FIELDS = {"code_context": 0, "raw": 0, "status_history": 0}


def _flagged_line(f: dict) -> str:
    snippet, start = f.get("code_snippet"), f.get("snippet_start_line")
    line = (f.get("location") or {}).get("line_start")
    if snippet and start and line:
        lines = snippet.splitlines()
        idx = line - start
        if 0 <= idx < len(lines):
            return re.sub(r"\s+", " ", lines[idx]).strip()
    return re.sub(r"\s+", " ", (f.get("description") or f.get("title") or "")).strip().lower()


def stable_key(f: dict) -> str:
    raw = "\x1f".join([f.get("rule_id") or "", (f.get("location") or {}).get("file") or "", _flagged_line(f)])
    return hashlib.sha256(raw.encode()).hexdigest()


def previous_completed(audit: dict) -> dict | None:
    return get_db().audits.find_one(
        {"organization_id": audit["organization_id"], "repository_id": audit["repository_id"],
         "status": "completed", "created_at": {"$lt": audit["created_at"]}},
        sort=[("created_at", -1), ("_id", -1)])


def _load(audit: dict) -> list[dict]:
    return list(get_db().findings.find({"organization_id": audit["organization_id"], "audit_id": audit["_id"]},
                                       _FIELDS))


def match(base: list[dict], target: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """Returns (pairs, unmatched_base, unmatched_target)."""
    pairs = []
    by_fp: dict[str, list[dict]] = {}
    for b in base:
        by_fp.setdefault(b["fingerprint"], []).append(b)
    rest_target = []
    for t in target:
        bucket = by_fp.get(t["fingerprint"])
        if bucket:
            pairs.append((bucket.pop(), t))
        else:
            rest_target.append(t)
    rest_base = [b for bucket in by_fp.values() for b in bucket]
    by_key: dict[str, list[dict]] = {}
    for b in rest_base:
        by_key.setdefault(stable_key(b), []).append(b)
    unmatched_target = []
    for t in rest_target:
        bucket = by_key.get(stable_key(t))
        if bucket:
            pairs.append((bucket.pop(), t))
        else:
            unmatched_target.append(t)
    unmatched_base = [b for bucket in by_key.values() for b in bucket]
    return pairs, unmatched_base, unmatched_target


def compare(target: dict, base: dict) -> dict:
    if base["repository_id"] != target["repository_id"]:
        raise ApiError(400, "validation_error", "Audits must belong to the same repository", {"base": "other_repository"})
    if base["_id"] == target["_id"]:
        raise ApiError(400, "validation_error", "Choose a different audit to compare with", {"base": "same_audit"})
    for a in (target, base):
        if a["status"] != "completed":
            raise ApiError.conflict(f"AUD-{a['audit_number']} is not completed")
    pairs, gone, new = match(_load(base), _load(target))
    reopened = [(b, t) for b, t in pairs if b["status"] in FIXED]
    unchanged = [(b, t) for b, t in pairs if b["status"] not in FIXED]
    resolved = [b for b in gone if b["status"] not in DISMISSED]
    dismissed_gone = [b for b in gone if b["status"] in DISMISSED]

    def rows(items, use_target=True):
        out = []
        for item in items[:LIST_LIMIT]:
            if isinstance(item, tuple):
                b, t = item
                row = serialize_summary(t if use_target else b)
                row["previous_status"] = b["status"]
            else:
                row = serialize_summary(item)
            out.append(row)
        return out

    sev = ("critical", "high", "medium", "low", "info")
    open_new = [t for t in new if t["status"] in OPEN_FINDING_STATUSES]
    return {
        "target": _audit_info(target),
        "base": _audit_info(base),
        "counts": {"new": len(new), "resolved": len(resolved), "unchanged": len(unchanged),
                   "reopened": len(reopened), "dismissed_no_longer_reported": len(dismissed_gone)},
        "new_by_severity": {s: sum(1 for t in open_new if t["severity"] == s) for s in sev},
        "resolved_by_severity": {s: sum(1 for b in resolved if b["severity"] == s) for s in sev},
        "score_change": _score(target) - _score(base) if _score(target) is not None and _score(base) is not None else None,
        "new": rows(new),
        "resolved": rows(resolved),
        "reopened": rows(reopened),
        "unchanged": rows(unchanged),
        "truncated": any(len(x) > LIST_LIMIT for x in (new, resolved, reopened, unchanged)),
    }


def _score(a: dict):
    return (a.get("summary") or {}).get("security_score")


def _audit_info(a: dict) -> dict:
    s = a.get("summary") or {}
    return {"id": id_str(a["_id"]), "display_id": f"AUD-{a['audit_number']}", "branch": a.get("branch"),
            "commit_hash": a.get("commit_hash"), "completed_at": iso(a.get("completed_at")),
            "security_score": s.get("security_score"), "open_findings": sum((s.get("counts") or {}).values())}


def fixed_between(base: dict, target: dict) -> int:
    """Open findings of `base` that `target` no longer reports (fixed in code)."""
    _pairs, gone, _new = match(_load(base), _load(target))
    return sum(1 for b in gone if b["status"] in OPEN_FINDING_STATUSES)


def get_base(org_id: ObjectId, target: dict, base_id: ObjectId | None) -> dict:
    if base_id is None:
        base = previous_completed(target)
        if base is None:
            raise ApiError(404, "not_found", "There is no earlier completed audit of this repository to compare with")
        return base
    base = get_db().audits.find_one({"_id": base_id, "organization_id": org_id})
    if base is None:
        raise ApiError.not_found("Audit")
    return base
