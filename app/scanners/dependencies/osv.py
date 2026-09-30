"""OSV.dev vulnerability lookups (https://osv.dev, free, no API key).

Only package names, versions and ecosystems are sent — never source code
(PRD §52). Vulnerability details are cached (callers supply the cache).
"""
import json
import urllib.error
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import urllib.request
from collections.abc import Callable

from ..cancel import NEVER, CancelToken
from ..models import Dependency, Vulnerability
from .cvss import base_score, severity_from_score
from .versions import highest, pick_upgrade

BATCH_SIZE = 500
FETCH_WORKERS = 8
_GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


class OSVError(Exception):
    pass


class OSVClient:
    def __init__(self, base_url: str, timeout: int, cache_get: Callable[[str], dict | None] | None = None,
                 cache_put: Callable[[str, dict], None] | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_get = cache_get or (lambda _id: None)
        self.cache_put = cache_put or (lambda _id, _data: None)

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method=method, headers={
            "Content-Type": "application/json", "User-Agent": "ai-code-auditor/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (fixed https base URL)
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, ValueError) as err:
            raise OSVError(f"OSV request failed: {getattr(err, 'reason', err)}")

    def query_batch(self, deps: list[Dependency], cancel: CancelToken = NEVER) -> list[list[str]]:
        """Vulnerability IDs per dependency (same order)."""
        out: list[list[str]] = []
        for start in range(0, len(deps), BATCH_SIZE):
            cancel.raise_if_cancelled()
            chunk = deps[start:start + BATCH_SIZE]
            queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk]
            results = self._request("POST", "/v1/querybatch", {"queries": queries}).get("results", [])
            for res in results:
                out.append([v["id"] for v in (res or {}).get("vulns", [])])
        return out

    def vulnerability(self, vuln_id: str) -> dict:
        cached = self.cache_get(vuln_id)
        if cached is not None:
            return cached
        data = self._request("GET", f"/v1/vulns/{vuln_id}")
        self.cache_put(vuln_id, data)
        return data


def _severity(data: dict, affected: dict | None) -> tuple[str, float | None]:
    scores = [base_score(s.get("score", "")) for s in data.get("severity", []) if s.get("type") == "CVSS_V3"]
    if affected:
        scores += [base_score(s.get("score", "")) for s in affected.get("severity", []) if s.get("type") == "CVSS_V3"]
    scores = [s for s in scores if s is not None]
    if scores:
        score = max(scores)
        return severity_from_score(score), score
    label = (data.get("database_specific") or {}).get("severity") or \
            ((affected or {}).get("database_specific") or {}).get("severity")
    if label and str(label).upper() in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[str(label).upper()], None
    return "medium", None  # unknown: don't under-report


def _affected_for(data: dict, dep: Dependency) -> dict | None:
    for aff in data.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] == dep.ecosystem and pkg.get("name", "").lower() == dep.name.lower():
            return aff
    return None


def _range_text(aff: dict | None) -> tuple[str | None, list[str]]:
    if not aff:
        return None, []
    parts, fixed = [], []
    for rng in aff.get("ranges", []):
        if rng.get("type") == "GIT":
            continue
        introduced = None
        for ev in rng.get("events", []):
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif "fixed" in ev or "last_affected" in ev:
                upper = ev.get("fixed")
                fixed += [upper] if upper else []
                lo = f">={introduced}" if introduced and introduced != "0" else ""
                hi = f"<{upper}" if upper else f"<={ev['last_affected']}"
                parts.append(", ".join(p for p in (lo, hi) if p))
                introduced = None
        if introduced is not None:
            parts.append(f">={introduced}" if introduced != "0" else "all versions")
    return ("; ".join(parts) or None), fixed


def _fetch_all(client: OSVClient, ids: list[str], cancel: CancelToken) -> dict[str, dict]:
    """Fetch advisory details in parallel; stop promptly if the audit is cancelled."""
    details: dict[str, dict] = {}
    pool = ThreadPoolExecutor(max_workers=FETCH_WORKERS, thread_name_prefix="osv")
    try:
        pending = {pool.submit(client.vulnerability, vid): vid for vid in ids}
        while pending:
            done, _ = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            cancel.raise_if_cancelled()
            for fut in done:
                details[pending.pop(fut)] = fut.result()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return details


def enrich(deps: list[Dependency], client: OSVClient, cancel: CancelToken = NEVER) -> None:
    """Attach vulnerabilities and a recommended version to pinned dependencies (in place)."""
    pinned = [d for d in deps if d.version]
    if not pinned:
        return
    ids_per_dep = client.query_batch(pinned, cancel)
    details = _fetch_all(client, sorted({vid for ids in ids_per_dep for vid in ids}), cancel)
    for dep, ids in zip(pinned, ids_per_dep):
        seen_aliases: set[str] = set()
        for vid in ids:
            if vid in seen_aliases:
                continue
            data = details[vid]
            aliases = sorted(set(data.get("aliases", [])))
            if seen_aliases & ({vid} | set(aliases)):
                continue  # same issue already reported under another ID (e.g. PYSEC vs GHSA)
            seen_aliases |= {vid, *aliases}
            aff = _affected_for(data, dep)
            severity, score = _severity(data, aff)
            rng, fixed = _range_text(aff)
            refs = [r["url"] for r in data.get("references", []) if r.get("url")][:5]
            dep.vulnerabilities.append(Vulnerability(
                id=vid, aliases=aliases, summary=data.get("summary") or (data.get("details") or "")[:200] or None,
                severity=severity, cvss_score=score, affected_range=rng, fixed_versions=sorted(set(fixed)),
                references=refs))
        if dep.vulnerabilities:
            all_fixed = [f for v in dep.vulnerabilities for f in v.fixed_versions]
            # Upgrade target must clear every known vulnerability: the highest of the
            # per-vulnerability minimum fixes above the current version.
            per_vuln = [pick_upgrade(dep.ecosystem, dep.version, v.fixed_versions) for v in dep.vulnerabilities]
            dep.recommended_version = highest(dep.ecosystem, [p for p in per_vuln if p]) or \
                pick_upgrade(dep.ecosystem, dep.version, all_fixed)
