"""Background audit worker (PRD §40) — MongoDB-backed queue, no Redis/Celery.

    queued ──claim──▶ cloning ▶ detecting ▶ scanning ▶ dependency_analysis ▶ ai_analysis ▶ processing ▶ completed
                                                                                                    ╰▶ failed / cancelled

- Claim: one atomic find_one_and_update on the oldest queued audit, so any number
  of worker threads/processes can run safely side by side.
- Heartbeat: a thread per job refreshes worker.heartbeat_at, picks up cancel
  requests and enforces AUDIT_TIMEOUT_SECONDS by firing the job's CancelToken,
  which kills running git/scanner processes.
- Ownership: every write is conditioned on worker.id, so a worker that lost its
  job (e.g. after being declared stale) can't overwrite the new attempt.
- Recovery: audits whose heartbeat stopped are re-queued (up to AUDIT_MAX_ATTEMPTS)
  or marked failed.

Run embedded in the web process (AUDIT_WORKER=embedded, started on the first
request) or as its own process: `flask --app run worker`.
"""
import os
import shutil
import socket
import threading
import time
import uuid
from datetime import timedelta

from flask import Flask
from pymongo import ReturnDocument

from .db import get_db
from .db.utils import id_str, utcnow
from .scanners.cancel import Cancelled, CancelToken
from .scanners.engine import run_scan
from .services import retention
from .services.audit_log import log_event
from .services.audit_service import RUNNING_STATUSES, initial_stages
from .ai.analyzer import analyze_findings
from .services.scan_service import ai_config, clear_partial_results, scan_config, store_results
from .services.workspace import WORKSPACE_PREFIX, SourceError, acquire_source, work_root


class LostOwnership(Exception):
    """Another worker now owns this audit (we were declared stale)."""


class Job:
    """One audit being processed by this worker: local stage state + guarded writes."""

    def __init__(self, worker: "AuditWorker", audit: dict):
        self.worker = worker
        self.audit = audit
        self.stages = [dict(s) for s in audit["stages"]]
        self.cancel = CancelToken()
        self.provider = "github"

    @property
    def filter(self) -> dict:
        return {"_id": self.audit["_id"], "worker.id": self.worker.id}

    def _write(self, update: dict) -> None:
        res = get_db().audits.update_one(self.filter, update)
        if res.matched_count == 0:
            raise LostOwnership()

    def _current_status(self) -> str:
        for s in self.stages:
            if s["status"] == "running":
                return s["name"]
        for s in self.stages:
            if s["status"] == "pending":
                return s["name"]
        return "processing"

    def mark(self, name: str, state: str, detail: str | None = None) -> None:
        """Update a stage in memory only."""
        now = utcnow()
        for s in self.stages:
            if s["name"] == name:
                if state == "running" and s["status"] != "running":
                    s["started_at"] = now
                if state in ("completed", "failed", "skipped", "cancelled"):
                    s["completed_at"] = now
                s["status"] = state
                if detail is not None:
                    s["detail"] = detail

    def stage(self, name: str, state: str, detail: str | None = None) -> None:
        """Update a stage and persist it (also used as the engine's progress callback)."""
        self.mark(name, state, detail)
        self._write({"$set": {"stages": self.stages, "status": self._current_status(), "updated_at": utcnow()}})

    def set(self, **fields) -> None:
        self._write({"$set": {**fields, "updated_at": utcnow()}})

    def close_stages(self, state: str) -> list[dict]:
        now = utcnow()
        for s in self.stages:
            if s["status"] in ("pending", "running"):
                s["status"] = state
                s["completed_at"] = now if state != "pending" else None
        return self.stages

    def finish(self, status: str, code: str | None = None, message: str | None = None) -> None:
        stage_state = {"failed": "failed", "cancelled": "cancelled"}.get(status, "skipped")
        now = utcnow()
        self._write({"$set": {"status": status, "stages": self.close_stages(stage_state), "completed_at": now,
                              "updated_at": now, "error": {"code": code, "message": message} if code else None},
                     "$unset": {"active": ""}})
        event = {"failed": "audit.failed", "cancelled": "audit.cancelled"}[status]
        log_event(event, org_id=self.audit["organization_id"], user_id=self.audit.get("created_by"),
                  details={"audit_id": id_str(self.audit["_id"]), "code": code})


class AuditWorker:
    def __init__(self, app: Flask, concurrency: int | None = None, worker_id: str | None = None):
        self.app = app
        cfg = app.config
        self.concurrency = concurrency or cfg["WORKER_CONCURRENCY"]
        self.poll_seconds = cfg["WORKER_POLL_SECONDS"]
        self.heartbeat_seconds = cfg["WORKER_HEARTBEAT_SECONDS"]
        self.stale_after = timedelta(seconds=cfg["WORKER_STALE_SECONDS"])
        self.timeout = timedelta(seconds=cfg["AUDIT_TIMEOUT_SECONDS"])
        self.max_attempts = cfg["AUDIT_MAX_ATTEMPTS"]
        self.id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    # ---- queue ----

    def claim(self, audit_id=None) -> dict | None:
        now = utcnow()
        query = {"status": "queued"}
        if audit_id is not None:
            query["_id"] = audit_id
        audit = get_db().audits.find_one_and_update(
            query,
            {"$set": {"status": "cloning", "cancel_requested": False, "updated_at": now,
                      "worker": {"id": self.id, "claimed_at": now, "heartbeat_at": now}},
             "$min": {"started_at": now},
             "$inc": {"attempts": 1}},
            sort=[("created_at", 1), ("_id", 1)],
            return_document=ReturnDocument.AFTER,
        )
        return audit

    def recover_stale(self) -> dict:
        """Re-queue (or fail) audits whose worker stopped sending heartbeats."""
        db = get_db()
        cutoff = utcnow() - self.stale_after
        counts = {"requeued": 0, "failed": 0, "cancelled": 0}
        for audit in db.audits.find({"status": {"$in": list(RUNNING_STATUSES)}, "worker.heartbeat_at": {"$lt": cutoff}}):
            guard = {"_id": audit["_id"], "worker.heartbeat_at": audit["worker"]["heartbeat_at"]}
            now = utcnow()
            if audit.get("cancel_requested"):
                update = {"$set": {"status": "cancelled", "completed_at": now, "updated_at": now,
                                   "error": {"code": "cancelled", "message": "Cancelled"}}, "$unset": {"active": ""}}
                key = "cancelled"
            elif audit.get("attempts", 0) < self.max_attempts:
                repo = db.repositories.find_one({"_id": audit["repository_id"]}, {"provider": 1}) or {}
                update = {"$set": {"status": "queued", "worker": None, "updated_at": now,
                                   "stages": initial_stages(repo.get("provider", "github"))}}
                key = "requeued"
            else:
                update = {"$set": {"status": "failed", "completed_at": now, "updated_at": now,
                                   "error": {"code": "worker_lost",
                                             "message": "The audit worker stopped responding; the audit was abandoned"}},
                          "$unset": {"active": ""}}
                key = "failed"
            if db.audits.update_one(guard, update).modified_count:
                counts[key] += 1
                self._remove_workspace(audit.get("worker") or {})
                log_event(f"audit.recovered_{key}", org_id=audit["organization_id"],
                          details={"audit_id": id_str(audit["_id"]), "worker": audit["worker"]["id"]})
        return counts

    def _remove_workspace(self, worker_info: dict) -> None:
        """Delete a crashed attempt's workspace if it lives on this host."""
        path = worker_info.get("workspace")
        if not path or worker_info.get("host") != socket.gethostname():
            return
        root = os.path.realpath(work_root())
        real = os.path.realpath(path)
        if real.startswith(root + os.sep) and os.path.basename(real).startswith(WORKSPACE_PREFIX):
            shutil.rmtree(real, ignore_errors=True)

    # ---- processing ----

    def _heartbeat(self, job: Job, done: threading.Event) -> None:
        deadline = utcnow() + self.timeout
        with self.app.app_context():
            while not done.wait(self.heartbeat_seconds):
                doc = get_db().audits.find_one_and_update(
                    job.filter, {"$set": {"worker.heartbeat_at": utcnow()}},
                    projection={"cancel_requested": 1})
                if doc is None:
                    job.cancel.cancel("lost")
                elif doc.get("cancel_requested"):
                    job.cancel.cancel("cancelled")
                elif utcnow() > deadline:
                    job.cancel.cancel("timeout")

    def process(self, audit: dict) -> str:
        """Run one claimed audit to a final (or re-queued) state. Returns the resulting status."""
        job = Job(self, audit)
        key = id_str(audit["_id"])
        with self._lock:
            self.jobs[key] = job
        done = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(job, done), daemon=True, name=f"heartbeat-{key}")
        beat.start()
        try:
            return self._run(job)
        except LostOwnership:
            self.app.logger.warning("Audit %s was taken over by another worker", key)
            return "lost"
        finally:
            done.set()
            with self._lock:
                self.jobs.pop(key, None)

    def _run(self, job: Job) -> str:
        audit = job.audit
        db = get_db()
        repo = db.repositories.find_one({"_id": audit["repository_id"], "organization_id": audit["organization_id"]})
        if repo is None:
            job.finish("failed", "repository_deleted", "The repository was deleted")
            return "failed"
        job.provider = repo["provider"]
        log_event("audit.started", org_id=audit["organization_id"], user_id=audit.get("created_by"),
                  details={"audit_id": id_str(audit["_id"]), "attempt": audit.get("attempts", 1)})
        clear_partial_results(audit)
        settings = audit.get("settings") or repo["settings"]
        branch = audit["branch"] if repo["provider"] == "github" else None
        try:
            job.stage("cloning", "running")
            with acquire_source(repo, branch, cancel=job.cancel) as ws:
                job.set(**{"worker.workspace": ws.path, "worker.host": socket.gethostname()})
                detail = f"{ws.file_count} files" + (f" @ {ws.commit_hash[:10]}" if ws.commit_hash else "")
                job.stage("cloning", "completed", detail)
                if ws.commit_hash:
                    job.set(commit_hash=ws.commit_hash)
                result = run_scan(ws.source_dir, ws.path, settings, scan_config(),
                                  progress=job.stage, cancel=job.cancel)
                job.cancel.raise_if_cancelled()
                if result.enabled_scanners and set(result.failed_scanners) >= set(result.enabled_scanners):
                    reasons = "; ".join(e["message"] for e in result.errors
                                        if e.get("scanner") in result.failed_scanners)
                    job.finish("failed", "scanner_failed", f"All scanners failed: {reasons}"[:500])
                    return "failed"
                ai_stats = self._ai_stage(job, result, ws.source_dir, settings)  # needs the source: inside the workspace
            job.stage("processing", "running")
            job.mark("processing", "completed", f"{len(result.findings)} findings")
            store_results(audit, result, stages=job.close_stages("skipped"), ai_stats=ai_stats)
            return "completed"
        except Cancelled as c:
            return self._cancelled(job, c.reason)
        except SourceError as err:
            if job.cancel.cancelled:
                return self._cancelled(job, job.cancel.reason)
            job.finish("failed", err.code, err.message)
            return "failed"
        except LostOwnership:
            raise
        except Exception:
            self.app.logger.exception("Audit %s failed", audit["_id"])
            job.finish("failed", "internal_error", "The audit failed unexpectedly")
            return "failed"

    def _ai_stage(self, job: Job, result, source_dir: str, settings: dict) -> dict | None:
        """AI analysis (PRD §26). Failures here never fail the audit: findings keep their scanner evidence."""
        if not settings.get("ai_enabled", True):
            job.stage("ai_analysis", "skipped", "Disabled in this repository's settings")
            return {"status": "disabled"}
        cfg = ai_config(job.audit["organization_id"])
        if cfg is None:
            job.stage("ai_analysis", "skipped", "Not configured (set GEMINI_API_KEY)")
            return {"status": "not_configured"}
        job.stage("ai_analysis", "running")
        stats = analyze_findings(result.findings, source_dir, result.project, cfg,
                                 progress=lambda detail: job.stage("ai_analysis", "running", detail),
                                 cancel=job.cancel)
        data = stats.to_dict()
        done = stats.analyzed + stats.cached
        if stats.error and done == 0 and stats.selected:
            data["status"] = "failed"
            job.stage("ai_analysis", "failed", f"AI analysis failed: {stats.error[:160]}")
            result.errors.append({"scanner": "ai", "message": stats.error[:300]})
        else:
            data["status"] = "completed"
            detail = f"{done} analysed ({stats.cached} cached)" if stats.selected else "No findings needed analysis"
            if stats.likely_false_positives:
                detail += f", {stats.likely_false_positives} likely false positive(s)"
            if stats.skipped_limit:
                detail += f", {stats.skipped_limit} over the limit"
            if stats.failed:
                detail += f", {stats.failed} failed"
                result.errors.append({"scanner": "ai", "message": f"{stats.failed} finding(s) could not be analysed"
                                      + (f": {stats.error[:200]}" if stats.error else "")})
            job.stage("ai_analysis", "completed", detail)
        return data

    def _cancelled(self, job: Job, reason: str) -> str:
        if reason == "timeout":
            minutes = int(self.timeout.total_seconds() // 60)
            job.finish("failed", "timeout", f"The audit exceeded the {minutes}-minute time limit")
            return "failed"
        if reason == "shutdown":
            now = utcnow()
            # Handed back to the queue; the interrupted attempt doesn't count.
            job._write({"$set": {"status": "queued", "worker": None, "updated_at": now,
                                 "stages": initial_stages(job.provider)},
                        "$inc": {"attempts": -1}})
            return "queued"
        if reason == "lost":
            raise LostOwnership()
        job.finish("cancelled", "cancelled", "Cancelled by a user")
        return "cancelled"

    # ---- loops ----

    def run_once(self, audit_id=None) -> str | None:
        """Claim and process one audit (optionally a specific one). Returns its final status or None."""
        with self.app.app_context():
            audit = self.claim(audit_id)
            return self.process(audit) if audit else None

    def _loop(self) -> None:
        with self.app.app_context():
            while not self.stop_event.is_set():
                try:
                    audit = self.claim()
                except Exception:
                    self.app.logger.exception("Worker could not claim an audit")
                    audit = None
                if audit is None:
                    self.stop_event.wait(self.poll_seconds)
                    continue
                self.process(audit)

    def _recovery_loop(self) -> None:
        """Maintenance: stale-audit recovery every cycle, data retention once a day."""
        last_retention = 0.0
        with self.app.app_context():
            while not self.stop_event.is_set():
                try:
                    self.recover_stale()
                except Exception:
                    self.app.logger.exception("Stale-audit recovery failed")
                if time.monotonic() - last_retention > 24 * 3600:
                    last_retention = time.monotonic()
                    try:
                        counts = retention.apply()
                        if any(counts.values()):
                            self.app.logger.info("Retention applied: %s", counts)
                    except Exception:
                        self.app.logger.exception("Retention failed")
                self.stop_event.wait(max(30, self.stale_after.total_seconds() / 2))

    def start(self) -> None:
        with self.app.app_context():
            self.recover_stale()
        self.threads = [threading.Thread(target=self._loop, daemon=True, name=f"audit-worker-{i}")
                        for i in range(self.concurrency)]
        self.threads.append(threading.Thread(target=self._recovery_loop, daemon=True, name="audit-recovery"))
        for t in self.threads:
            t.start()
        self.app.logger.info("Audit worker %s started (%d threads)", self.id, self.concurrency)

    def stop(self, timeout: float | None = None) -> None:
        """Stop claiming; running audits are handed back to the queue (reason "shutdown")."""
        self.stop_event.set()
        with self._lock:
            jobs = list(self.jobs.values())
        for job in jobs:
            job.cancel.cancel("shutdown")
        for t in self.threads:
            t.join(timeout)


_embedded: AuditWorker | None = None
_embedded_lock = threading.Lock()


def ensure_embedded_worker(app: Flask) -> None:
    """Start the in-process worker once per serving process (called on the first request)."""
    global _embedded
    if _embedded is not None or app.config["AUDIT_WORKER"] != "embedded":
        return
    with _embedded_lock:
        if _embedded is None:
            _embedded = AuditWorker(app)
            _embedded.start()

