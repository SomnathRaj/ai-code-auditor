import click
from pymongo.errors import PyMongoError

from .db import get_db, supports_transactions
from .db.schema import ensure_schema
from .db.utils import parse_id
from .errors import ApiError
from .services.workspace import purge_stale_workspaces


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Create MongoDB collections, validators and indexes (safe to re-run)."""
        try:
            names = ensure_schema(get_db())
            tx = supports_transactions()
        except PyMongoError as err:
            raise click.ClickException(f"MongoDB error: {err}")
        click.echo(f"Database '{get_db().name}' ready: {', '.join(names)}")
        if not tx:
            click.echo("Warning: server is not a replica set; multi-document transactions are unavailable.")

    @app.cli.command("cleanup-workspaces")
    @click.option("--max-age-hours", default=6, show_default=True, help="Remove workspaces older than this.")
    def cleanup_workspaces(max_age_hours: int):
        """Delete audit workspaces left behind by crashes (run from cron)."""
        removed = purge_stale_workspaces(max_age_hours * 3600)
        click.echo(f"Removed {removed} stale workspace(s) from {app.config['WORK_DIR']}")

    @app.cli.command("retention")
    @click.option("--dry-run", is_flag=True, help="Report what would be deleted without deleting.")
    def retention(dry_run: bool):
        """Apply data-retention settings (the worker also runs this daily)."""
        from .services.retention import apply
        counts = apply(dry_run=dry_run)
        prefix = "Would delete" if dry_run else "Deleted"
        click.echo(f"{prefix}: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items()))

    @app.cli.command("rotate-encryption-key")
    def rotate_encryption_key():
        """Re-encrypt stored GitHub tokens and ZIP archives with the first key in ENCRYPTION_KEYS.

        Rotation: put the new key first (ENCRYPTION_KEYS=new,old), restart, run this command,
        then remove the old key."""
        from .services.crypto import rotate_text
        from .services.source_archive import delete_archive, reencrypt_archive

        db = get_db()
        tokens = archives = 0
        for repo in db.repositories.find({"credentials.encrypted_token": {"$type": "string"}}, {"credentials": 1}):
            db.repositories.update_one({"_id": repo["_id"]}, {"$set": {
                "credentials.encrypted_token": rotate_text(repo["credentials"]["encrypted_token"])}})
            tokens += 1
        for repo in db.repositories.find({"provider": "zip", "source": {"$ne": None}},
                                         {"source": 1, "organization_id": 1}):
            new = reencrypt_archive(repo["source"], repo["organization_id"])
            db.repositories.update_one({"_id": repo["_id"]}, {"$set": {"source": new}})
            delete_archive(repo["source"]["archive_id"])
            archives += 1
        click.echo(f"Re-encrypted {tokens} access token(s) and {archives} archive(s) with the primary key.")

    @app.cli.command("worker")
    @click.option("--concurrency", type=int, default=None, help="Audits processed in parallel (WORKER_CONCURRENCY).")
    def worker(concurrency: int | None):
        """Run the background audit worker (use with AUDIT_WORKER=external in the web process)."""
        import signal
        import threading

        from .worker import AuditWorker

        w = AuditWorker(app, concurrency=concurrency)
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        w.start()
        click.echo(f"Audit worker {w.id} running with {w.concurrency} thread(s). Ctrl+C to stop.")
        stop.wait()
        click.echo("Stopping: running audits are returned to the queue …")
        w.stop(timeout=30)

    @app.cli.command("scan")
    @click.argument("repository_id")
    @click.option("--branch", default=None, help="Branch to audit (GitHub repositories; default: the default branch).")
    @click.option("--type", "audit_type", default="full", show_default=True,
                  type=click.Choice(["full", "security", "dependency", "secret", "quick"]))
    def scan(repository_id: str, branch: str | None, audit_type: str):
        """Queue an audit and process it right here (no separate worker needed)."""
        from .services.audit_service import enqueue
        from .worker import AuditWorker

        try:
            repo = get_db().repositories.find_one({"_id": parse_id(repository_id, "Repository")})
        except ApiError:
            repo = None
        if repo is None:
            raise click.ClickException(f"Repository {repository_id} not found")
        try:
            audit = enqueue(repo, None, branch, audit_type)
        except ApiError as err:
            raise click.ClickException(err.message)
        label = f"AUD-{audit['audit_number']}"
        click.echo(f"Auditing {repo['name']} ({repo['provider']}) as {label} …")
        AuditWorker(app, worker_id="cli").run_once(audit["_id"])
        audit = get_db().audits.find_one({"_id": audit["_id"]})
        for st in audit["stages"]:
            mark = {"completed": "✓", "failed": "✗", "skipped": "–", "cancelled": "✗"}.get(st["status"], "○")
            click.echo(f"  {mark} {st['label']}" + (f"  ({st['detail']})" if st.get("detail") else ""))
        if audit["status"] != "completed":
            raise click.ClickException(f"{label} {audit['status']}: {audit['error']['message']}")
        s = audit["summary"]
        click.echo(f"{label} completed in {s['durations'].get('total', 0)}s — "
                   f"{s['total_findings']} findings, score {s['security_score']}/100")
        click.echo("  " + (", ".join(f"{k}: {v}" for k, v in s["counts"].items() if v) or "no open findings"))
        click.echo(f"  dependencies: {s['dependency_count']} ({s['vulnerable_dependency_count']} vulnerable)")
        for err in s["scanner_errors"]:
            click.echo(f"  warning [{err['scanner']}]: {err['message']}")
