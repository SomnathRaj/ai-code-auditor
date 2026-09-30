"""Gunicorn settings for production (see docs/DEPLOYMENT.md).

Run:  .venv/bin/gunicorn -c gunicorn.conf.py run:app
Audits run in a separate `flask --app run worker` process (AUDIT_WORKER=external).
"""
import multiprocessing
import os

bind = os.environ.get("GUNICORN_BIND", "127.0.0.1:4000")  # Nginx proxies to this; never expose it directly
workers = int(os.environ.get("GUNICORN_WORKERS", min(4, multiprocessing.cpu_count() * 2 + 1)))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
worker_class = "gthread"
timeout = 120            # PDF reports of large audits can take a while
graceful_timeout = 30
keepalive = 5
max_requests = 2000      # recycle workers periodically
max_requests_jitter = 200
limit_request_line = 8190
limit_request_fields = 100
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
# Don't log query strings with tokens: the API only uses headers for auth, so the default format is fine.
