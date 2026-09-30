# Deployment

This guide deploys AI Code Auditor on a single Linux server without Docker:

- **Nginx** handles TLS, serves `frontend/` and proxies `/api/v1` to gunicorn.
- **gunicorn** runs the Flask API on 127.0.0.1:4000.
- A **separate worker process** runs audits.
- **MongoDB** can be local or remote.

See [SECURITY.md](SECURITY.md) for the reasoning behind the hardening steps.

```
browser ──HTTPS──> Nginx ──┬── /            frontend/ (static files)
                           └── /api/v1/  ──> gunicorn 127.0.0.1:4000 ──┐
                                                                       ├──> MongoDB
                     worker (flask worker) ── semgrep / gitleaks / OSV / Gemini
```

## 1. System user and code

```bash
sudo useradd --system --create-home --home-dir /opt/aca --shell /usr/sbin/nologin aca
sudo -u aca git clone <repo-url> /opt/aca/app      # or copy the release files
cd /opt/aca/app
sudo -u aca python3 -m venv .venv
sudo -u aca .venv/bin/pip install -r requirements.lock   # exact, reviewed versions
sudo -u aca .venv/bin/pip check
sudo -u aca scripts/install-scanners.sh                  # .tools/semgrep-venv + .tools/bin/{semgrep,gitleaks}
```

- **Python 3.11 or newer** is needed (developed on 3.14), plus `git`.
- **Semgrep** installs into its own virtualenv (`.tools/semgrep-venv`), so its dependency pins never conflict with the app's.
- **`requirements.lock`** already includes gunicorn. To upgrade dependencies:
  1. Run `pip install -U -r requirements-prod.txt`.
  2. Run the tests.
  3. Regenerate the lock file with `pip freeze`.

## 2. Configuration (`/opt/aca/app/.env`)

Start from `.env.example`. Settings that differ in production:

```ini
FLASK_DEBUG=0
JWT_SECRET=<64+ random chars>          # python -c "import secrets; print(secrets.token_urlsafe(64))"
ENCRYPTION_KEYS=<fernet key>           # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MONGODB_URI=mongodb://<user>:<password>@<host>:27017/?authSource=admin
MONGODB_DATABASE=ai_code_auditor

COOKIE_SECURE=1        # HTTPS only refresh cookie
PROXY_FIX=1            # trust X-Forwarded-For/Proto/Host from Nginx (client IPs for rate limits, HSTS)
SERVE_FRONTEND=0       # Nginx serves frontend/
AUDIT_WORKER=external  # audits run in the separate worker service, not in gunicorn
ALLOWED_ORIGINS=https://auditor.example.com

WORK_DIR=/var/lib/aca/work            # 0700, owned by aca
# SCANNER_USER=aca-scan               # optional: run scanners as a separate, egress-restricted user
GEMINI_API_KEY=<key>
```

```bash
sudo chown aca:aca .env && sudo chmod 600 .env
sudo install -d -o aca -g aca -m 700 /var/lib/aca/work
sudo -u aca .venv/bin/flask --app run init-db     # collections, validators, indexes (safe to re-run)
```

Keep backups of `ENCRYPTION_KEYS`. Without the key, stored GitHub tokens and uploaded archives can't be read.

## 3. gunicorn and worker (systemd)

`/etc/systemd/system/aca-web.service`:

```ini
[Unit]
Description=AI Code Auditor API (gunicorn)
After=network-online.target

[Service]
User=aca
Group=aca
WorkingDirectory=/opt/aca/app
ExecStart=/opt/aca/app/.venv/bin/gunicorn -c gunicorn.conf.py run:app
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aca
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/aca-worker.service`:

```ini
[Unit]
Description=AI Code Auditor audit worker
After=network-online.target

[Service]
User=aca
Group=aca
WorkingDirectory=/opt/aca/app
ExecStart=/opt/aca/app/.venv/bin/flask --app run worker
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=60          # SIGTERM: stop claiming, hand running audits back to the queue, exit
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aca
ProtectHome=true
LimitCORE=0

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aca-web aca-worker
journalctl -u aca-web -u aca-worker -f
```

`gunicorn.conf.py` settings:

- binds to 127.0.0.1:4000, with `GUNICORN_BIND`, `GUNICORN_WORKERS` and `GUNICORN_THREADS` as overrides;
- uses gthread workers with a 120 s timeout (large PDF reports need it);
- logs to stdout.

Rate-limit counters are kept in MongoDB, so every gunicorn worker shares them.

You can run several worker instances, on one host or several. Audits are claimed atomically. A crashed worker's audits are re-queued after `WORKER_STALE_SECONDS`.

### Network restrictions for scanners (recommended)

With no containers, scanners have the worker user's network access. Restrict the worker's user (or `SCANNER_USER`) to the endpoints it needs:

- MongoDB;
- `github.com:443`, for cloning;
- `api.osv.dev:443`;
- `generativelanguage.googleapis.com:443`, or the proxy set in `GEMINI_BASE_URL`.

Use nftables `meta skuid` rules or an egress proxy for this.

## 4. Nginx

```nginx
server {
    listen 80;
    server_name auditor.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auditor.example.com;

    ssl_certificate     /etc/letsencrypt/live/auditor.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auditor.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /opt/aca/app/frontend;
    index index.html;
    client_max_body_size 100m;          # = MAX_UPLOAD_MB (ZIP uploads)

    # Static pages: same security headers the API sends
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy same-origin always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        try_files $uri =404;
    }

    location /api/v1/ {
        proxy_pass http://127.0.0.1:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, don't append client-supplied values
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_read_timeout 180s;
        proxy_request_buffering off;    # stream large uploads to the app
    }
}
```

Compare the CSP above with `CSP` in `app/__init__.py` and keep the two in sync.

`X-Forwarded-For` is overwritten with `$remote_addr`, so clients can't spoof their IP to get around rate limits. `ProxyFix` trusts exactly one proxy hop.

## 5. Scheduled jobs

The worker already runs data retention once a day and recovers stale audits. Add this cron entry to remove workspaces left behind by crashes (`crontab -u aca -e`):

```cron
15 * * * *  cd /opt/aca/app && .venv/bin/flask --app run cleanup-workspaces --max-age-hours 6
# Optional, if the worker is not always running:
30 3 * * *  cd /opt/aca/app && .venv/bin/flask --app run retention
```

## 6. Operations

| Task | Command |
|---|---|
| Preview retention | `flask --app run retention --dry-run` |
| Rotate the encryption key | Put the new key first in `ENCRYPTION_KEYS`, restart both services, then run `flask --app run rotate-encryption-key`. After that, drop the old key and restart. |
| Update scanners | `scripts/install-scanners.sh`, then `systemctl restart aca-worker` |
| Upgrade the app | Pull the code, `pip install -r requirements.lock`, `flask --app run init-db`, then restart both services |
| Health check | `curl -s https://auditor.example.com/api/v1/health` |

### Checklist before going live

- [ ] HTTPS works and HTTP redirects to it.
- [ ] `COOKIE_SECURE=1` and `PROXY_FIX=1`.
- [ ] An API response has `Strict-Transport-Security`.
- [ ] `.env` is mode 600, and the key and secrets are backed up somewhere safe.
- [ ] MongoDB requires authentication and is not reachable from the internet.
- [ ] Neither service runs as root.
- [ ] Egress from the worker user is restricted.
- [ ] `flask --app run init-db` was run after the upgrade.
- [ ] `pip check` is clean, and `scripts/install-scanners.sh` was run.
