# AI Code Auditor

AI Code Auditor is a multi-tenant web app for security and code-quality audits. Point it at a GitHub repository or upload a ZIP, and it:

- runs **Semgrep**, **Gitleaks** and a dependency check against **OSV.dev**;
- asks **Google Gemini** whether each code finding is real and how to fix it;
- lets your team triage findings, compare audits and download reports.

**Stack:** Flask REST API (`/api/v1`), MongoDB, and a static HTML/CSS/JS frontend. There is no Docker and no build step.

| Document | What's in it |
|---|---|
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model → controls, rate limits, encryption, remaining risks |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production setup: gunicorn, Nginx, systemd, cron, go-live checklist |

## Features

- **Repositories:**
  - Add public or private GitHub repositories (branch picker; access token stored encrypted), or upload ZIP archives and later upload new versions.
- **Audits:**
  - Audits are queued and run by a background worker, with live progress per stage and a cancel button.
  - Audit types: full, security, dependency, secret, quick.
- **Findings:**
  - Filter by severity, status, category, scanner, AI verdict, file or text.
  - Each finding opens in a code viewer with the exact audited code, secrets masked.
  - Triage follows a lifecycle, with comments. Decisions are remembered in later audits.
- **AI analysis:**
  - For each finding: a verdict and confidence, explanation, impact, attack scenario and suggested fix.
  - It is advisory only; it never changes a finding's status or the score.
- **Reports:** technical (PDF, HTML, CSV, JSON) and executive (PDF, HTML, JSON).
- **Comparison and trends:**
  - Compare two audits (new, resolved, reopened, unchanged); code that only moved isn't counted as fixed.
  - Dashboard trends: open findings and score over time.
- **Teams:**
  - Workspaces with owner, admin, developer and viewer roles, and a workspace switcher.
  - Member management and an activity log.
  - Per-workspace data retention.
- **Hardening:**
  - Rate limits, encrypted credentials with key rotation, security headers.
  - Scanners are isolated with resource limits.
  - Hostile repositories can't hide their own issues.

## Requirements

- **Python 3.11 or newer** (developed and tested on 3.14), and `git` on the PATH.
- **MongoDB** (tested with 8.0). A standalone server is fine. This project uses a separate container at `localhost:27017`; see [MongoDB](#mongodb).
- **Semgrep and Gitleaks.** They are installed into `.tools/` by the script below, with no sudo.
- **Optional:** a Gemini API key from Google AI Studio, for AI analysis.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
./scripts/install-scanners.sh          # Semgrep → .tools/semgrep-venv, Gitleaks → .tools/bin
cp .env.example .env                   # then fill in the values below
.venv/bin/flask --app run init-db      # collections, validators, indexes (safe to re-run)
.venv/bin/flask --app run run --debug
```

Open **http://127.0.0.1:4000** and register. The first user of a workspace becomes its owner.

Minimum `.env`:

```ini
JWT_SECRET=...        # python -c "import secrets; print(secrets.token_urlsafe(64))"
ENCRYPTION_KEYS=...   # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MONGODB_URI=mongodb://USER:PASSWORD@localhost:27017/?authSource=admin
MONGODB_DATABASE=ai_code_auditor
TEST_MONGODB_URI=...  # for the tests (same server is fine; tests use throwaway aca_test_* databases)
GEMINI_API_KEY=...    # optional
```

**Back up `ENCRYPTION_KEYS`.** It encrypts stored GitHub tokens and uploaded archives. If the key is lost, that data can't be decrypted.

## Configuration

All settings come from `.env`. [.env.example](.env.example) lists every setting with comments. The ones you are most likely to change:

| Setting | Default | Purpose |
|---|---|---|
| `FLASK_RUN_HOST` / `FLASK_RUN_PORT` | `127.0.0.1` / `4000` | Dev server address |
| `AUDIT_WORKER` | `embedded` | `embedded` (inside the web process), `external` (`flask worker`), or `off` |
| `WORKER_CONCURRENCY` | `2` | Audits processed in parallel per worker |
| `AUDIT_TIMEOUT_SECONDS` | `3600` | An audit is stopped after this long |
| `MAX_UPLOAD_MB` / `MAX_SOURCE_MB` / `MAX_SOURCE_FILES` | `100` / `500` / `50000` | Upload size, and extracted or cloned size limits |
| `OSV_ENABLED` | `1` | Dependency vulnerability lookups (only package names and versions are sent) |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | — / `gemini-3.8-flash` | AI analysis. No key means the AI stage is skipped. |
| `AI_MIN_SEVERITY` / `AI_MAX_FINDINGS` | `medium` / `50` | Which findings are sent to the AI |
| `AI_REQUESTS_PER_MINUTE` | `0` (learned automatically) | Preset the pace for your Gemini quota |
| `RATE_LIMIT_ENABLED` | `1` | API rate limits |
| `AUDIT_LOG_RETENTION_DAYS` | `365` | How long activity-log entries are kept |
| `COOKIE_SECURE`, `PROXY_FIX`, `SERVE_FRONTEND`, `ALLOWED_ORIGINS` | dev values | Production settings; see [Production](#production) |

## Using it

### Repositories and audits

1. **Add a repository** from **Repositories → Add repository**: a GitHub URL (plus an access token if it's private) or a ZIP upload.
2. **Start an audit** from the repository page. It is queued, and the progress page shows each stage live, where you can also cancel it.
3. **Open the findings** from the finished audit (**View findings**, or click a severity card).

Each repository can have only one queued or running audit at a time. If a worker crashes, its audits are re-queued automatically.

You can also queue and run an audit from the command line:

```bash
.venv/bin/flask --app run scan <repository_id> [--branch main] [--type full|security|dependency|secret|quick]
```

The repository ID is in the page URL (`/repository.html?id=…`).

### Triage

Developers move findings through the lifecycle: confirm, start fixing, resolve, verify, reopen.

- **False positive**, **accepted risk** and **ignored** require a reason.
- These decisions carry over to later audits and update the score immediately.
- The filters are kept in the URL, so a filtered view can be shared as a link.

### Reports, comparison, trends

- **Reports:** download them from a finished audit's page, or over the API: `GET /api/v1/audits/{id}/report?format=pdf&type=executive`.
- **Compare with previous audit:** from the audit page.
- **Trends:** on the dashboard, covering all repositories.

### AI analysis (Google Gemini)

With `GEMINI_API_KEY` set, every audit gets an **AI analysis** stage.

- **What is sent:** for code findings of medium severity or above (at most 50 per audit), the surrounding function goes to Gemini, with secrets masked. Secret findings and dependency findings are never sent.
- **Caching:** results are cached per workspace, so unchanged code isn't sent again.
- **Free tier (15 requests/minute):** the client learns the limit from Gemini's responses and paces itself. A 50-finding audit takes about 4 minutes.
- **Per repository:** the AI stage can be turned off in the repository's audit settings. That screen also shows exactly what is sent.

### Workspace settings and members (`/settings.html`)

- **Owners:** rename the workspace and set retention.
  - Audit results: 7, 30, 90 (default), 180 or 365 days, or forever. Each repository's latest completed audit is always kept.
  - Uploaded ZIP source: 7 to 365 days, or until replaced.
- **Owners and admins:**
  - Add members by email. There are no invitation emails: the person registers first, then gets added.
  - Change or remove members' roles. Only owners can manage owners and admins, and the last owner can't be removed.
  - Browse the **activity log**.
- **Anyone:** can leave a workspace, except its last owner.
- **Workspace switcher:** in the top bar. The next login opens the workspace you last used.

| Role | Can |
|---|---|
| Owner | Everything, including workspace settings and managing owners and admins |
| Admin | Repositories, developers and viewers, the activity log |
| Developer | Run audits, triage, comment, upload new source versions |
| Viewer | Read only |

## CLI

All commands are run as `.venv/bin/flask --app run <command>`.

| Command | What it does |
|---|---|
| `run --debug` | Development server on 127.0.0.1:4000 |
| `init-db` | Create or update collections, validators and indexes |
| `worker [--concurrency N]` | Run the audit worker as its own process (`AUDIT_WORKER=external`) |
| `scan <repo_id>` | Queue an audit and process it right away |
| `retention [--dry-run]` | Apply retention settings now. The worker also does this daily. |
| `rotate-encryption-key` | Re-encrypt tokens and archives with the first key in `ENCRYPTION_KEYS` |
| `cleanup-workspaces [--max-age-hours 6]` | Remove audit workspaces left behind by crashes |

**Rotating the encryption key:**

1. Set `ENCRYPTION_KEYS=new,old`.
2. Restart the app and the worker.
3. Run `rotate-encryption-key`.
4. Remove the old key and restart.

## Tests

```bash
.venv/bin/pytest -q                                   # full suite (~90 s)
.venv/bin/pytest -q tests/test_security.py            # one file
.venv/bin/pytest -q tests/test_scanner_engine.py -k rule_suites   # Semgrep rule tests
```

- **The tests need a real MongoDB,** given by `TEST_MONGODB_URI`. Each test creates its own `aca_test_*` database and drops it afterwards.
- **Without the variable,** the tests are skipped.
- **Never point it at a production server.**
- **Test fixtures contain fake secrets on purpose,** to exercise the secret scanner.

## Project layout

```
app/
  __init__.py      app factory: security headers, CORS, dev frontend serving, embedded worker
  config.py        settings from .env
  cli.py           flask commands (see CLI)
  security.py      bearer auth, role checks, CSRF check for cookie endpoints
  worker.py        audit worker: atomic claim, stages, heartbeat, cancel, timeout, recovery, daily retention
  api/             /api/v1 blueprints (HTTP only), request schemas, OpenAPI spec
  services/        business rules: auth, tokens, repositories, audits, findings, comparison, dashboard,
                   organization, rate limits, retention, crypto, hardened git, ZIP handling, workspaces
  scanners/        Semgrep (own rules in rules/), Gitleaks, dependencies + OSV, masking, limited runner
  ai/              Gemini client, context extraction, prompt, validation, rate limiter, cache
  reports/         report model + JSON / HTML / PDF / CSV renderers
  db/              client, transactions, collection validators + indexes, ID/date helpers
frontend/          static pages (index.html = dashboard), css/, js/ (api.js + one file per page)
tests/             pytest API and unit tests
scripts/           install-scanners.sh
docs/              SECURITY.md, DEPLOYMENT.md
```

**Layering:** `api/` handles HTTP only, `services/` holds the rules and tenant checks, and `db/` talks to MongoDB. Routes never call PyMongo directly.

## Development conventions

- **Responses:**
  - Success is `{"data": …}`. Collections add `"meta": {page, per_page, total, total_pages}`.
  - Errors are always `{"error": {"code", "message", "details"}}`.
- **IDs:** ObjectIds as 24-character hex strings. Parse them with `parse_id()`, so that malformed IDs return 404.
- **Tenant isolation:** every workspace-owned document stores `organization_id`, and every query filters on `current_identity().org_id`.
- **Roles:** checked on the server with `@require_role(...)`, and re-read from the database on every request.
- **Auth:**
  - The access token (a JWT, valid for 15 minutes) goes in `Authorization: Bearer` and is kept in memory by the frontend.
  - The refresh token is an `HttpOnly; SameSite=Strict` cookie on `/api/v1/auth`, rotated on every use.
  - `/auth/refresh` and `/auth/logout` require `X-Requested-With: fetch` and an allowed `Origin`.
- **Frontend:**
  - Build the DOM with `App.el()` / `textContent`. **Never use `innerHTML`** with server data; the app displays untrusted code.
  - The CSP blocks inline scripts, so all JS lives in `frontend/js/`.
- **Dependencies:**
  - `requirements.txt` sets version floors that exclude releases with known advisories.
  - `requirements.lock` pins exact versions.
  - Semgrep has its own venv so that its pins don't hold back the app's dependencies.

## API

- **Spec:** OpenAPI at `GET /api/v1/openapi.json`.
- **Rate limits:** any endpoint can return `429 rate_limited`, with `Retry-After` and `X-RateLimit-*` headers.

| Method | Path | Who |
|---|---|---|
| **Auth** | | |
| POST | `/auth/register`, `/auth/login` | public |
| POST | `/auth/refresh`, `/auth/logout` | refresh cookie |
| POST | `/auth/switch-organization` | any member |
| GET | `/me`, `/me/organizations`, `/me/features` | any member |
| **Workspace** | | |
| GET | `/organization` | any member |
| PATCH | `/organization` (name, retention) | owner |
| GET, POST | `/organization/members` | owner/admin |
| PATCH, DELETE | `/organization/members/{user_id}` | owner/admin (DELETE on yourself = leave) |
| GET | `/audit-logs?event=&user_id=&since=&until=` | owner/admin |
| **Dashboard** | | |
| GET | `/dashboard`, `/dashboard/trends?days=` | any member |
| **Repositories** | | |
| GET | `/repositories`, `/repositories/{id}` (+ `/settings`, `/audits`, `/branches`, `/dependencies`) | any member |
| POST | `/repositories` (GitHub), `/repositories/uploads` (ZIP) | owner/admin |
| PATCH, DELETE | `/repositories/{id}` | owner/admin |
| PUT | `/repositories/{id}/settings` | owner/admin |
| PUT | `/repositories/{id}/source` (new ZIP version) | developer+ |
| POST | `/repositories/{id}/audits` (→ `202`, poll `Location`) | developer+ |
| **Audits** | | |
| GET | `/audits/{id}`, `/audits/{id}/status` | any member |
| POST | `/audits/{id}/cancel` | developer+ |
| DELETE | `/audits/{id}` | owner/admin |
| GET | `/audits/{id}/findings` (filters, facets) | any member |
| GET | `/audits/{id}/report?format=json\|html\|pdf\|csv&type=technical\|executive` | any member |
| GET | `/audits/{id}/comparison?base=` | any member |
| **Findings** | | |
| GET | `/findings/{id}`, `/findings/{id}/code`, `/findings/{id}/comments` | any member |
| PATCH | `/findings/{id}` (status) | developer+ |
| POST | `/findings/{id}/comments` | developer+ |
| **System** | | |
| GET | `/health`, `/openapi.json` | public |

All paths are relative to `/api/v1`.

## Scanners and security

| Scanner | What it finds |
|---|---|
| Semgrep + our 64 rules ([app/scanners/rules/](app/scanners/rules/README.md)) | Injection, XSS, path traversal, SSRF, deserialization, weak crypto, disabled TLS, debug mode, sensitive logging… in Python, JS/TS, PHP, Java, Go and config files |
| Gitleaks | Secrets. Values are redacted and never stored. |
| Dependencies + OSV.dev | Known-vulnerable packages, with the upgrade that fixes each one |

Dependency manifests read: `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `composer.json`, `composer.lock`, `go.mod`, `pom.xml`.

- **Own ruleset:** we don't use the Semgrep Registry, because its licence prohibits use in competing products.
- **Hostile repositories are expected:**
  - Repository code is never executed.
  - Git is hardened: HTTPS only, no hooks, submodules or LFS, symlinks checked out as plain files.
  - ZIP files are checked for path traversal, symlinks and zip bombs.
  - `nosemgrep` comments, `gitleaks:allow`, `.semgrepignore`, `.gitleaksignore` and `.gitleaks.toml` are all neutralised.
- **Scanner isolation:** scanners get no app secrets, run with CPU, memory and output limits, and never run as root.
- **Source retention:** cloned code is deleted after each audit. Uploaded ZIPs are stored encrypted in GridFS.
- **Remaining risk:** without containers, scanners have no network sandbox. See [docs/SECURITY.md](docs/SECURITY.md) for the full review and mitigations.

## MongoDB

MongoDB runs in its own Docker container, separate from this project, with port 27017 published to the host. That server is shared with other projects: the app only uses `MONGODB_DATABASE`, and the tests only use `aca_test_*` databases.

The container is a **standalone** server, so `init-db` warns that transactions are unavailable. The app handles this by ordering multi-document writes and cleaning up after a partial failure. To turn transactions on with no code change:

1. Convert the container to a single-node replica set.
2. Add `&replicaSet=rs0` to the URI.

## Production

Follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). In short:

- Install exact versions with `pip install -r requirements.lock`, and run `scripts/install-scanners.sh`.
- Run the API with `gunicorn -c gunicorn.conf.py run:app`, bound to 127.0.0.1:4000, behind Nginx. Nginx serves `frontend/`, terminates TLS and proxies `/api/v1`.
- Run the worker separately (`AUDIT_WORKER=external`, `flask --app run worker`) under systemd. On SIGTERM it returns running audits to the queue.
- Set `COOKIE_SECURE=1`, `PROXY_FIX=1`, `SERVE_FRONTEND=0` and `FLASK_DEBUG=0`.
- If the frontend is served from another origin, list it in `ALLOWED_ORIGINS`. It must be the same *site*, because the refresh cookie is `SameSite=Strict`.
- Add a cron job for `cleanup-workspaces`. Retention runs daily inside the worker.
