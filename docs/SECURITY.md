# Security Review

Sprint 8 review of AI Code Auditor against the PRD threat model (§80). For each threat it lists the controls in place, where they are implemented, and the risks that remain.

Last reviewed: 2026-09-30 (Sprint 8).

---

## 1. Scanner isolation: malicious repositories (§80)

Every repository is assumed to be hostile. The platform **never executes repository code**: no builds, no dependency installs, no scripts, no Dockerfiles. Analysis is static only.

| Threat | Control | Where |
|---|---|---|
| Malicious scripts, build commands or Dockerfiles | Nothing from the repository is executed. Semgrep, Gitleaks and OSV only read files. | `app/scanners/*` |
| Malicious dependencies | Manifests and lockfiles are parsed as text. Versions are looked up on OSV.dev; nothing is installed. | `app/scanners/dependencies/` |
| Symlinks pointing outside the checkout | Git runs with `core.symlinks=false`, so symlinks are checked out as plain files. Any symlink that still appears is deleted before scanning. ZIP extraction rejects symlink entries. | `git_client.py`, `workspace.py::_measure`, `source_archive.py` |
| Path traversal in ZIP archives | Entry names are normalised, and absolute paths or paths containing `..` are rejected. | `source_archive.py` |
| Zip bombs or huge repositories | Upload limit (`MAX_UPLOAD_MB`). Limits on extracted size and file count (`MAX_SOURCE_MB`, `MAX_SOURCE_FILES`). Any entry over 1 MB with a compression ratio above 200 is rejected. | `config.py`, `workspace.py` |
| Hostile git features | Shallow clone of a single branch. No tags, submodules or LFS. Hooks are disabled and fetched objects are checked with fsck. Git config is isolated, with no system or global config and no credential helpers. Only HTTPS is allowed. Timeouts kill the whole process group. | `git_client.py` |
| Files designed to crash or exhaust scanners | Each scanner runs through the `_limits.py` watchdog. It sets CPU seconds, file size and, on Linux, address space, and disables core dumps. Output size is capped. The whole audit has a timeout (`AUDIT_TIMEOUT_SECONDS`). If the worker dies, the watchdog kills the scanner. | `app/scanners/_limits.py`, `runner.py` |
| Repository hiding its own findings | Scanner control files (`.semgrepignore`, `.gitleaksignore`, `.gitleaks.toml`) are deleted before scanning, and `nosem` / `nosemgrep` comments are disabled. Rules come from our own ruleset, never from the repository. | `files.py`, `engine.py`, `semgrep.py`, `gitleaks.toml` |
| Scanners running as root | The runner refuses to run as root unless `SCANNER_USER` is set. If it is set, privileges are dropped to that user. | `runner.py`, `_limits.py` |
| Secret values leaking into stored results | Gitleaks runs with `--redact`, and every stored snippet or message is masked again. | `app/scanners/masking.py` |
| Scanner telemetry sending source metadata to third parties | Semgrep runs with `--metrics=off --disable-version-check --oss-only`. It uses the local ruleset only; the Semgrep Registry is not used, because of its licence. | `semgrep.py` |

### Residual risks

- **No network sandbox.** Without containers (a project constraint), scanner processes could reach the network. None of the scanners fetch anything the repository asks for, but an exploit in a scanner would run with the worker user's network access. **Recommended mitigations:**
  - Run the worker as a dedicated, unprivileged system user (`SCANNER_USER`, or the worker's own user).
  - Block that user's outbound traffic except to MongoDB, `api.osv.dev`, `github.com` and the Gemini endpoint. Use nftables/iptables owner matching, or route through an egress proxy (`GEMINI_BASE_URL` supports one).
- **No filesystem sandbox.** Scanners can read anything the worker user can read. Keep `.env`, and anything else secret, readable only by the web user, not the scanner user. Workspaces are created with mode 0700 under `WORK_DIR`. The app refuses to use `WORK_DIR` if it is a symlink, is owned by another user, or is group- or world-accessible.
- **Memory limits on macOS.** `RLIMIT_AS` is not enforced on macOS; only the CPU and file-size limits apply. Linux is the supported production platform.
- **Scanner vulnerabilities.** Keep Semgrep and Gitleaks up to date: re-run `scripts/install-scanners.sh`. Semgrep has its own virtualenv (`.tools/semgrep-venv`), so its dependency pins can't hold back the app's dependencies.

---

## 2. Malicious users (§80)

| Threat | Control |
|---|---|
| Cross-tenant access | Every organisation-owned query is scoped by `organization_id` from the verified token (`current_identity().org_id`). Membership is re-checked on every request, so a removed member loses access immediately. IDs from other tenants return 404, not 403. Covered in `tests/test_repositories.py`, `tests/test_audit_pipeline.py` and `tests/test_security.py`. |
| Privilege escalation | Roles are checked on the server (`require_role`). Admins can't add, change or remove owners or admins. The last owner can't be demoted, removed or leave. The role change is an atomic `$elemMatch` update with a post-check. |
| Repository credential theft | GitHub tokens are encrypted at rest (see §3) and never returned by the API, logged, placed in URLs or passed in argv. Git receives them through `GIT_CONFIG_*` environment variables, and the header is scoped to `https://github.com/`. |
| SSRF | Repositories can only be GitHub URLs parsed into `owner/name` and rebuilt as `https://github.com/{owner}/{name}`. Users cannot supply arbitrary hosts. Outbound calls go only to fixed endpoints (GitHub, OSV.dev, Gemini). |
| File traversal (code viewer) | The code viewer never reads files. It shows the masked excerpt stored with the finding at scan time, and source is deleted after each audit. Scan output only contains paths relative to the workspace. |
| Scanner abuse and resource exhaustion | One active audit per repository (partial unique index). Rate limits (see below). Worker concurrency limit. Resource limits on scanners. Upload size cap. |
| Brute force and credential stuffing | Login is limited per IP (`login_ip`, 20/min). Failed logins are also limited per email across all IPs (`login_fail`, 10 per 15 min), and hitting that limit is written to the activity log. Passwords are hashed with scrypt (Werkzeug), and unknown emails are checked against a dummy hash so response timing doesn't reveal which accounts exist. |
| CSRF | The API is authenticated by a bearer token held in memory, not a cookie. The two endpoints that read the refresh cookie (`/auth/refresh`, `/auth/logout`) require `X-Requested-With: fetch` and an allowed `Origin`. The cookie is `HttpOnly; SameSite=Strict; Path=/api/v1/auth`. |
| Session theft | Access tokens last 15 minutes. Refresh tokens rotate on every use, and reusing an old one outside the grace window revokes the whole token family. |
| XSS | The frontend builds DOM nodes with `textContent`, never `innerHTML` with data. A strict Content-Security-Policy (`default-src 'self'`) blocks inline and third-party scripts. |

### Rate limits

Fixed windows are counted in MongoDB (`rate_limits`, with a TTL index), so all gunicorn workers share the same counters. When a limit is hit, the API returns `429 rate_limited` with `Retry-After` and `X-RateLimit-*` headers.

| Name | Key | Limit |
|---|---|---|
| `login_ip` | client IP | 20 / minute |
| `login_fail` | email | 10 failures / 15 minutes |
| `register_ip` | client IP | 10 / hour |
| `refresh_ip` | client IP | 120 / minute |
| `audit_start` | organisation | 30 / hour |
| `upload` | organisation | 30 / hour |
| `report` | user | 30 / 10 minutes |
| `comment` | user | 60 / 10 minutes |
| `api_user` | user | 1200 / minute (all authenticated calls) |

Limits can be overridden with `RATE_LIMITS` in config, and the limiter can be turned off with `RATE_LIMIT_ENABLED=0` (the tests do this). Behind Nginx, `PROXY_FIX=1` must be set so that the client IP comes from `X-Forwarded-For`. Without it, every request appears to come from 127.0.0.1 and IP limits apply to everyone together.

---

## 3. Credential and data encryption review

- **Algorithm:** Fernet (AES-128-CBC with HMAC-SHA256, authenticated) via `cryptography`'s `MultiFernet`.
- **What is encrypted:** GitHub access tokens, and uploaded ZIP archives stored in GridFS. Archives are encrypted in 4 MB chunks, and a plaintext SHA-256 is checked on read to detect reordered or truncated chunks.
- **Keys:** `ENCRYPTION_KEYS`, comma-separated, is read from `.env` only. The first key encrypts; every key can decrypt. The app refuses to start without a valid key.
- **Rotation:**
  1. Generate a key:
     ```
     python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
     ```
  2. Put the new key first: `ENCRYPTION_KEYS=new,old`.
  3. Restart the web app and the worker.
  4. Run `flask --app run rotate-encryption-key`. It re-encrypts every token and archive with the new key and verifies each archive's checksum.
  5. Remove the old key and restart again.

  This is covered end to end by `tests/test_security.py::test_key_rotation`.
- **Other secrets:**
  - `JWT_SECRET` signs access tokens (HS256, a single allowed algorithm).
  - Refresh tokens are stored only as SHA-256 hashes.
  - Passwords are hashed with scrypt (Werkzeug), and unknown emails are checked against a dummy hash so response timing doesn't reveal which accounts exist.
  - The Gemini API key is used only in a request header and is never logged.
- **Not encrypted:** findings, code snippets and audit metadata are stored in MongoDB in plain text. Protect MongoDB with authentication, network isolation and disk encryption. Source code is confidential customer data (§80).

---

## 4. Application security review (dogfooding)

The app was scanned with itself (Semgrep + Gitleaks + OSV) during Sprint 8.

| Scanner | Result | Action |
|---|---|---|
| Semgrep (64 rules) | 0 findings in `app/` | None |
| Gitleaks | 7 secrets, all fake credentials in `tests/` fixtures that exist to test the secret scanner | Expected. Mark them *false positive* or *accepted risk* when auditing this repository. |
| OSV | PyJWT 2.13.0: 10 advisories, including GHSA-ffc3-869f-jxw9 | Not exploitable in our usage (fixed HS256 with a raw secret, `algorithms=["HS256"]`), but upgraded to **2.15.1**. `requirements.txt` now has version floors that exclude releases with known advisories, and `requirements.lock` pins exact versions. |

Semgrep's own dependency pins (`pyjwt~=2.13.0`) blocked the upgrade. The fix was to move Semgrep into its own virtualenv (`.tools/semgrep-venv`), linked from `.tools/bin/semgrep`.

### Security headers

Every response carries:

- `Content-Security-Policy` (`default-src 'self'`, so no inline or third-party scripts)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: same-origin`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cache-Control: no-store` on API responses

`Strict-Transport-Security` is added only when the request arrived over HTTPS. Behind Nginx this requires `PROXY_FIX=1` and `X-Forwarded-Proto`.

### Activity log

Security-relevant events are written to `audit_logs`:

- logins, failed logins and lockouts;
- registration, token-reuse detection;
- organisation changes;
- member added, role changed, member removed or left;
- repository create and delete, audit start and cancel, finding status changes;
- report downloads;
- retention runs.

Admins and owners can browse the log in **Settings → Activity log** (`GET /api/v1/audit-logs`). Entries are deleted after `AUDIT_LOG_RETENTION_DAYS` (default 365).

---

## 5. Data retention (§81)

Retention is configured per organisation in Settings, by owners only.

- **Audit results:** 7 / 30 / 90 (default) / 180 / 365 days, or forever. Each repository's latest completed audit is always kept.
- **Uploaded source:** 7 … 365 days, or until it is replaced (default).

Retention runs once a day inside the worker. It can also be run with `flask --app run retention [--dry-run]`.

Cloned source is never stored. It lives in a temporary workspace that is deleted when the audit finishes; `cleanup-workspaces` removes anything left over after a crash.
