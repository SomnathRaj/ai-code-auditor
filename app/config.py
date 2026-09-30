import os
import tempfile
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _origins(name: str) -> list[str]:
    return [o.strip().rstrip("/") for o in os.environ.get(name, "").split(",") if o.strip()]


class Config:
    # Access tokens (PRD §43.3)
    JWT_SECRET = os.environ.get("JWT_SECRET")
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_TTL = timedelta(minutes=int(os.environ.get("ACCESS_TOKEN_MINUTES", "15")))

    # Refresh tokens
    REFRESH_TOKEN_TTL = timedelta(days=int(os.environ.get("REFRESH_TOKEN_DAYS", "7")))
    # A rotated refresh token presented again within this window is treated as a
    # concurrent refresh (e.g. two tabs loading), not as token theft.
    REFRESH_REUSE_GRACE = timedelta(seconds=30)
    REFRESH_COOKIE_NAME = "aca_refresh"
    REFRESH_COOKIE_PATH = "/api/v1/auth"
    COOKIE_SECURE = _bool("COOKIE_SECURE")
    ALLOWED_ORIGINS = _origins("ALLOWED_ORIGINS")

    # MongoDB (PRD §41)
    MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017")
    MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "ai_code_auditor")
    MONGO_TIMEOUT_MS = 5000

    SERVE_FRONTEND = _bool("SERVE_FRONTEND", True)
    FRONTEND_DIR = str(ROOT_DIR / "frontend")
    PROXY_FIX = _bool("PROXY_FIX")

    # Fernet keys (comma-separated, newest first) for access tokens and stored
    # source archives. Older keys stay readable, enabling key rotation.
    ENCRYPTION_KEYS = [k.strip() for k in os.environ.get("ENCRYPTION_KEYS", "").split(",") if k.strip()]

    # Source acquisition (Sprint 2)
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "100")) * 1024 * 1024  # ZIP upload size
    MAX_SOURCE_BYTES = int(os.environ.get("MAX_SOURCE_MB", "500")) * 1024 * 1024  # extracted / cloned size
    MAX_SOURCE_FILES = int(os.environ.get("MAX_SOURCE_FILES", "50000"))
    ZIP_MAX_COMPRESSION_RATIO = 200  # per entry; zip-bomb guard for entries over 1 MB
    WORK_DIR = os.environ.get("WORK_DIR") or os.path.join(tempfile.gettempdir(), "ai-code-auditor")
    GIT_CLONE_TIMEOUT = int(os.environ.get("GIT_CLONE_TIMEOUT", "300"))
    GIT_REMOTE_TIMEOUT = int(os.environ.get("GIT_REMOTE_TIMEOUT", "30"))
    GIT_ALLOWED_PROTOCOLS = ("https",)

    # Scanner engine (Sprint 3). Tools come from .tools/bin and the virtualenv (scripts/install-scanners.sh).
    SCANNER_BIN_DIRS = [str(ROOT_DIR / ".tools" / "bin")]  # semgrep (own venv, linked) and gitleaks
    SCANNER_CPU_SECONDS = int(os.environ.get("SCANNER_CPU_SECONDS", "1800"))
    SCANNER_MEMORY_MB = int(os.environ.get("SCANNER_MEMORY_MB", "6144"))  # enforced on Linux
    SCANNER_MAX_OUTPUT_MB = int(os.environ.get("SCANNER_MAX_OUTPUT_MB", "512"))
    SCANNER_USER = os.environ.get("SCANNER_USER") or None  # required if the app runs as root
    SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", "900"))
    SEMGREP_JOBS = int(os.environ.get("SEMGREP_JOBS", str(min(4, os.cpu_count() or 2))))
    SEMGREP_MAX_MEMORY_MB = int(os.environ.get("SEMGREP_MAX_MEMORY_MB", "4096"))
    # Opt-in extra Semgrep configs (e.g. "p/default"). Registry rules are under the Semgrep Rules
    # License, which restricts use in competing products — review before enabling.
    SEMGREP_EXTRA_CONFIGS = [c.strip() for c in os.environ.get("SEMGREP_EXTRA_CONFIGS", "").split(",") if c.strip()]
    GITLEAKS_TIMEOUT = int(os.environ.get("GITLEAKS_TIMEOUT", "600"))
    OSV_ENABLED = _bool("OSV_ENABLED", True)
    OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev")
    OSV_TIMEOUT = int(os.environ.get("OSV_TIMEOUT", "30"))
    OSV_CACHE_HOURS = 24

    # AI analysis (Sprint 5) — Google Gemini (PRD §64). Without GEMINI_API_KEY the stage is skipped.
    AI_ENABLED = _bool("AI_ENABLED", True)
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or None
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
    GEMINI_BASE_URL = os.environ.get("GEMINI_BASE_URL") or None  # e.g. an egress proxy; default: Google
    AI_MIN_SEVERITY = os.environ.get("AI_MIN_SEVERITY", "medium")
    AI_MAX_FINDINGS = int(os.environ.get("AI_MAX_FINDINGS", "50"))  # per audit, most severe first
    AI_CONCURRENCY = int(os.environ.get("AI_CONCURRENCY", "4"))
    AI_MAX_RETRIES = int(os.environ.get("AI_MAX_RETRIES", "2"))
    # Client-side pacing; 0 = learn the limit from Gemini's rate-limit responses (free tier: 15/min).
    AI_REQUESTS_PER_MINUTE = int(os.environ.get("AI_REQUESTS_PER_MINUTE", "0"))
    AI_TIMEOUT_SECONDS = float(os.environ.get("AI_TIMEOUT_SECONDS", "60"))
    AI_CONTEXT_MAX_LINES = int(os.environ.get("AI_CONTEXT_MAX_LINES", "120"))
    AI_CACHE_DAYS = int(os.environ.get("AI_CACHE_DAYS", "30"))

    # Rate limiting (Sprint 8), stored in MongoDB. RATE_LIMITS overrides app.services.rate_limit.DEFAULT_LIMITS.
    RATE_LIMIT_ENABLED = _bool("RATE_LIMIT_ENABLED", True)
    # Data retention (Sprint 8): per-organization settings live on the organization; this one is server-wide.
    AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", "365"))  # 0 = keep forever
    RATE_LIMITS: dict = {}

    # Audit worker (Sprint 4). "embedded": runs inside the web process (started on the first
    # request); "external": run `flask --app run worker` separately; "off": no processing.
    AUDIT_WORKER = os.environ.get("AUDIT_WORKER", "embedded")
    WORKER_CONCURRENCY = int(os.environ.get("WORKER_CONCURRENCY", "2"))
    WORKER_POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "2"))
    WORKER_HEARTBEAT_SECONDS = float(os.environ.get("WORKER_HEARTBEAT_SECONDS", "5"))
    WORKER_STALE_SECONDS = int(os.environ.get("WORKER_STALE_SECONDS", "120"))
    AUDIT_TIMEOUT_SECONDS = int(os.environ.get("AUDIT_TIMEOUT_SECONDS", "3600"))
    AUDIT_MAX_ATTEMPTS = int(os.environ.get("AUDIT_MAX_ATTEMPTS", "2"))

    # Security score deductions per open finding (PRD §49).
    SCORE_WEIGHTS = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
