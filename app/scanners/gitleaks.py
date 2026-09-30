"""Gitleaks adapter: secret detection with secrets redacted in the tool output (PRD §18)."""
import json
import os

from .files import Excluder
from .models import Finding
from .cancel import NEVER, CancelToken
from .runner import RunnerConfig, ScannerError, find_tool, run_tool, tool_version

BASE_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gitleaks.toml")

CRITICAL_RULES = ("private-key", "aws", "gcp", "azure", "github", "gitlab", "stripe", "slack", "twilio",
                  "sendgrid", "openai", "anthropic", "heroku", "digitalocean", "npm-access-token", "pypi")
LOW_CONFIDENCE_RULES = ("generic-api-key", "generic", "hashicorp-tf-password")
_WORDS = {"aws": "AWS", "gcp": "GCP", "api": "API", "jwt": "JWT", "github": "GitHub", "gitlab": "GitLab",
          "pat": "PAT", "npm": "npm", "pypi": "PyPI", "ssh": "SSH", "id": "ID", "url": "URL", "oauth": "OAuth",
          "openai": "OpenAI", "sendgrid": "SendGrid", "digitalocean": "DigitalOcean"}


def version(cfg: RunnerConfig, work_dir: str) -> str | None:
    exe = find_tool("gitleaks", cfg)
    return tool_version("gitleaks", [exe, "version"], cfg, work_dir) if exe else None


def _config_file(work_dir: str, excluder: Excluder) -> str:
    """Our base config plus this audit's excluded paths. Passed explicitly with --config so a
    repository's own .gitleaks.toml is never used."""
    with open(BASE_CONFIG, encoding="utf-8") as fh:
        text = fh.read()
    paths = excluder.gitleaks_path_regexes()
    if paths:
        quoted = ", ".join("'''" + p + "'''" for p in paths)
        text += f'\n[[allowlists]]\ndescription = "Excluded by audit settings"\npaths = [{quoted}]\n'
    path = os.path.join(work_dir, "gitleaks.toml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def scan(source_dir: str, work_dir: str, excluder: Excluder, cfg: RunnerConfig, *, timeout: int,
         cancel: CancelToken = NEVER) -> list[dict]:
    """Returns raw (already redacted) gitleaks records; the engine builds masked snippets."""
    exe = find_tool("gitleaks", cfg)
    if not exe:
        raise ScannerError("gitleaks", "Gitleaks is not installed (run scripts/install-scanners.sh)")
    empty_ignore_dir = os.path.join(work_dir, "gitleaks-ignore")
    os.makedirs(empty_ignore_dir, mode=0o700, exist_ok=True)
    report = os.path.join(work_dir, "gitleaks.json")
    args = [
        exe, "dir", ".", "--config", _config_file(work_dir, excluder),
        "--gitleaks-ignore-path", empty_ignore_dir, "--ignore-gitleaks-allow",
        "--redact=100", "--no-banner", "--no-color", "--log-level", "error", "--exit-code", "0",
        "--max-target-megabytes", "5", "--report-format", "json", "--report-path", report,
    ]
    res = run_tool("gitleaks", args, cwd=source_dir, work_dir=work_dir, timeout=timeout, cfg=cfg, cancel=cancel)
    if res.returncode != 0:
        raise ScannerError("gitleaks", f"Gitleaks failed (exit {res.returncode}): {res.stderr_tail.strip()[-500:]}")
    try:
        with open(report, encoding="utf-8") as fh:
            records = json.load(fh) or []
    except (OSError, ValueError):
        raise ScannerError("gitleaks", "Gitleaks produced no readable report")
    for rec in records:  # never keep secret material, even if redaction was bypassed
        rec["Secret"] = rec["Match"] = "REDACTED"
    return records


def humanize(rule_id: str) -> str:
    words = rule_id.replace("_", "-").split("-")
    return " ".join(_WORDS.get(w, w) for w in words if w).strip().capitalize() if words else rule_id


def normalize(rec: dict) -> Finding:
    rule = rec.get("RuleID", "secret")
    lower = rule.lower()
    # Cloud/provider credentials and private keys give direct access: critical (PRD §18 example).
    severity = "critical" if any(p in lower for p in CRITICAL_RULES) else "high"
    confidence = 0.4 if any(lower.startswith(p) for p in LOW_CONFIDENCE_RULES) else 0.85
    kind = humanize(rule)
    return Finding(
        scanner="gitleaks",
        rule_id=rule,
        title=f"Exposed secret: {kind}",
        category="Secrets",
        severity=severity,
        confidence=confidence,
        file=rec.get("File", "").removeprefix("./"),
        line_start=rec.get("StartLine"),
        line_end=rec.get("EndLine"),
        message=rec.get("Description") or f"Possible {kind} found in source code.",
        description=(rec.get("Description") or "") + " The value is masked here and is never stored.",
        recommendation=("Treat the credential as compromised: revoke or rotate it, remove it from the code "
                        "(and the Git history), and load it from an environment variable or secret manager."),
        cwe="CWE-798",
        owasp="A07:2021",
        extra={"entropy": round(float(rec.get("Entropy") or 0), 2), "gitleaks_fingerprint_rule": rule,
               "columns": [rec.get("StartColumn"), rec.get("EndColumn")]},
    )
