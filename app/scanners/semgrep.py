"""Semgrep adapter: runs our ruleset (app/scanners/rules) and normalizes results."""
import json
import os

from .files import Excluder
from .models import CONFIDENCE_LEVELS, Finding
from .cancel import NEVER, CancelToken
from .runner import RunnerConfig, ScannerError, find_tool, run_tool, tool_version

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
_SEVERITY_FALLBACK = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def version(cfg: RunnerConfig, work_dir: str) -> str | None:
    exe = find_tool("semgrep", cfg)
    return tool_version("semgrep", [exe, "--version", "--disable-version-check"], cfg, work_dir) if exe else None


def scan(source_dir: str, work_dir: str, excluder: Excluder, cfg: RunnerConfig, *, timeout: int, jobs: int,
         max_memory_mb: int, extra_configs: list[str], cancel: CancelToken = NEVER) -> tuple[list[Finding], list[dict]]:
    exe = find_tool("semgrep", cfg)
    if not exe:
        raise ScannerError("semgrep", "Semgrep is not installed (run scripts/install-scanners.sh)")
    args = [
        exe, "scan", "--config", RULES_DIR, *sum((["--config", c] for c in extra_configs), []),
        "--json", "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--oss-only",
        # A scanned repository must not be able to hide its own findings:
        "--disable-nosem", "--x-ignore-semgrepignore-files", "--no-git-ignore",
        "--timeout", "30", "--timeout-threshold", "3", "--max-target-bytes", str(1024 * 1024),
        "--jobs", str(jobs), "--max-memory", str(max_memory_mb), "--quiet",
        *excluder.semgrep_args(), ".",
    ]
    res = run_tool("semgrep", args, cwd=source_dir, work_dir=work_dir, timeout=timeout, cfg=cfg,
                   env={"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}, cancel=cancel)
    try:
        with open(res.stdout_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        raise ScannerError("semgrep", f"Semgrep failed (exit {res.returncode}): {res.stderr_tail.strip()[-500:]}")

    findings = [_normalize(r) for r in data.get("results", [])]
    errors = [
        {"scanner": "semgrep", "message": (e.get("message") or e.get("type") or "error")[:300],
         "path": (e.get("path") or "").removeprefix("./") or None}
        for e in data.get("errors", []) if e.get("level", "error") == "error"
    ]
    return findings, errors


def _normalize(r: dict) -> Finding:
    extra = r.get("extra", {})
    meta = extra.get("metadata", {}) or {}
    severity = (meta.get("aca_severity") or _SEVERITY_FALLBACK.get(extra.get("severity"), "medium")).lower()
    confidence = CONFIDENCE_LEVELS.get(str(meta.get("aca_confidence", "medium")).lower(), 0.7)
    cwe = meta.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    owasp = meta.get("owasp")
    if isinstance(owasp, list):
        owasp = owasp[0] if owasp else None
    message = " ".join((extra.get("message") or "").split())
    return Finding(
        scanner="semgrep",
        rule_id=r["check_id"],
        title=meta.get("title") or r["check_id"],
        category=meta.get("category") or "Security",
        severity=severity,
        confidence=confidence,
        file=r["path"].removeprefix("./"),
        line_start=r.get("start", {}).get("line"),
        line_end=r.get("end", {}).get("line"),
        message=message,
        description=message,
        recommendation=" ".join((meta.get("recommendation") or "").split()) or None,
        cwe=str(cwe).split(":")[0] if cwe else None,
        owasp=str(owasp).split(" ")[0] if owasp else None,
        references=list(meta.get("references") or []),
    )
