"""Scanner engine (PRD §10-§11, §21): detect the project, run Semgrep, Gitleaks and
dependency analysis in parallel, and normalize everything into one ScanResult.

    result = run_scan(source_dir, work_dir, settings, ScanConfig.from_app(current_app))

The engine has no database access and no Flask dependency beyond ScanConfig.from_app,
so it can run in a worker process (Sprint 4).
"""
import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import gitleaks, semgrep
from .cancel import NEVER, Cancelled, CancelToken
from .dependencies import OSVClient, OSVError, collect_dependencies, enrich
from .detect import detect_project
from .files import Excluder, remove_scanner_control_files, safe_read_lines
from .masking import mask_secrets, mask_span, mask_string_literals
from .models import SEVERITY_ORDER, Dependency, Finding, ScanResult
from .runner import RunnerConfig, ScannerError

SNIPPET_CONTEXT = 3          # short excerpt shown in lists
VIEWER_CONTEXT = 12          # larger excerpt stored for the code viewer (source is deleted after the audit)
SNIPPET_MAX_LINES = 30
VIEWER_MAX_LINES = 60
SNIPPET_MAX_LINE_LENGTH = 400
ALL_SCANNERS = ("semgrep", "gitleaks", "dependencies")


@dataclass
class ScanConfig:
    runner: RunnerConfig
    semgrep_timeout: int = 900
    semgrep_jobs: int = 2
    semgrep_max_memory_mb: int = 4096
    semgrep_extra_configs: list[str] = field(default_factory=list)
    gitleaks_timeout: int = 600
    osv_enabled: bool = True
    osv_url: str = "https://api.osv.dev"
    osv_timeout: int = 30
    osv_cache_get: object = None
    osv_cache_put: object = None

    @classmethod
    def from_app(cls, app, **overrides) -> "ScanConfig":
        c = app.config
        runner = RunnerConfig(bin_dirs=c["SCANNER_BIN_DIRS"], cpu_seconds=c["SCANNER_CPU_SECONDS"],
                              memory_mb=c["SCANNER_MEMORY_MB"], max_output_mb=c["SCANNER_MAX_OUTPUT_MB"],
                              scanner_user=c["SCANNER_USER"])
        return cls(runner=runner, semgrep_timeout=c["SEMGREP_TIMEOUT"], semgrep_jobs=c["SEMGREP_JOBS"],
                   semgrep_max_memory_mb=c["SEMGREP_MAX_MEMORY_MB"],
                   semgrep_extra_configs=c["SEMGREP_EXTRA_CONFIGS"], gitleaks_timeout=c["GITLEAKS_TIMEOUT"],
                   osv_enabled=c["OSV_ENABLED"], osv_url=c["OSV_API_URL"], osv_timeout=c["OSV_TIMEOUT"],
                   **overrides)


def scanner_versions(cfg: ScanConfig, work_dir: str) -> dict[str, str]:
    from .rules_info import rules_version
    versions = {"rules": rules_version()}
    for name, fn in (("semgrep", semgrep.version), ("gitleaks", gitleaks.version)):
        v = fn(cfg.runner, work_dir)
        if v:
            versions[name] = v
    if cfg.osv_enabled:
        versions["osv"] = "api.osv.dev/v1"
    return versions


def _noop_progress(stage: str, state: str, detail: str | None = None) -> None:
    pass


def run_scan(source_dir: str, work_dir: str, settings: dict, cfg: ScanConfig, *,
             progress: Callable[[str, str, str | None], None] = _noop_progress,
             cancel: CancelToken = NEVER) -> ScanResult:
    """Scan an already-acquired source tree. `settings` is repositories.settings.

    progress(stage, state, detail) is called for the stages "detecting", "scanning"
    (Semgrep + Gitleaks) and "dependency_analysis" with state running | completed |
    failed | skipped. Raises Cancelled if `cancel` fires (running tools are killed).
    """
    t0 = time.monotonic()
    enabled = set(settings.get("enabled_scanners") or ALL_SCANNERS)
    excluder = Excluder(settings.get("excluded_paths") or [])
    threshold = SEVERITY_ORDER.get(settings.get("severity_threshold", "info"), 0)
    tool_dir = os.path.join(work_dir, "tools")
    os.makedirs(tool_dir, mode=0o700, exist_ok=True)

    progress("detecting", "running")
    removed = remove_scanner_control_files(source_dir)
    project = detect_project(source_dir, excluder)
    durations = {"detect": round(time.monotonic() - t0, 2)}
    progress("detecting", "completed", " / ".join(project.frameworks[:2] + [project.primary_language or "Unknown"]))
    cancel.raise_if_cancelled()

    errors: list[dict] = []
    findings: list[Finding] = []
    dependencies: list[Dependency] = []

    def timed(name, fn):
        start = time.monotonic()
        try:
            return fn()
        finally:
            durations[name] = round(time.monotonic() - start, 2)

    code_scanners = [n for n in ("semgrep", "gitleaks") if n in enabled]
    progress("scanning", "running" if code_scanners else "skipped", None if code_scanners else "Not enabled")
    progress("dependency_analysis", "running" if "dependencies" in enabled else "skipped",
             None if "dependencies" in enabled else "Not enabled")

    jobs = {}
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="scanner") as pool:
        if "semgrep" in enabled:
            code_excluder = excluder.with_files(project.vendored_files)
            jobs[pool.submit(timed, "semgrep", lambda: semgrep.scan(
                source_dir, tool_dir, code_excluder, cfg.runner, timeout=cfg.semgrep_timeout, jobs=cfg.semgrep_jobs,
                max_memory_mb=cfg.semgrep_max_memory_mb, extra_configs=cfg.semgrep_extra_configs,
                cancel=cancel))] = "semgrep"
        if "gitleaks" in enabled:
            jobs[pool.submit(timed, "gitleaks", lambda: gitleaks.scan(
                source_dir, tool_dir, excluder, cfg.runner, timeout=cfg.gitleaks_timeout, cancel=cancel))] = "gitleaks"
        if "dependencies" in enabled:
            jobs[pool.submit(timed, "dependencies",
                             lambda: _dependencies(source_dir, excluder, cfg, cancel))] = "dependencies"
        versions = scanner_versions(cfg, tool_dir)

        failed: set[str] = set()
        pending_code = set(code_scanners)
        cancelled: Cancelled | None = None
        for job in as_completed(jobs):
            name = jobs[job]
            try:
                out = job.result()
            except Cancelled as err:
                cancelled = err
                continue
            except ScannerError as err:
                errors.append({"scanner": err.scanner, "message": err.message})
                failed.add(name)
                out = None
            if out is not None and name == "semgrep":
                sg_findings, sg_errors = out
                findings += [_with_snippet(f, source_dir) for f in sg_findings]
                errors += sg_errors
            elif out is not None and name == "gitleaks":
                findings += [_secret_finding(rec, source_dir) for rec in out]
            elif out is not None:
                dependencies, dep_errors = out
                errors += dep_errors
                findings += [_with_snippet(f, source_dir) for f in dependency_findings(dependencies)]

            if name == "dependencies":
                vulnerable = sum(1 for d in dependencies if d.vulnerabilities)
                progress("dependency_analysis", "failed" if name in failed else "completed",
                         "Failed" if name in failed else f"{len(dependencies)} dependencies, {vulnerable} vulnerable")
            else:
                pending_code.discard(name)
                if not pending_code:
                    code_count = sum(1 for f in findings if f.scanner in ("semgrep", "gitleaks"))
                    state = "failed" if failed >= set(code_scanners) else "completed"
                    progress("scanning", state, "Failed" if state == "failed" else f"{code_count} issues found")
        if cancelled:
            raise cancelled

    findings = [f for f in _dedupe(findings) if SEVERITY_ORDER.get(f.severity, 0) >= threshold]
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line_start or 0, f.rule_id))
    durations["total"] = round(time.monotonic() - t0, 2)
    return ScanResult(project=project, findings=findings, dependencies=dependencies, scanner_versions=versions,
                      errors=errors, removed_control_files=removed, durations=durations,
                      failed_scanners=sorted(failed), enabled_scanners=sorted(enabled & set(ALL_SCANNERS)))


def _dependencies(source_dir: str, excluder: Excluder, cfg: ScanConfig, cancel: CancelToken = NEVER):
    deps, errors = collect_dependencies(source_dir, excluder)
    cancel.raise_if_cancelled()
    if cfg.osv_enabled and deps:
        client = OSVClient(cfg.osv_url, cfg.osv_timeout, cfg.osv_cache_get, cfg.osv_cache_put)
        try:
            enrich(deps, client, cancel)
        except OSVError as err:
            errors.append({"scanner": "osv", "message": f"{err} — dependencies listed without vulnerability data"})
        cancel.raise_if_cancelled()
    return deps, errors


# ---- snippets & masking ----

def _snippet(source_dir: str, file: str, start: int | None, end: int | None, *, secret_span=None,
             mask_literals: bool = False, context: int = SNIPPET_CONTEXT,
             max_lines: int = SNIPPET_MAX_LINES) -> tuple[str | None, int | None]:
    if not start:
        return None, None
    lines = safe_read_lines(source_dir, file)
    if lines is None:
        return None, None
    end = end or start
    first = max(1, start - context)
    last = min(len(lines), end + context, first + max_lines - 1)
    out = []
    for n in range(first, last + 1):
        line = lines[n - 1]
        if secret_span and secret_span[0] <= n <= secret_span[1]:
            s_line, e_line, s_col, e_col = secret_span
            if s_line == e_line and s_col and e_col:
                line = mask_span(line, s_col, e_col)  # exact columns reported by Gitleaks
            else:
                line = "****"  # multi-line secret (e.g. a private key): hide every line of it
        elif mask_literals and start <= n <= end:
            line = mask_string_literals(line)
        if len(line) > SNIPPET_MAX_LINE_LENGTH:
            line = line[:SNIPPET_MAX_LINE_LENGTH] + " …"
        out.append(line)
    return mask_secrets("\n".join(out)), first


def _with_snippet(f: Finding, source_dir: str) -> Finding:
    literals = f.category == "Secrets"
    f.code_snippet, f.snippet_start_line = _snippet(source_dir, f.file, f.line_start, f.line_end,
                                                    mask_literals=literals)
    f.code_context, f.context_start_line = _snippet(source_dir, f.file, f.line_start, f.line_end,
                                                    mask_literals=literals, context=VIEWER_CONTEXT,
                                                    max_lines=VIEWER_MAX_LINES)
    return f


def _secret_finding(rec: dict, source_dir: str) -> Finding:
    f = gitleaks.normalize(rec)
    span = (rec.get("StartLine"), rec.get("EndLine") or rec.get("StartLine"), rec.get("StartColumn"), rec.get("EndColumn"))
    f.code_snippet, f.snippet_start_line = _snippet(source_dir, f.file, f.line_start, f.line_end, secret_span=span)
    f.code_context, f.context_start_line = _snippet(source_dir, f.file, f.line_start, f.line_end, secret_span=span,
                                                    context=VIEWER_CONTEXT, max_lines=VIEWER_MAX_LINES)
    return f


# ---- dependency findings ----

def dependency_findings(deps: list[Dependency]) -> list[Finding]:
    """One finding per vulnerability per dependency (PRD §21 fields in `extra`)."""
    out = []
    for dep in deps:
        for v in dep.vulnerabilities:
            fix = dep.recommended_version or (v.fixed_versions[0] if v.fixed_versions else None)
            out.append(Finding(
                scanner="osv",
                rule_id=v.id,
                title=f"Vulnerable dependency: {dep.name} {dep.version} ({v.id})",
                category="Dependencies",
                severity=v.severity,
                confidence=0.9,  # exact version match against a curated advisory database
                file=dep.manifest,
                line_start=dep.line,
                line_end=dep.line,
                message=v.summary or f"{dep.name} {dep.version} is affected by {v.id}.",
                description=v.summary,
                recommendation=(f"Upgrade {dep.name} to {fix} or later." if fix
                                else f"No fixed version of {dep.name} is published yet; consider an alternative or mitigations."),
                cwe=None,
                owasp="A06:2021",
                references=v.references,
                extra={"package": dep.name, "ecosystem": dep.ecosystem, "current_version": dep.version,
                       "affected_range": v.affected_range, "vulnerability": v.id, "aliases": v.aliases,
                       "cvss_score": v.cvss_score, "recommended_version": fix, "scope": dep.scope,
                       "direct": dep.direct},
            ))
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Same rule at the same place reported twice (e.g. overlapping patterns) → keep one.
    A Semgrep hard-coded-credential finding on a line Gitleaks also flagged → keep Gitleaks'."""
    secret_lines = {(f.file, f.line_start) for f in findings if f.scanner == "gitleaks"}
    seen, out = set(), []
    for f in findings:
        if f.scanner == "semgrep" and f.category == "Secrets" and (f.file, f.line_start) in secret_lines:
            continue
        key = (f.scanner, f.rule_id, f.file, f.line_start, f.extra.get("package"))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
