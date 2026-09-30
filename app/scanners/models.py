"""Normalized scanner output (PRD §11, §28). Every scanner maps into these."""
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_LEVELS = {"high": 0.9, "medium": 0.7, "low": 0.4}


@dataclass
class Finding:
    scanner: str  # semgrep | gitleaks | osv
    rule_id: str
    title: str
    category: str
    severity: str  # critical | high | medium | low | info
    confidence: float  # 0..1, scanner confidence before AI analysis
    file: str  # path relative to the source root, "/" separated
    line_start: int | None
    line_end: int | None
    message: str
    description: str | None = None
    recommendation: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    code_snippet: str | None = None
    snippet_start_line: int | None = None
    code_context: str | None = None        # ±12 lines, masked, for the code viewer
    context_start_line: int | None = None
    references: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)  # scanner-specific evidence (secrets already masked)
    function: str | None = None  # enclosing function, found during AI context extraction
    ai: dict | None = None       # AI analysis result (app/ai), advisory only

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Vulnerability:
    id: str
    aliases: list[str]
    summary: str | None
    severity: str
    cvss_score: float | None
    affected_range: str | None
    fixed_versions: list[str]
    references: list[str]


@dataclass
class Dependency:
    ecosystem: str  # PyPI | npm | Packagist | Go | Maven
    name: str
    version: str | None  # exact version, or None when only a range is declared
    manifest: str  # relative path
    line: int | None = None
    scope: str = "runtime"  # runtime | dev
    direct: bool = True
    declared: str | None = None  # original specifier when not pinned
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    recommended_version: str | None = None


@dataclass
class ProjectInfo:
    languages: list[dict]  # [{"name": "Python", "files": 12, "bytes": 3400, "percent": 81.2}]
    primary_language: str | None
    frameworks: list[str]
    manifests: list[str]
    file_count: int
    total_bytes: int
    # Minified / vendored third-party files: skipped by code analysis (still scanned for secrets).
    vendored_files: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    project: ProjectInfo
    findings: list[Finding]
    dependencies: list[Dependency]
    scanner_versions: dict[str, str]
    errors: list[dict]  # [{"scanner": "semgrep", "message": "..."}]
    removed_control_files: list[str] = field(default_factory=list)
    durations: dict[str, float] = field(default_factory=dict)
    failed_scanners: list[str] = field(default_factory=list)
    enabled_scanners: list[str] = field(default_factory=list)
