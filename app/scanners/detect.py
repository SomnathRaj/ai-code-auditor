"""Language and framework detection (PRD §8, §9)."""
import json
import os
import re
import tomllib

from .files import Excluder, safe_read_lines, walk_files
from .models import ProjectInfo

EXTENSIONS = {
    ".py": "Python", ".pyw": "Python",
    ".php": "PHP", ".phtml": "PHP",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".java": "Java", ".go": "Go",
    ".rb": "Ruby", ".cs": "C#", ".kt": "Kotlin", ".kts": "Kotlin", ".swift": "Swift", ".rs": "Rust",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".vue": "Vue", ".svelte": "Svelte",
}
# Languages with rules in app/scanners/rules (PRD §8 MVP).
SUPPORTED = {"Python", "PHP", "JavaScript", "TypeScript", "Java", "Go"}

MANIFESTS = {
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "setup.py",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock", "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
}
_REQ_FILE = re.compile(r"^requirements[\w.-]*\.txt$")
# Bundled third-party assets that would otherwise dominate language statistics.
_VENDORED = re.compile(r"(\.min\.(js|css)$|[-.]bundle\.js$|(^|/)(vendor|vendors|bower_components|third[_-]party|"
                       r"static/(js/)?(lib|libs|vendor)|assets/(js/)?(lib|libs|vendor)|public/(js/)?vendor)/)", re.I)
_VENDORED_NAMES = re.compile(r"^(jquery|bootstrap|angular|react|vue|lodash|underscore|backbone|d3|moment|"
                             r"popper|chart|highcharts|three)([.-][\w.-]*)?\.js$", re.I)
MINIFIED_CHECK_EXTENSIONS = (".js", ".mjs", ".cjs", ".css")


def looks_minified(path: str, size: int) -> bool:
    """Heuristic: large file whose first 64 KB has very long lines (typical of minified bundles)."""
    if size < 20_000:
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
    except OSError:
        return False
    lines = head.split(b"\n")
    longest = max((len(line) for line in lines), default=0)
    return longest > 2000 or len(head) / max(len(lines), 1) > 300


FRAMEWORK_LANGUAGE = {
    "Django": "Python", "Flask": "Python", "FastAPI": "Python",
    "Laravel": "PHP", "Lumen": "PHP", "Symfony": "PHP", "CodeIgniter": "PHP", "Slim": "PHP",
    "Spring Boot": "Java", "Spring": "Java", "Gin": "Go", "Fiber": "Go", "Echo": "Go", "Chi": "Go",
}

# Framework → markers in dependency names (lower-case).
PY_FRAMEWORKS = {"django": "Django", "flask": "Flask", "fastapi": "FastAPI"}
JS_FRAMEWORKS = {"next": "Next.js", "@nestjs/core": "NestJS", "express": "Express", "react": "React",
                 "vue": "Vue", "@angular/core": "Angular", "svelte": "Svelte", "koa": "Koa", "fastify": "Fastify"}
PHP_FRAMEWORKS = {"laravel/framework": "Laravel", "laravel/lumen-framework": "Lumen", "symfony/framework-bundle": "Symfony",
                  "symfony/symfony": "Symfony", "codeigniter4/framework": "CodeIgniter", "slim/slim": "Slim"}
GO_FRAMEWORKS = {"github.com/gin-gonic/gin": "Gin", "github.com/gofiber/fiber": "Fiber",
                 "github.com/labstack/echo": "Echo", "github.com/go-chi/chi": "Chi"}
# Framework precedence when several are present (full-stack/meta frameworks first).
PRECEDENCE = ["Laravel", "Symfony", "CodeIgniter", "Lumen", "Slim", "Django", "FastAPI", "Flask",
              "Next.js", "NestJS", "Angular", "Express", "Koa", "Fastify", "React", "Vue", "Svelte",
              "Spring Boot", "Spring", "Gin", "Fiber", "Echo", "Chi"]


def is_manifest(name: str) -> bool:
    return name in MANIFESTS or bool(_REQ_FILE.match(name))


def _py_names(root: str, rel: str) -> set[str]:
    lines = safe_read_lines(root, rel) or []
    name = rel.rsplit("/", 1)[-1]
    text = "\n".join(lines).lower()
    if name == "pyproject.toml":
        try:
            data = tomllib.loads("\n".join(lines))
        except tomllib.TOMLDecodeError:
            return set()
        deps = list(data.get("project", {}).get("dependencies", []))
        deps += list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
        return {re.split(r"[\s<>=!~;\[\(]", d.strip(), maxsplit=1)[0].lower() for d in deps if d}
    return {re.split(r"[\s<>=!~;\[\(]", ln.strip(), maxsplit=1)[0].lower()
            for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(("#", "-"))}


def _json_keys(root: str, rel: str, sections: tuple[str, ...]) -> set[str]:
    lines = safe_read_lines(root, rel)
    if not lines:
        return set()
    try:
        data = json.loads("\n".join(lines))
    except ValueError:
        return set()
    names = set()
    for sec in sections:
        if isinstance(data.get(sec), dict):
            names |= {k.lower() for k in data[sec]}
    return names


def detect_project(root: str, excluder: Excluder) -> ProjectInfo:
    stats: dict[str, list[int]] = {}
    manifests, markers, vendored = [], set(), []
    file_count = total_bytes = 0

    for rel, full, st in walk_files(root, excluder):
        file_count += 1
        total_bytes += st.st_size
        name = rel.rsplit("/", 1)[-1]
        lang = EXTENSIONS.get(os.path.splitext(name)[1].lower())
        is_vendored = bool(_VENDORED.search(rel) or _VENDORED_NAMES.match(name) or (
            name.lower().endswith(MINIFIED_CHECK_EXTENSIONS) and looks_minified(full, st.st_size)))
        if is_vendored:
            vendored.append(rel)
            lang = None  # third-party asset: not the project's language, not analysed as its code
        if lang:
            s = stats.setdefault(lang, [0, 0])
            s[0] += 1
            s[1] += st.st_size
        if is_manifest(name):
            manifests.append(rel)
        if name in ("manage.py", "artisan", "next.config.js", "next.config.mjs", "next.config.ts", "spark"):
            markers.add(name)

    frameworks: set[str] = set()
    for rel in manifests:
        name = rel.rsplit("/", 1)[-1]
        if name in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py") or _REQ_FILE.match(name):
            deps = _py_names(root, rel)
            frameworks |= {fw for key, fw in PY_FRAMEWORKS.items() if key in deps}
        elif name == "package.json":
            deps = _json_keys(root, rel, ("dependencies", "devDependencies"))
            frameworks |= {fw for key, fw in JS_FRAMEWORKS.items() if key in deps}
        elif name == "composer.json":
            deps = _json_keys(root, rel, ("require",))
            frameworks |= {fw for key, fw in PHP_FRAMEWORKS.items() if key in deps}
        elif name == "go.mod":
            text = "\n".join(safe_read_lines(root, rel) or [])
            frameworks |= {fw for key, fw in GO_FRAMEWORKS.items() if key in text}
        elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            text = "\n".join(safe_read_lines(root, rel) or [])
            if "spring-boot" in text:
                frameworks.add("Spring Boot")
            elif "springframework" in text:
                frameworks.add("Spring")
    if "manage.py" in markers:
        frameworks.add("Django")
    if "artisan" in markers:
        frameworks.add("Laravel")
    if markers & {"next.config.js", "next.config.mjs", "next.config.ts"}:
        frameworks.add("Next.js")

    code_bytes = sum(b for _, b in stats.values()) or 1
    languages = sorted(
        ({"name": lang, "files": f, "bytes": b, "percent": round(100 * b / code_bytes, 1),
          "supported": lang in SUPPORTED} for lang, (f, b) in stats.items()),
        key=lambda x: -x["bytes"])
    ordered = sorted(frameworks, key=lambda fw: PRECEDENCE.index(fw) if fw in PRECEDENCE else len(PRECEDENCE))
    present = {lang["name"] for lang in languages}
    # A detected back-end framework is stronger evidence than byte counts (e.g. a Flask app with a big JS file).
    framework_lang = next((FRAMEWORK_LANGUAGE[fw] for fw in ordered if FRAMEWORK_LANGUAGE.get(fw) in present), None)
    primary = framework_lang or next((lang["name"] for lang in languages if lang["supported"]),
                                     languages[0]["name"] if languages else None)
    return ProjectInfo(languages=languages, primary_language=primary, frameworks=ordered,
                       manifests=sorted(manifests), file_count=file_count, total_bytes=total_bytes,
                       vendored_files=sorted(vendored))
