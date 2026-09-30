"""Dependency manifest / lockfile parsers (PRD §21).

Lockfiles give exact versions and are preferred. A manifest with only ranges
(package.json, composer.json, pyproject.toml) is recorded as unpinned and only
checked when no lockfile covers the same directory.
"""
import json
import re
import tomllib
import xml.etree.ElementTree as ET

from ..models import Dependency

_PEP503 = re.compile(r"[-_.]+")
_EXACT_SEMVER = re.compile(r"^v?\d+(\.\d+){0,3}([-+][0-9A-Za-z.\-]+)?$")


def normalize_pypi(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def _line_of(lines: list[str], needle: str) -> int | None:
    needle_l = needle.lower()
    for i, line in enumerate(lines, 1):
        if needle_l in line.lower():
            return i
    return None


# ---- Python ----

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(===|==)\s*([A-Za-z0-9.*+!_\-]+)")
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)")


def parse_requirements(path: str, lines: list[str]) -> list[Dependency]:
    deps, dev = [], any(k in path.lower() for k in ("dev", "test"))
    for i, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:", "file:")):
            continue
        line = line.split(";", 1)[0].strip()
        m = _REQ.match(line)
        if m and "*" not in m.group(4):
            deps.append(Dependency("PyPI", normalize_pypi(m.group(1)), m.group(4), path, i,
                                   "dev" if dev else "runtime"))
        elif (n := _REQ_NAME.match(line)):
            deps.append(Dependency("PyPI", normalize_pypi(n.group(1)), None, path, i,
                                   "dev" if dev else "runtime", declared=line[len(n.group(1)):].strip() or "*"))
    return deps


def parse_pipfile_lock(path: str, lines: list[str]) -> list[Dependency]:
    data = json.loads("\n".join(lines))
    deps = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=")
            if version:
                deps.append(Dependency("PyPI", normalize_pypi(name), version, path, _line_of(lines, f'"{name}"'), scope))
    return deps


def parse_poetry_lock(path: str, lines: list[str]) -> list[Dependency]:
    data = tomllib.loads("\n".join(lines))
    deps = []
    for pkg in data.get("package", []):
        if pkg.get("name") and pkg.get("version"):
            scope = "dev" if pkg.get("category") == "dev" else "runtime"
            deps.append(Dependency("PyPI", normalize_pypi(pkg["name"]), pkg["version"], path,
                                   _line_of(lines, f'name = "{pkg["name"]}"'), scope, direct=False))
    return deps


def parse_pyproject(path: str, lines: list[str]) -> list[Dependency]:
    data = tomllib.loads("\n".join(lines))
    specs = list(data.get("project", {}).get("dependencies", []))
    deps = []
    for spec in specs:
        m = _REQ.match(spec)
        n = _REQ_NAME.match(spec)
        if not n:
            continue
        version = m.group(4) if m else None
        deps.append(Dependency("PyPI", normalize_pypi(n.group(1)), version, path, _line_of(lines, n.group(1)),
                               declared=None if version else spec[len(n.group(1)):].strip() or "*"))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        s = spec if isinstance(spec, str) else (spec.get("version", "*") if isinstance(spec, dict) else "*")
        exact = s if _EXACT_SEMVER.match(s or "") else None
        deps.append(Dependency("PyPI", normalize_pypi(name), exact, path, _line_of(lines, name),
                               declared=None if exact else s))
    return deps


# ---- JavaScript ----

def parse_package_lock(path: str, lines: list[str]) -> list[Dependency]:
    data = json.loads("\n".join(lines))
    deps = []
    if isinstance(data.get("packages"), dict):  # lockfile v2/v3
        root = data["packages"].get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        for key, info in data["packages"].items():
            if not key or "node_modules/" not in key or info.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[1]
            if info.get("version"):
                deps.append(Dependency("npm", name, info["version"], path, _line_of(lines, f'"{key}"'),
                                       "dev" if info.get("dev") else "runtime", direct=name in direct))
    else:  # lockfile v1
        def walk(tree: dict, top: bool):
            for name, info in (tree or {}).items():
                if info.get("version"):
                    deps.append(Dependency("npm", name, info["version"], path, _line_of(lines, f'"{name}"'),
                                           "dev" if info.get("dev") else "runtime", direct=top))
                walk(info.get("dependencies"), False)
        walk(data.get("dependencies"), True)
    return deps


_YARN_HEADER = re.compile(r'^"?(@?[^@\s"]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')


def parse_yarn_lock(path: str, lines: list[str]) -> list[Dependency]:
    """yarn.lock v1 and Berry (v2+) formats."""
    deps, seen, current = [], set(), None
    for i, line in enumerate(lines, 1):
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            m = _YARN_HEADER.match(line.strip())
            current = (m.group(1), i) if m else None
        elif current and (v := _YARN_VERSION.match(line)):
            name, header_line = current
            if (name, v.group(1)) not in seen and name != "__metadata":
                seen.add((name, v.group(1)))
                deps.append(Dependency("npm", name, v.group(1), path, header_line, direct=False))
            current = None
    return deps


def parse_package_json(path: str, lines: list[str]) -> list[Dependency]:
    data = json.loads("\n".join(lines))
    deps = []
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev")):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            exact = spec.lstrip("=v") if _EXACT_SEMVER.match(spec.lstrip("=")) else None
            deps.append(Dependency("npm", name, exact, path, _line_of(lines, f'"{name}"'), scope,
                                   declared=None if exact else spec))
    return deps


# ---- PHP ----

def parse_composer_lock(path: str, lines: list[str]) -> list[Dependency]:
    data = json.loads("\n".join(lines))
    deps = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for pkg in data.get(section) or []:
            if pkg.get("name") and pkg.get("version"):
                deps.append(Dependency("Packagist", pkg["name"], str(pkg["version"]).lstrip("v"), path,
                                       _line_of(lines, f'"name": "{pkg["name"]}"'), scope, direct=False))
    return deps


def parse_composer_json(path: str, lines: list[str]) -> list[Dependency]:
    data = json.loads("\n".join(lines))
    deps = []
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, spec in (data.get(section) or {}).items():
            if name == "php" or name.startswith(("ext-", "lib-")) or "/" not in name:
                continue
            spec = str(spec)
            exact = spec.lstrip("v") if _EXACT_SEMVER.match(spec) else None
            deps.append(Dependency("Packagist", name, exact, path, _line_of(lines, f'"{name}"'), scope,
                                   declared=None if exact else spec))
    return deps


# ---- Go ----

_GO_REQ = re.compile(r"^\s*(?:require\s+)?([A-Za-z0-9.\-_~/]+\.[A-Za-z0-9.\-_~/]+)\s+(v[0-9][^\s]*)(\s*//\s*indirect)?")


def parse_go_mod(path: str, lines: list[str]) -> list[Dependency]:
    deps, in_block = [], False
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block or line.startswith("require "):
            m = _GO_REQ.match(line)
            if m:
                deps.append(Dependency("Go", m.group(1), m.group(2), path, i, direct=not m.group(3)))
    return deps


# ---- Java ----

def parse_pom(path: str, lines: list[str]) -> list[Dependency]:
    try:
        root = ET.fromstring("\n".join(lines))
    except ET.ParseError:
        return []
    ns = {"m": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)
    deps = []
    for dep in root.iter(f"{{{ns['m']}}}dependency" if ns else "dependency"):
        group, artifact, version = (dep.findtext(q(t), namespaces=ns) for t in ("groupId", "artifactId", "version"))
        if not group or not artifact:
            continue
        scope = dep.findtext(q("scope"), namespaces=ns) or "compile"
        exact = version if version and "${" not in version and _EXACT_SEMVER.match(version.split("-")[0]) else None
        deps.append(Dependency("Maven", f"{group}:{artifact}", exact, path, _line_of(lines, f"<artifactId>{artifact}"),
                               "dev" if scope == "test" else "runtime", declared=None if exact else version))
    return deps


LOCKFILES = {
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "composer.lock": parse_composer_lock,
    "go.mod": parse_go_mod,
}
MANIFESTS = {
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
    "composer.json": parse_composer_json,
    "pom.xml": parse_pom,
}
# Which lockfiles supersede which manifest in the same directory.
COVERED_BY = {
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "composer.json": ("composer.lock",),
    "pyproject.toml": ("poetry.lock",),
}


def parser_for(filename: str):
    if filename in LOCKFILES:
        return LOCKFILES[filename]
    if filename in MANIFESTS:
        return MANIFESTS[filename]
    if re.match(r"^requirements[\w.-]*\.txt$", filename):
        return parse_requirements
    return None
