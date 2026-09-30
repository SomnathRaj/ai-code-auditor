"""Scanner engine units that need neither tools nor network: detection, parsers,
versions, CVSS, OSV enrichment (fake client), masking, exclusions."""
import json

import pytest

from app.scanners.dependencies import collect_dependencies
from app.scanners.dependencies.cvss import base_score, severity_from_score
from app.scanners.dependencies.osv import enrich
from app.scanners.dependencies.parsers import (
    parse_composer_lock, parse_go_mod, parse_package_json, parse_package_lock, parse_pom, parse_requirements,
    parse_yarn_lock, parse_poetry_lock, parse_pipfile_lock, parse_pyproject,
)
from app.scanners.dependencies.versions import pick_upgrade, version_key
from app.scanners.detect import detect_project
from app.scanners.files import Excluder, remove_scanner_control_files, walk_files
from app.scanners.masking import mask_secrets, mask_span
from app.scanners.models import Dependency


def write(root, files: dict):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


# ---- detection ----

def test_detect_laravel(tmp_path):
    write(tmp_path, {
        "artisan": "#!/usr/bin/env php", "composer.json": json.dumps({"require": {"laravel/framework": "^10.0"}}),
        "app/Http/Controllers/UserController.php": "<?php " + "x" * 500, "resources/js/app.js": "x" * 50,
        "vendor/laravel/framework/src/Big.php": "<?php " + "x" * 50000,
    })
    info = detect_project(str(tmp_path), Excluder(["vendor/"]))
    assert info.primary_language == "PHP" and info.frameworks == ["Laravel"]
    assert "vendor/laravel/framework/src/Big.php" not in info.manifests
    assert [lang["name"] for lang in info.languages] == ["PHP", "JavaScript"]


@pytest.mark.parametrize("files,expected", [
    ({"requirements.txt": "Django==4.2\n", "manage.py": ""}, ["Django"]),
    ({"pyproject.toml": '[project]\ndependencies = ["fastapi>=0.100", "uvicorn"]\n'}, ["FastAPI"]),
    ({"package.json": json.dumps({"dependencies": {"next": "14.0.0", "react": "18.2.0"}})}, ["Next.js", "React"]),
    ({"package.json": json.dumps({"dependencies": {"@nestjs/core": "^10", "express": "^4"}})}, ["NestJS", "Express"]),
    ({"go.mod": "module x\nrequire github.com/gin-gonic/gin v1.9.1\n"}, ["Gin"]),
    ({"pom.xml": "<project><artifactId>spring-boot-starter-web</artifactId></project>"}, ["Spring Boot"]),
])
def test_detect_frameworks(tmp_path, files, expected):
    write(tmp_path, files)
    assert detect_project(str(tmp_path), Excluder([])).frameworks == expected


def test_excluder_and_symlinks(tmp_path):
    write(tmp_path, {"src/a.py": "x", "node_modules/p/i.js": "x", "dist/bundle.js": "x", "src/gen/x.min.js": "x",
                     ".git/config": "x"})
    (tmp_path / "src" / "link.py").symlink_to("/etc/passwd")
    ex = Excluder(["node_modules/", "dist/", "*.min.js"])
    assert sorted(rel for rel, _, _ in walk_files(str(tmp_path), ex)) == ["src/a.py"]
    assert "--exclude" in ex.semgrep_args() and "node_modules" in ex.semgrep_args()


def test_scanner_control_files_removed(tmp_path):
    write(tmp_path, {".gitleaksignore": "x", "sub/.semgrepignore": "x", ".gitleaks.toml": "x", "keep.py": "x"})
    assert remove_scanner_control_files(str(tmp_path)) == [".gitleaks.toml", ".gitleaksignore", "sub/.semgrepignore"]
    assert (tmp_path / "keep.py").exists() and not (tmp_path / ".gitleaksignore").exists()


# ---- parsers ----

def test_requirements():
    deps = parse_requirements("requirements.txt", [
        "Flask==2.0.0", "requests[socks]==2.25.0 ; python_version>'3.6'", "Jinja2>=3", "# c", "-r base.txt",
        "git+https://x/y.git", "Django_REST_framework===3.14.0"])
    assert [(d.name, d.version, d.declared) for d in deps] == [
        ("flask", "2.0.0", None), ("requests", "2.25.0", None), ("jinja2", None, ">=3"),
        ("django-rest-framework", "3.14.0", None)]
    assert deps[0].line == 1 and deps[3].line == 7
    assert parse_requirements("requirements-dev.txt", ["pytest==8.0.0"])[0].scope == "dev"


def test_package_lock_v3_and_v1():
    v3 = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "^4"}, "devDependencies": {"jest": "^29"}},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/jest": {"version": "29.0.0", "dev": True},
        "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
        "packages/local": {"version": "0.0.1"},
    }}
    deps = parse_package_lock("package-lock.json", json.dumps(v3, indent=1).splitlines())
    assert {(d.name, d.version, d.scope, d.direct) for d in deps} == {
        ("lodash", "4.17.15", "runtime", True), ("jest", "29.0.0", "dev", True), ("@scope/b", "1.0.0", "runtime", False)}
    v1 = {"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
    deps = parse_package_lock("package-lock.json", json.dumps(v1).splitlines())
    assert {(d.name, d.version, d.direct) for d in deps} == {("a", "1.0.0", True), ("b", "2.0.0", False)}


def test_yarn_lock_v1_and_berry():
    v1 = ['"@babel/core@^7.0.0", "@babel/core@^7.1.0":', '  version "7.22.5"', "", "lodash@^4.17.0:", '  version "4.17.15"']
    berry = ['"lodash@npm:^4.17.0":', "  version: 4.17.21", "  resolution: x"]
    assert [(d.name, d.version) for d in parse_yarn_lock("yarn.lock", v1)] == [("@babel/core", "7.22.5"), ("lodash", "4.17.15")]
    assert [(d.name, d.version) for d in parse_yarn_lock("yarn.lock", berry)] == [("lodash", "4.17.21")]


def test_other_ecosystems():
    composer = {"packages": [{"name": "laravel/framework", "version": "v8.0.0"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}
    assert [(d.name, d.version, d.scope) for d in parse_composer_lock("composer.lock", json.dumps(composer, indent=1).splitlines())] == [
        ("laravel/framework", "8.0.0", "runtime"), ("phpunit/phpunit", "9.5.0", "dev")]
    gomod = ["module x", "go 1.21", "require (", "\tgithub.com/gin-gonic/gin v1.6.0", "\tgolang.org/x/net v0.1.0 // indirect", ")",
             "require github.com/stretchr/testify v1.8.0"]
    assert [(d.name, d.version, d.direct) for d in parse_go_mod("go.mod", gomod)] == [
        ("github.com/gin-gonic/gin", "v1.6.0", True), ("golang.org/x/net", "v0.1.0", False), ("github.com/stretchr/testify", "v1.8.0", True)]
    pom = ('<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
           "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
           "<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>${junit.version}</version><scope>test</scope></dependency>"
           "</dependencies></project>")
    assert [(d.name, d.version, d.scope) for d in parse_pom("pom.xml", [pom])] == [
        ("org.apache.logging.log4j:log4j-core", "2.14.1", "runtime"), ("junit:junit", None, "dev")]
    poetry = ['[[package]]', 'name = "Django"', 'version = "3.2.0"', 'category = "main"']
    assert [(d.name, d.version) for d in parse_poetry_lock("poetry.lock", poetry)] == [("django", "3.2.0")]
    pipfile = {"default": {"requests": {"version": "==2.25.0"}}, "develop": {"pytest": {"version": "==7.0.0"}}}
    assert [(d.name, d.version, d.scope) for d in parse_pipfile_lock("Pipfile.lock", json.dumps(pipfile).splitlines())] == [
        ("requests", "2.25.0", "runtime"), ("pytest", "7.0.0", "dev")]
    pyproject = ['[project]', 'dependencies = ["flask==2.0.0", "requests>=2"]']
    assert [(d.name, d.version, d.declared) for d in parse_pyproject("pyproject.toml", pyproject)] == [
        ("flask", "2.0.0", None), ("requests", None, ">=2")]
    pkg = {"dependencies": {"express": "4.17.1", "react": "^18.2.0"}, "devDependencies": {"jest": "~29.0.0"}}
    assert [(d.name, d.version, d.declared) for d in parse_package_json("package.json", json.dumps(pkg).splitlines())] == [
        ("express", "4.17.1", None), ("react", None, "^18.2.0"), ("jest", None, "~29.0.0")]


def test_lockfile_supersedes_manifest_and_bad_files(tmp_path):
    write(tmp_path, {
        "package.json": json.dumps({"dependencies": {"lodash": "^4"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.15"}}}),
        "api/composer.json": "{ not json", "api/requirements.txt": "flask==2.0.0\n",
    })
    deps, errors = collect_dependencies(str(tmp_path), Excluder([]))
    assert {(d.name, d.version, d.manifest) for d in deps} == {
        ("lodash", "4.17.15", "package-lock.json"), ("flask", "2.0.0", "api/requirements.txt")}
    assert errors and errors[0]["path"] == "api/composer.json"


# ---- versions / CVSS ----

def test_versions():
    assert version_key("PyPI", "2.10.0") > version_key("PyPI", "2.9.1")
    assert version_key("npm", "1.2.0") > version_key("npm", "1.2.0-beta.2")
    assert version_key("Go", "v1.10.0") > version_key("Go", "v1.9.9")
    assert pick_upgrade("PyPI", "2.25.0", ["2.20.0", "2.32.4", "2.31.0"]) == "2.31.0"
    assert pick_upgrade("npm", "4.17.21", ["4.17.21"]) is None


@pytest.mark.parametrize("vector,score,severity", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "low"),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "info"),
])
def test_cvss(vector, score, severity):
    assert base_score(vector) == score and severity_from_score(score) == severity
    assert base_score("CVSS:4.0/AV:N") is None and base_score("garbage") is None


# ---- OSV enrichment (fake client) ----

class FakeOSV:
    def __init__(self, ids, vulns):
        self.ids, self.vulns, self.fetched = ids, vulns, []

    def query_batch(self, deps, cancel=None):
        return [self.ids.get((d.name, d.version), []) for d in deps]

    def vulnerability(self, vid):
        self.fetched.append(vid)
        return self.vulns[vid]


def test_enrich_dedupes_aliases_and_picks_upgrade():
    affected = lambda fixed, sev=None: [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                                         **({"database_specific": {"severity": sev}} if sev else {})}]
    vulns = {
        "PYSEC-1": {"id": "PYSEC-1", "aliases": ["GHSA-a", "CVE-1"], "summary": "leak",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "affected": affected("2.31.0")},
        "GHSA-a": {"id": "GHSA-a", "aliases": ["PYSEC-1"], "affected": affected("2.31.0")},
        "GHSA-b": {"id": "GHSA-b", "aliases": [], "summary": "tmp", "affected": affected("2.32.4", "MODERATE")},
    }
    dep = Dependency("PyPI", "requests", "2.25.0", "requirements.txt", 1)
    unpinned = Dependency("PyPI", "jinja2", None, "requirements.txt", 2, declared=">=3")
    client = FakeOSV({("requests", "2.25.0"): ["PYSEC-1", "GHSA-a", "GHSA-b"]}, vulns)
    enrich([dep, unpinned], client)
    assert [v.id for v in dep.vulnerabilities] == ["PYSEC-1", "GHSA-b"]  # GHSA-a is an alias of PYSEC-1
    assert dep.vulnerabilities[0].severity == "critical" and dep.vulnerabilities[0].cvss_score == 9.8
    assert dep.vulnerabilities[1].severity == "medium" and dep.vulnerabilities[1].affected_range == "<2.32.4"
    assert dep.recommended_version == "2.32.4"  # clears both vulnerabilities
    assert unpinned.vulnerabilities == []
    assert sorted(client.fetched) == ["GHSA-a", "GHSA-b", "PYSEC-1"]  # each ID fetched once (in parallel)


# ---- masking ----

def test_masking():
    line = 'aws_key = "AKIAQYLPMN5HHHFPZAM2"; db = "postgres://admin:hunter2@db:5432/x"'
    masked = mask_secrets(line)
    assert "AKIAQYLPMN5HHHFPZAM2" not in masked and "hunter2" not in masked
    assert mask_secrets('password = os.environ["PW"]') == 'password = os.environ["PW"]'
    assert mask_secrets("API_KEY=sk_live_abcdefghijklmnop1234") == "API_KEY=****"
    assert mask_span("TOKEN=abcdef123456 # x", 7, 18) == "TOKEN=**** # x"
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in mask_secrets(key)


def test_primary_language_ignores_vendored_js_and_follows_framework(tmp_path):
    write(tmp_path, {
        "app.py": "from flask import Flask\n" + "x = 1\n" * 50,
        "requirements.txt": "flask==3.0.0\n",
        "static/js/jquery-3.6.0.js": "x" * 100000,
        "static/app.min.js": "x" * 50000,
        "web/loader.js": "(function(){" + "var a=1;" * 20000 + "})();",  # minified, unrecognizable name
        "web/app.js": "function main() {\n  return 1;\n}\n" * 2000,  # large but hand-written
    })
    info = detect_project(str(tmp_path), Excluder([]))
    assert info.primary_language == "Python" and info.frameworks == ["Flask"]
    assert {lang["name"]: lang["files"] for lang in info.languages} == {"JavaScript": 1, "Python": 1}
    assert info.vendored_files == ["static/app.min.js", "static/js/jquery-3.6.0.js", "web/loader.js"]
