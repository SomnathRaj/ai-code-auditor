"""Dependency discovery (manifests/lockfiles) and vulnerability matching via OSV."""
import posixpath

from ..files import Excluder, safe_read_lines, walk_files
from ..models import Dependency
from .osv import OSVClient, OSVError, enrich
from .parsers import COVERED_BY, parser_for

__all__ = ["collect_dependencies", "enrich", "OSVClient", "OSVError"]


def collect_dependencies(root: str, excluder: Excluder) -> tuple[list[Dependency], list[dict]]:
    """Parse every supported manifest; returns (dependencies, parse errors)."""
    files = [(rel, rel.rsplit("/", 1)[-1]) for rel, _full, _st in walk_files(root, excluder)]
    present = {rel for rel, _ in files}
    deps, errors = [], []
    seen: set[tuple] = set()
    for rel, name in sorted(files):
        parse = parser_for(name)
        if parse is None:
            continue
        directory = posixpath.dirname(rel)
        if any(posixpath.join(directory, lock) in present for lock in COVERED_BY.get(name, ())):
            continue  # a lockfile in the same directory has the exact versions
        lines = safe_read_lines(root, rel)
        if lines is None:
            continue
        try:
            parsed = parse(rel, lines)
        except Exception as exc:  # malformed manifests must not break the audit
            errors.append({"scanner": "dependencies", "message": f"Could not parse {rel}: {type(exc).__name__}",
                           "path": rel})
            continue
        for dep in parsed:
            key = (dep.ecosystem, dep.name.lower(), dep.version, dep.manifest)
            if key not in seen:
                seen.add(key)
                deps.append(dep)
    return deps, errors
