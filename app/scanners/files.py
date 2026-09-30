"""Walking the source tree with the repository's exclusion settings (PRD §37)."""
import fnmatch
import os
import re
import stat
from collections.abc import Iterator

ALWAYS_EXCLUDED_DIRS = {".git", ".hg", ".svn"}

# Files a scanned repository could use to hide findings from our scanners.
SCANNER_CONTROL_FILES = {".gitleaksignore", ".gitleaks.toml", ".semgrepignore"}


class Excluder:
    """Entries ending in "/" match a directory name at any depth (like .gitignore);
    other entries are globs matched against the relative path or the file name."""

    def __init__(self, patterns: list[str]):
        self.dir_names = set(ALWAYS_EXCLUDED_DIRS)
        self.globs = []
        for p in patterns:
            p = p.strip().lstrip("./")
            if not p:
                continue
            if p.endswith("/") and "/" not in p[:-1] and not any(c in p for c in "*?["):
                self.dir_names.add(p[:-1])
            else:
                self.globs.append(p.rstrip("/"))

    def dir_excluded(self, rel_dir: str, name: str) -> bool:
        return name in self.dir_names or any(
            fnmatch.fnmatch(rel_dir, g) or fnmatch.fnmatch(rel_dir, g + "/*") for g in self.globs)

    def file_excluded(self, rel_path: str) -> bool:
        name = rel_path.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(rel_path, g) or fnmatch.fnmatch(name, g) or
                   fnmatch.fnmatch(rel_path, g + "/*") for g in self.globs)

    def with_files(self, rel_paths: list[str]) -> "Excluder":
        """A copy that also excludes these exact files (used to skip vendored code for Semgrep)."""
        other = Excluder([])
        other.dir_names = set(self.dir_names)
        other.globs = list(self.globs) + [p for p in rel_paths]
        return other

    def semgrep_args(self) -> list[str]:
        args = []
        for d in sorted(self.dir_names):
            args += ["--exclude", d]
        for g in self.globs:
            args += ["--exclude", g]
        return args

    def gitleaks_path_regexes(self) -> list[str]:
        regexes = [rf"(^|/){re.escape(d)}/" for d in sorted(self.dir_names)]
        regexes += [_glob_to_regex(g) for g in self.globs]
        return regexes


def _glob_to_regex(glob: str) -> str:
    return "(^|/)" + fnmatch.translate(glob).removeprefix("(?s:").removesuffix(")\\Z") + "($|/)"


def walk_files(root: str, excluder: Excluder) -> Iterator[tuple[str, str, os.stat_result]]:
    """Yield (relative_path, absolute_path, lstat) for regular files, never following symlinks."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames
                       if not excluder.dir_excluded(f"{rel_dir}/{d}".lstrip("/"), d)
                       and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            rel = f"{rel_dir}/{name}".lstrip("/")
            if excluder.file_excluded(rel):
                continue
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if stat.S_ISREG(st.st_mode):
                yield rel, full, st


def remove_scanner_control_files(root: str) -> list[str]:
    """Delete files that could suppress findings (the workspace is a disposable copy)."""
    removed = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in ALWAYS_EXCLUDED_DIRS]
        for name in filenames:
            if name in SCANNER_CONTROL_FILES:
                full = os.path.join(dirpath, name)
                os.unlink(full)
                removed.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(removed)


def safe_read_lines(root: str, rel_path: str, max_bytes: int = 2 * 1024 * 1024) -> list[str] | None:
    """Read a file inside root (no symlinks, no escaping root). Returns None if unsafe/unreadable."""
    root_real = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_real, rel_path))
    if not full.startswith(root_real + os.sep) or os.path.islink(os.path.join(root, rel_path)):
        return None
    try:
        if os.path.getsize(full) > max_bytes:
            return None
        with open(full, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return None
