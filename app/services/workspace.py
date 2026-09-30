"""Secure temporary workspaces for audits (PRD §52, §53, §67).

    with acquire_source(repo, branch="main") as ws:
        run_scanners(ws.source_dir)
    # workspace deleted here, even on errors (default retention: delete after audit)

Each workspace is a fresh 0700 directory under WORK_DIR (itself 0700).
"""
import os
import shutil
import stat
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from flask import current_app

from ..scanners.cancel import NEVER, CancelToken
from . import git_client, source_archive
from .crypto import decrypt_text

WORKSPACE_PREFIX = "ws-"


class SourceError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Workspace:
    path: str
    source_dir: str
    source_type: str  # github | zip
    branch: str | None = None
    commit_hash: str | None = None
    file_count: int = 0
    total_bytes: int = 0


def work_root() -> str:
    root = current_app.config["WORK_DIR"]
    os.makedirs(root, mode=0o700, exist_ok=True)
    st = os.lstat(root)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"WORK_DIR {root} must be a real directory")
    if st.st_uid != os.getuid():
        raise RuntimeError(f"WORK_DIR {root} must be owned by the app user")
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(root, 0o700)
    return root


def _measure(path: str) -> tuple[int, int]:
    """Count regular files and bytes without following symlinks; enforce limits."""
    cfg = current_app.config
    files = total = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            st = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISLNK(st.st_mode):
                os.unlink(os.path.join(dirpath, name))  # defence in depth; git is set to core.symlinks=false
                continue
            files += 1
            total += st.st_size
        if files > cfg["MAX_SOURCE_FILES"]:
            raise SourceError("too_many_files", f"Source has more than {cfg['MAX_SOURCE_FILES']} files")
        if total > cfg["MAX_SOURCE_BYTES"]:
            raise SourceError("too_large", f"Source is larger than {cfg['MAX_SOURCE_BYTES'] // (1024 * 1024)} MB")
    return files, total


@contextmanager
def workspace() -> Iterator[str]:
    path = tempfile.mkdtemp(prefix=WORKSPACE_PREFIX, dir=work_root())  # mode 0700
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@contextmanager
def acquire_source(repo: dict, branch: str | None = None, cancel: CancelToken = NEVER) -> Iterator[Workspace]:
    """Fetch a repository's source into a private workspace; always cleaned up."""
    with workspace() as path:
        source_dir = os.path.join(path, "src")
        ws = Workspace(path=path, source_dir=source_dir, source_type=repo["provider"])
        try:
            if repo["provider"] == "github":
                ws.branch = branch or repo["default_branch"]
                token = decrypt_text(repo["credentials"]["encrypted_token"]) if repo.get("credentials") else None
                ws.commit_hash = git_client.clone(repo["url"], ws.branch, source_dir, token, cancel=cancel)
            elif repo["provider"] == "zip":
                if not repo.get("source"):
                    raise SourceError("no_source", "No archive has been uploaded for this repository")
                source_archive.extract_stored_archive(repo["source"], repo["organization_id"], source_dir)
                ws.commit_hash = repo["source"]["sha256"][:12]
            else:
                raise SourceError("unsupported_provider", f"Unsupported provider {repo['provider']}")
            ws.file_count, ws.total_bytes = _measure(source_dir)
        except git_client.GitError as err:
            raise SourceError(err.code, err.message) from err
        except source_archive.UnsafeArchive as err:
            raise SourceError("unsafe_archive", err.message) from err
        yield ws


def purge_stale_workspaces(max_age_seconds: int = 6 * 3600) -> int:
    """Remove workspaces left behind by crashes. Returns the number removed."""
    root = work_root()
    cutoff = time.time() - max_age_seconds
    removed = 0
    for entry in os.scandir(root):
        if entry.name.startswith(WORKSPACE_PREFIX) and entry.is_dir(follow_symlinks=False):
            if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                shutil.rmtree(entry.path, ignore_errors=True)
                removed += 1
    return removed
