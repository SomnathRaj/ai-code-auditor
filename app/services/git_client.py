"""Hardened git subprocess wrapper (PRD §67, §80: repositories may be malicious).

- Fixed argument lists (no shell); `--` before URLs; branch names pre-validated.
- Isolated config: no system/global config or credential helpers (e.g. macOS
  keychain), HOME points at an empty directory, prompts disabled.
- Only allowed protocols (https in production).
- Access tokens go in an http.extraHeader set through GIT_CONFIG_* environment
  variables, scoped to https://github.com/ — never in argv, URLs or logs.
- Clone: shallow, single branch, no tags, no submodules, no LFS, symlinks
  checked out as plain files, hooks disabled, objects fsck'd.
- Timeouts kill the whole process group (git spawns helpers).
"""
import base64
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from flask import current_app

from ..scanners.cancel import NEVER, CancelToken

TOKEN_HEADER_SCOPE = "https://github.com/"

HARDENING_CONFIG = [
    "core.symlinks=false",
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "credential.helper=",
    "transfer.fsckObjects=true",
    "fetch.fsckObjects=true",
    "submodule.recurse=false",
    "advice.detachedHead=false",
    "init.defaultBranch=main",
]


class GitError(Exception):
    """`message` is safe to show to users; `code` is machine-readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class RemoteInfo:
    default_branch: str | None
    branches: dict[str, str] = field(default_factory=dict)  # name -> commit sha


def _check_protocol(url: str) -> None:
    scheme = urlsplit(url).scheme.lower()
    if scheme not in current_app.config["GIT_ALLOWED_PROTOCOLS"]:
        raise GitError("protocol_not_allowed", f"Protocol '{scheme}' is not allowed")


def _env(home: str, token: str | None) -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/echo",
        "SSH_ASKPASS": "/bin/echo",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": ":".join(current_app.config["GIT_ALLOWED_PROTOCOLS"]),
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"http.{TOKEN_HEADER_SCOPE}.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        })
    return env


def redact(text: str, token: str | None) -> str:
    if token:
        text = text.replace(token, "***")
        text = text.replace(base64.b64encode(f"x-access-token:{token}".encode()).decode(), "***")
    return text


def _git_args() -> list[str]:
    args = ["git"]
    for item in HARDENING_CONFIG:
        args += ["-c", item]
    return args


def run(args: list[str], *, timeout: float, token: str | None = None, cwd: str | None = None,
        cancel: CancelToken = NEVER) -> str:
    """Run a command in its own process group; return stdout. Raises GitError, or
    Cancelled when the audit is cancelled (the process group is killed)."""
    cancel.raise_if_cancelled()
    home = tempfile.mkdtemp(prefix="git-home-")
    try:
        proc = subprocess.Popen(
            args, cwd=cwd, env=_env(home, token), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                out, err = proc.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if cancel.cancelled or time.monotonic() > deadline:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
                    cancel.raise_if_cancelled()
                    raise GitError("timeout", f"Git operation timed out after {int(timeout)} seconds")
    finally:
        shutil.rmtree(home, ignore_errors=True)

    stderr = redact(err.decode(errors="replace"), token)
    if proc.returncode != 0:
        current_app.logger.warning("git failed (%s): %s", proc.returncode, stderr.strip()[:2000])
        raise _classify(stderr, token_sent=bool(token))
    return out.decode(errors="replace")


def _classify(stderr: str, token_sent: bool = False) -> GitError:
    s = stderr.lower()
    if "remote branch" in s and "not found" in s:
        return GitError("branch_not_found", "Branch not found in the repository")
    if any(m in s for m in ("could not resolve host", "failed to connect", "connection timed out",
                            "network is unreachable", "connection refused")):
        return GitError("network_error", "Could not reach the Git provider")
    if any(m in s for m in ("repository not found", "authentication failed", "could not read username",
                            "terminal prompts disabled", "does not appear to be a git repository",
                            "access denied", "403", "not found")):
        if token_sent:
            return GitError("repository_inaccessible",
                            "GitHub rejected the access token, or the token cannot read this repository")
        return GitError("repository_inaccessible",
                        "Repository not found or not accessible. Private repositories need an access token.")
    if "transport" in s and "not allowed" in s:
        return GitError("protocol_not_allowed", "Protocol is not allowed")
    return GitError("git_failed", "Git operation failed")


def ls_remote(url: str, token: str | None = None) -> RemoteInfo:
    """List branches and the default branch without cloning."""
    _check_protocol(url)
    out = run(
        _git_args() + ["ls-remote", "--symref", "--", url, "HEAD", "refs/heads/*"],
        timeout=current_app.config["GIT_REMOTE_TIMEOUT"], token=token,
    )
    info = RemoteInfo(default_branch=None)
    for line in out.splitlines():
        left, _, ref = line.partition("\t")
        if left.startswith("ref: ") and ref == "HEAD":
            info.default_branch = left[5:].removeprefix("refs/heads/")
        elif ref.startswith("refs/heads/"):
            info.branches[ref.removeprefix("refs/heads/")] = left
    if info.default_branch not in info.branches:
        info.default_branch = next(iter(sorted(info.branches)), None)
    return info


def clone(url: str, branch: str, dest: str, token: str | None = None, cancel: CancelToken = NEVER) -> str:
    """Shallow-clone one branch into dest (must not exist). Returns the commit SHA.

    The .git directory is removed afterwards: scanners only need the working tree.
    """
    _check_protocol(url)
    run(
        _git_args() + [
            "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
            "--branch", branch, "--", url, dest,
        ],
        timeout=current_app.config["GIT_CLONE_TIMEOUT"], token=token, cancel=cancel,
    )
    sha = run(_git_args() + ["-C", dest, "rev-parse", "HEAD"], timeout=30, cancel=cancel).strip()
    shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)
    return sha
