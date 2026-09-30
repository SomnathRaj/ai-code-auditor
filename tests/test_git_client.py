"""Real git subprocesses against local repositories (file:// allowed only in these tests)."""
import os
import subprocess

import pytest

from app.services import git_client
from app.services.workspace import SourceError, acquire_source

pytestmark = pytest.mark.real_git

GIT_ENV = {
    "PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
}


def git(*args, cwd):
    return subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", *args],
                          cwd=cwd, env=GIT_ENV, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def local_git(app):
    app.config["GIT_ALLOWED_PROTOCOLS"] = ("file",)
    yield
    app.config["GIT_ALLOWED_PROTOCOLS"] = ("https",)


@pytest.fixture
def origin(tmp_path):
    """A repository with a feature branch, a symlink escaping the tree, a hook and a submodule."""
    sub = tmp_path / "sub"
    sub.mkdir()
    git("init", cwd=sub)
    (sub / "secret.txt").write_text("from submodule")
    git("add", ".", cwd=sub)
    git("commit", "-m", "sub", cwd=sub)

    repo = tmp_path / "origin"
    repo.mkdir()
    git("init", cwd=repo)
    (repo / "app.py").write_text("print('main')\n")
    os.symlink("/etc/passwd", repo / "passwd-link")
    git("add", ".", cwd=repo)
    git("submodule", "add", f"file://{sub}", "vendor/sub", cwd=repo)
    git("commit", "-m", "main", cwd=repo)
    main_sha = git("rev-parse", "HEAD", cwd=repo)
    git("checkout", "-b", "feature/x", cwd=repo)
    (repo / "feature.py").write_text("print('feature')\n")
    git("add", ".", cwd=repo)
    git("commit", "-m", "feature", cwd=repo)
    feature_sha = git("rev-parse", "HEAD", cwd=repo)
    git("checkout", "main", cwd=repo)
    # A hook in the origin must never run on our side.
    hook = repo / ".git" / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {tmp_path}/HOOK_RAN\n")
    hook.chmod(0o755)
    return {"url": f"file://{repo}", "main": main_sha, "feature": feature_sha, "tmp": tmp_path}


def test_ls_remote_lists_branches_and_default(app, local_git, origin):
    with app.app_context():
        info = git_client.ls_remote(origin["url"])
    assert info.default_branch == "main"
    assert info.branches == {"main": origin["main"], "feature/x": origin["feature"]}


def test_clone_is_hardened(app, local_git, origin):
    repo = {"provider": "github", "url": origin["url"], "default_branch": "main", "organization_id": None}
    with app.app_context():
        with acquire_source(repo, branch="feature/x") as ws:
            src = ws.source_dir
            assert ws.commit_hash == origin["feature"]
            assert os.path.isfile(os.path.join(src, "feature.py"))
            assert not os.path.exists(os.path.join(src, ".git"))
            link = os.path.join(src, "passwd-link")
            assert not os.path.islink(link)  # checked out as a plain file
            assert open(link).read() == "/etc/passwd"
            assert os.listdir(os.path.join(src, "vendor", "sub")) == []  # submodule not fetched
            assert oct(os.stat(ws.path).st_mode & 0o777) == "0o700"
            workspace_path = ws.path
    assert not os.path.exists(workspace_path)
    assert not (origin["tmp"] / "HOOK_RAN").exists()


def test_missing_branch(app, local_git, origin):
    repo = {"provider": "github", "url": origin["url"], "default_branch": "nope", "organization_id": None}
    with app.app_context(), pytest.raises(SourceError) as exc:
        with acquire_source(repo):
            pass
    assert exc.value.code == "branch_not_found"


def test_protocol_allowlist(app, origin):
    with app.app_context():
        for url in (origin["url"], "http://github.com/a/b", "ssh://git@github.com/a/b", "ext::sh -c touch% /tmp/x"):
            with pytest.raises(git_client.GitError) as exc:
                git_client.ls_remote(url)
            assert exc.value.code == "protocol_not_allowed", url


def test_source_size_limit(app, local_git, origin):
    app.config["MAX_SOURCE_BYTES"] = 10
    repo = {"provider": "github", "url": origin["url"], "default_branch": "main", "organization_id": None}
    with app.app_context(), pytest.raises(SourceError) as exc:
        with acquire_source(repo):
            pass
    assert exc.value.code == "too_large"
    assert os.listdir(app.config["WORK_DIR"]) == []  # cleaned up despite the failure


def test_timeout_kills_process_group(app):
    with app.app_context(), pytest.raises(git_client.GitError) as exc:
        git_client.run(["/bin/sh", "-c", "sleep 30 & sleep 30"], timeout=0.5)
    assert exc.value.code == "timeout"


def test_token_is_passed_by_env_and_redacted(app):
    with app.app_context():
        env = git_client._env("/tmp", "ghp_SECRET123")
    assert "ghp_SECRET123" not in " ".join(git_client._git_args())
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
    assert "credential.helper=" in git_client.HARDENING_CONFIG
    header_b64 = env["GIT_CONFIG_VALUE_0"].rsplit(" ", 1)[1]
    leaked = f"fatal: bad token ghp_SECRET123 header {header_b64}"
    assert git_client.redact(leaked, "ghp_SECRET123") == "fatal: bad token *** header ***"


def test_system_credential_helpers_are_ignored(app):
    with app.app_context():
        out = git_client.run(git_client._git_args() + ["config", "--list", "--show-origin"], timeout=10)
    assert "osxkeychain" not in out and "file:" not in out


def test_error_message_depends_on_token():
    stderr = "remote: Invalid username or token.\nfatal: Authentication failed for 'https://github.com/a/b/'"
    assert "need an access token" in git_client._classify(stderr).message
    assert "rejected the access token" in git_client._classify(stderr, token_sent=True).message
