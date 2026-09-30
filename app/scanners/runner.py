"""Run scanner tools in an isolated, resource-limited subprocess (PRD §67, §80).

- Minimal environment: no app secrets (JWT/encryption keys, DB URI) reach scanners.
- Limits applied by `_limits.py` (CPU seconds, output file size, memory on Linux,
  no core dumps); refuses to run as root unless SCANNER_USER is configured.
- Own process group, killed entirely on timeout.
- stdout/stderr go to files in the workspace (no pipe deadlocks on big output).
"""
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass

from .cancel import NEVER, CancelToken

LIMITS_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_limits.py")


class ScannerError(Exception):
    def __init__(self, scanner: str, message: str):
        super().__init__(message)
        self.scanner = scanner
        self.message = message


@dataclass
class ToolResult:
    returncode: int
    stderr_tail: str
    stdout_path: str


@dataclass
class RunnerConfig:
    bin_dirs: list[str]
    cpu_seconds: int
    memory_mb: int
    max_output_mb: int
    scanner_user: str | None


def find_tool(name: str, cfg: RunnerConfig) -> str | None:
    for d in cfg.bin_dirs:
        path = os.path.join(d, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which(name)


def _env(cfg: RunnerConfig, home: str, extra: dict | None) -> dict:
    env = {
        "PATH": os.pathsep.join(cfg.bin_dirs + ["/usr/local/bin", "/usr/bin", "/bin"]),
        "HOME": home,
        "TMPDIR": home,
        "XDG_CACHE_HOME": os.path.join(home, ".cache"),
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "PYTHONIOENCODING": "utf-8",
        "NO_COLOR": "1",
    }
    env.update(extra or {})
    return env


def run_tool(scanner: str, args: list[str], *, cwd: str, work_dir: str, timeout: int, cfg: RunnerConfig,
             env: dict | None = None, cancel: CancelToken = NEVER) -> ToolResult:
    """Run a scanner; raise ScannerError on timeout or launch failure (not on non-zero exit),
    Cancelled if the audit is cancelled meanwhile (the process group is killed)."""
    cancel.raise_if_cancelled()
    home = os.path.join(work_dir, f"home-{scanner}")
    os.makedirs(home, mode=0o700, exist_ok=True)
    stdout_path = os.path.join(work_dir, f"{scanner}.stdout")
    stderr_path = os.path.join(work_dir, f"{scanner}.stderr")

    wrapper = [sys.executable, "-I", "-S", LIMITS_SCRIPT,
               "--cpu", str(cfg.cpu_seconds), "--mem-mb", str(cfg.memory_mb), "--fsize-mb", str(cfg.max_output_mb)]
    if cfg.scanner_user:
        wrapper += ["--user", cfg.scanner_user]
    elif os.geteuid() == 0:
        raise ScannerError(scanner, "Refusing to run scanners as root; configure SCANNER_USER")

    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        try:
            proc = subprocess.Popen(wrapper + ["--"] + args, cwd=cwd, env=_env(cfg, home, env),
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        except OSError as exc:
            raise ScannerError(scanner, f"Could not start {scanner}: {exc.strerror}")
        deadline = time.monotonic() + timeout
        while True:
            try:
                proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if cancel.cancelled or time.monotonic() > deadline:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    cancel.raise_if_cancelled()
                    raise ScannerError(scanner, f"{scanner} timed out after {timeout} seconds")

    with open(stderr_path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        fh.seek(max(0, fh.tell() - 4000))
        tail = fh.read().decode(errors="replace")
    if proc.returncode < 0:
        raise ScannerError(scanner, f"{scanner} was killed by signal {-proc.returncode} (resource limit?)")
    return ToolResult(returncode=proc.returncode, stderr_tail=tail, stdout_path=stdout_path)


def tool_version(scanner: str, args: list[str], cfg: RunnerConfig, work_dir: str) -> str | None:
    try:
        res = run_tool(f"{scanner}-version", args, cwd=work_dir, work_dir=work_dir, timeout=60, cfg=cfg)
        with open(res.stdout_path, encoding="utf-8", errors="replace") as fh:
            out = fh.read().strip()
        return out.splitlines()[-1].strip() if out else None
    except ScannerError:
        return None
