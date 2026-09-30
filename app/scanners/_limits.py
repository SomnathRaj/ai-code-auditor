"""Scanner launcher: applies resource limits (and optionally drops privileges), runs the
scanner as a child, and kills it if the app process dies.

Run as:  python -I -S _limits.py --cpu N --mem-mb M --fsize-mb F [--user NAME] -- cmd args...

A separate process (not preexec_fn) because preexec_fn is unsafe when the parent is
multi-threaded, and scanners run in parallel threads. It stays alive as a watchdog:
if the audit worker is killed (even with SIGKILL), the scanner is not left running
as an orphan. Stdlib only.
"""
import os
import resource
import signal
import sys
import time


def _set(limit, value):
    try:
        soft, hard = resource.getrlimit(limit)
        if hard != resource.RLIM_INFINITY:
            value = min(value, hard)
        resource.setrlimit(limit, (value, hard if hard != resource.RLIM_INFINITY else value))
    except (ValueError, OSError):
        pass  # not supported on this platform


def _apply_limits(values: dict) -> None:
    _set(resource.RLIMIT_CORE, 0)
    if "--cpu" in values:
        _set(resource.RLIMIT_CPU, int(values["--cpu"]))
    if "--fsize-mb" in values:
        _set(resource.RLIMIT_FSIZE, int(values["--fsize-mb"]) * 1024 * 1024)
    # Address-space limits are only enforced reliably on Linux.
    if "--mem-mb" in values and sys.platform.startswith("linux"):
        _set(resource.RLIMIT_AS, int(values["--mem-mb"]) * 1024 * 1024)


def _drop_privileges(user: str | None) -> None:
    if user:
        import pwd

        pw = pwd.getpwnam(user)
        os.setgroups([])
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
    if os.geteuid() == 0:
        sys.exit("refusing to run a scanner as root; set SCANNER_USER")


def main(argv: list[str]) -> None:
    if "--" not in argv:
        sys.exit("usage: _limits.py [options] -- command ...")
    split = argv.index("--")
    opts, cmd = argv[:split], argv[split + 1:]
    values = dict(zip(opts[::2], opts[1::2]))
    _drop_privileges(values.get("--user"))
    parent = os.getppid()

    child = os.fork()
    if child == 0:
        _apply_limits(values)  # limits apply to the scanner only
        try:
            os.execvpe(cmd[0], cmd, os.environ)
        except OSError as exc:
            print(f"cannot run {cmd[0]}: {exc.strerror}", file=sys.stderr)
            os._exit(127)

    def _forward(signum, _frame):
        os.kill(child, signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _forward)

    while True:
        pid, status = os.waitpid(child, os.WNOHANG)
        if pid:
            break
        if os.getppid() != parent:  # the app died: don't leave the scanner running
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            os._exit(137)
        time.sleep(0.5)

    if os.WIFSIGNALED(status):  # propagate e.g. SIGXCPU so the caller sees "killed by signal"
        sig = os.WTERMSIG(status)
        signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
    os._exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)


if __name__ == "__main__":
    main(sys.argv[1:])
