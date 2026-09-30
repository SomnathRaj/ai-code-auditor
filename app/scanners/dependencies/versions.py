"""Version ordering per ecosystem, used to pick the recommended upgrade."""
import re

from packaging.version import InvalidVersion, Version

_PART = re.compile(r"\d+|[a-zA-Z]+")


def _generic_key(v: str):
    """Loose semver-ish ordering: numeric parts compare numerically; a pre-release
    suffix (1.2.0-beta) sorts before the release (1.2.0)."""
    v = v.strip().lstrip("vV=")
    main, _, pre = v.partition("-")
    nums = tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.+]", main) if p != "")
    nums = nums + (0,) * (6 - len(nums))
    pre_key = tuple((0, int(p)) if p.isdigit() else (1, p) for p in _PART.findall(pre)) if pre else ()
    return nums, 0 if pre else 1, pre_key


def version_key(ecosystem: str, v: str):
    if ecosystem == "PyPI":
        try:
            return (0, Version(v))
        except InvalidVersion:
            pass
    return (1, _generic_key(v))


def is_greater(ecosystem: str, a: str, b: str) -> bool:
    try:
        return version_key(ecosystem, a) > version_key(ecosystem, b)
    except TypeError:
        return False


def pick_upgrade(ecosystem: str, current: str, fixed: list[str]) -> str | None:
    """Smallest fixed version above the current one (the least disruptive upgrade)."""
    candidates = [f for f in set(fixed) if f and is_greater(ecosystem, f, current)]
    if not candidates:
        return None
    return min(candidates, key=lambda f: version_key(ecosystem, f))


def highest(ecosystem: str, versions: list[str]) -> str | None:
    vs = [v for v in set(versions) if v]
    return max(vs, key=lambda v: version_key(ecosystem, v)) if vs else None
