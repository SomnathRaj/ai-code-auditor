"""Ruleset version = short hash of the rule files, recorded in audits.scanner_versions."""
import functools
import hashlib
import os

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


@functools.lru_cache(maxsize=1)
def rules_version() -> str:
    digest = hashlib.sha256()
    count = 0
    for name in sorted(os.listdir(RULES_DIR)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(RULES_DIR, name), "rb") as fh:
                digest.update(name.encode() + b"\0" + fh.read())
            count += 1
    return f"aca-rules-{digest.hexdigest()[:12]} ({count} files)"
