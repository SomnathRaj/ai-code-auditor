"""Secret masking for anything we store or show (PRD §18: never expose secret values).

Applied to every code snippet, whatever the scanner, as defence in depth.
"""
import re

MASK = "****"

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWTs
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),  # user:password@ in URLs
]
# key = "value" / key: 'value' / KEY=value where the key looks secret-ish.
_ASSIGNMENT = re.compile(
    r"""(?ix)
    (\b[\w.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|
      client[_-]?secret|credential|auth)[\w.\-]*['"]?\s*(?:=>|:=|=|:)\s*)
    (["']?)([^\s"',;)}]{4,})(\2)
    """)
_PLACEHOLDER = re.compile(r"(?i)^(env\(|os\.environ|process\.env|getenv|\$\{|\{\{|<|\*+$|changeme|none|null|true|false|"
                          r"config\(|settings\.|request\.|self\.|this\.|\$|"
                          # SQL / format placeholders and bind parameters: "password = ?", "= :password", "(:pw)", "%s"
                          r"\?|:\w|\(|%[sd(]|@\w|\[)")


def mask_secrets(text: str | None) -> str | None:
    if not text:
        return text
    for pattern in _PATTERNS:
        text = pattern.sub(MASK, text)

    def _assign(m: re.Match) -> str:
        value = m.group(3)
        if _PLACEHOLDER.match(value):
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}{MASK}{m.group(4)}"

    return _ASSIGNMENT.sub(_assign, text)


def mask_span(line: str, start_col: int, end_col: int) -> str:
    """Mask a 1-based inclusive column span (as reported by Gitleaks)."""
    start = max(start_col - 1, 0)
    end = max(end_col, start + 1)
    return line[:start] + MASK + line[end:]


def mask_string_literals(text: str) -> str:
    """Mask quoted literals on a line (used for hard-coded credential findings)."""
    return re.sub(r"""(["'])(?:(?!\1).){4,}\1""", lambda m: f"{m.group(1)}{MASK}{m.group(1)}", text)
