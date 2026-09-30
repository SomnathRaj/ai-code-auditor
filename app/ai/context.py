"""Relevant-code extraction for AI analysis (PRD §26, §71).

Sends the enclosing function (or a window around the finding) plus the file's
imports — never whole files. Every line is secret-masked before it leaves the server.
"""
import hashlib
import os
import re
from dataclasses import dataclass

from ..scanners.detect import EXTENSIONS
from ..scanners.files import safe_read_lines
from ..scanners.masking import mask_secrets

WINDOW = 15          # lines on each side when no enclosing function is found
HEADER_SCAN = 60     # lines at the top of the file searched for imports
HEADER_MAX = 15
MAX_LINE = 300

_IMPORT = re.compile(r"^\s*(import\s|from\s+\S+\s+import|require\(|const\s+\w+\s*=\s*require\(|use\s+[\w\\]+|"
                     r"package\s|#include|require_once|include_once)")
_STRINGS = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")
_LINE_COMMENT = re.compile(r"(//|#).*$")
_CONTROL = {"if", "for", "while", "switch", "catch", "else", "do", "try", "return", "new", "elseif", "foreach"}

_PY_DEF = re.compile(r"^(\s*)(?:async\s+def|def|class)\s+(\w+)")
_BRACE_FUNC = {
    "JavaScript": re.compile(r"\bfunction\b|=>|^\s*(?:async\s+|static\s+|get\s+|set\s+)*[\w$]+\s*\([^;]*\)\s*\{"),
    "TypeScript": re.compile(r"\bfunction\b|=>|^\s*(?:public|private|protected|async|static|get|set|\s)*[\w$]+\s*\([^;]*\)[^;{]*\{"),
    "PHP": re.compile(r"\bfunction\b"),
    "Java": re.compile(r"^\s*(?:@\w+\s*)*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*"
                       r"[\w<>\[\],.? ]+\s+\w+\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\{?\s*$"),
    "Go": re.compile(r"^\s*func\b"),
}
# Explicit declarations only; anonymous handlers get no name rather than a wrong one.
_DECL_NAMES = [
    re.compile(r"\bfunction\s*\*?\s*([\w$]+)\s*\("),                       # function name( / PHP methods
    re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([\w$]+)\s*\("),                 # Go (incl. methods)
    re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)"),
    re.compile(r"^\s*(?:(?:public|private|protected|static|final|async|synchronized|abstract|get|set)\s+)*"
               r"(?:[\w<>\[\],.?]+\s+)?([\w$]+)\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\{"),  # methods
]


@dataclass
class CodeContext:
    text: str            # numbered, masked lines; finding lines marked with ">>"
    start_line: int
    end_line: int
    function: str | None
    language: str | None
    digest: str          # hash of the masked code (cache key; excludes line numbers)


def language_for(path: str) -> str | None:
    return EXTENSIONS.get(os.path.splitext(path)[1].lower())


def _clean(line: str) -> str:
    return _LINE_COMMENT.sub("", _STRINGS.sub('""', line))


def _python_function(lines: list[str], idx: int) -> tuple[int, int, str] | None:
    target = lines[idx]
    indent = len(target) - len(target.lstrip())
    for i in range(idx, -1, -1):
        m = _PY_DEF.match(lines[i])
        if m and (i == idx or len(m.group(1)) < indent):
            def_indent = len(m.group(1))
            end = len(lines) - 1
            for j in range(i + 1, len(lines)):
                stripped = lines[j].strip()
                if stripped and not stripped.startswith("#") and len(lines[j]) - len(lines[j].lstrip()) <= def_indent:
                    end = j - 1
                    break
            while end > i and not lines[end].strip():
                end -= 1
            start = i
            while start > 0 and lines[start - 1].strip().startswith("@"):  # decorators carry routes/auth
                start -= 1
            return start, end, m.group(2)
    return None


def _brace_function(lines: list[str], idx: int, lang: str, max_lines: int) -> tuple[int, int, str | None] | None:
    """The outermost enclosing function that fits in max_lines (callbacks nest inside
    request handlers, and the handler is where the tainted input comes from)."""
    func_re = _BRACE_FUNC.get(lang)
    if func_re is None:
        return None
    depth, best, innermost = 0, None, None
    for i in range(idx, -1, -1):
        code = _clean(lines[i])
        depth += code.count("}") - code.count("{")
        if depth < 0 or (i == idx and "{" in code):
            # The signature may span a few lines before the opening brace; patterns are line-anchored.
            signature_lines = [_clean(lines[k]) for k in range(max(0, i - 2), i + 1)]
            words = re.findall(r"[A-Za-z_]+", _clean(lines[i]))
            if any(func_re.search(sl) for sl in signature_lines) and not (words and words[0] in _CONTROL):
                end = _block_end(lines, i)
                candidate = (i, end, _name(lines[i]))
                innermost = innermost or candidate
                if end - i + 1 > max_lines:
                    break
                best = candidate
            depth = 0  # continue outward past if/for/class blocks and nested functions
    return best or innermost


def _block_end(lines: list[str], start: int) -> int:
    depth, opened = 0, False
    for j in range(start, len(lines)):
        code = _clean(lines[j])
        depth += code.count("{") - code.count("}")
        opened = opened or "{" in code
        if opened and depth <= 0:
            return j
    return len(lines) - 1


def _name(line: str) -> str | None:
    code = _clean(line)
    for pattern in _DECL_NAMES:
        m = pattern.search(code)
        if m and m.group(1) not in _CONTROL:
            return m.group(1)
    return None


def extract_context(source_dir: str, file: str, line_start: int | None, line_end: int | None,
                    max_lines: int = 120) -> CodeContext | None:
    if not line_start:
        return None
    lines = safe_read_lines(source_dir, file)
    if not lines or line_start > len(lines):
        return None
    lang = language_for(file)
    idx = line_start - 1
    end_idx = min((line_end or line_start) - 1, len(lines) - 1)

    found = _python_function(lines, idx) if lang == "Python" else _brace_function(lines, idx, lang or "", max_lines)
    function = None
    if found and found[1] - found[0] + 1 <= max_lines and found[0] <= idx <= found[1]:
        first, last, function = found
        last = max(last, end_idx)
    else:
        if found:
            function = found[2]
        first = max(0, idx - WINDOW)
        last = min(len(lines) - 1, end_idx + WINDOW, first + max_lines - 1)

    header = [i for i in range(min(HEADER_SCAN, first)) if _IMPORT.match(lines[i])][:HEADER_MAX]
    out = []
    for i in header:
        out.append(f"{i + 1:>5}   {lines[i][:MAX_LINE]}")
    if header and header[-1] < first - 1:
        out.append("  ...")
    for i in range(first, last + 1):
        marker = ">>" if idx <= i <= end_idx else "  "
        out.append(f"{i + 1:>5} {marker} {lines[i][:MAX_LINE]}")
    text = mask_secrets("\n".join(out))
    code_only = "\n".join(line[9:] for line in text.splitlines())
    return CodeContext(text=text, start_line=first + 1, end_line=last + 1, function=function, language=lang,
                       digest=hashlib.sha256(code_only.encode()).hexdigest())
