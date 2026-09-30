"""Rewrite single-line Semgrep patterns that YAML can't parse (contain ': ') as block scalars."""
import re
import sys

LINE = re.compile(r"^(\s*)(- )?(pattern(?:-inside|-not|-not-inside|-regex)?): (.+)$")

for path in sys.argv[1:]:
    out = []
    for line in open(path).read().splitlines():
        m = LINE.match(line)
        if m and ": " in m.group(4) and not m.group(4).startswith(("|", '"', "'")):
            indent, dash, key, value = m.groups()
            prefix = indent + (dash or "")
            out.append(f"{prefix}{key}: |")
            out.append(" " * (len(prefix) + 2) + value)
        else:
            out.append(line)
    open(path, "w").write("\n".join(out) + "\n")
