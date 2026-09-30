# AI Code Auditor Semgrep ruleset

These rules are our own. We deliberately don't use the Semgrep Registry (`p/default` etc.): registry rules are under the *Semgrep Rules License*, which restricts using them in a product that competes with Semgrep. The Semgrep **engine** is LGPL-2.1 and is run as a separate program, which is fine. Extra configs can be enabled with `SEMGREP_EXTRA_CONFIGS` after a licence review.

| File | Language | Rules |
|---|---|---|
| `python.yml` | Python (Flask, Django, generic) | 18 |
| `javascript.yml` | JavaScript / TypeScript (Node, Express, React, browser) | 17 |
| `php.yml` | PHP (plain, Laravel, Blade) | 15 |
| `java.yml` | Java (JDBC, Spring) | 6 |
| `go.yml` | Go (net/http, Gin) | 6 |
| `config.yml` | `.env` / settings files | 2 |

## Rule conventions

- `id` is `aca-<language>-<issue>` and must stay stable: finding fingerprints and triage decisions (false positive, accepted risk) depend on it.
- `metadata` drives normalization (PRD §28–30):
  - `title`: short name shown in the UI.
  - `category`: `Injection`, `XSS`, `File Security`, `SSRF`, `Cryptography`, `Authentication`, `Authorization`, `API Security`, `Configuration`, `Information Disclosure`, `Secrets`.
  - `aca_severity`: `critical | high | medium | low | info`.
  - `aca_confidence`: `high | medium | low` (becomes 0.9 / 0.7 / 0.4).
  - `cwe`, `owasp` (e.g. `CWE-89`, `A03:2021`) and `recommendation`.
- Prefer precise patterns over broad ones. A noisy rule costs more trust than a missed edge case.
- `metavariable-regex` on a metavariable that isn't bound by every `pattern-either` branch silently filters that branch out. Put such checks inside the branch that binds it.
- YAML: patterns containing `: ` must be block scalars (`pattern: |`). `scripts/fix_rule_yaml.py` rewrites them.

## Testing

Every rule has cases in `tests/semgrep_rules/<file>`. A line after `# ruleid: <id>` must match; a line after `# ok: <id>` must not.

```bash
.venv/bin/semgrep --test --metrics=off --config app/scanners/rules/python.yml tests/semgrep_rules/python.py
.venv/bin/pytest -q tests/test_scanner_engine.py -k rule_suites   # all suites
```

Rules scoped by path (`*settings*.py`, `*.blade.php`, `.env`) are covered by `test_engine_end_to_end`.
