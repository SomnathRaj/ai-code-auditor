"""AI analysis of scanner findings (PRD §26-27, §51, §70-71).

    Scanner finding → select (cost control) → relevant code (masked) → cache? → AI → validate → store

- Only code findings (Semgrep) at or above AI_MIN_SEVERITY are sent; secrets and
  dependency advisories never are (nothing to reason about, and secrets must not leave).
- At most AI_MAX_FINDINGS per audit, most severe first; the rest are marked skipped.
- Results are cached per organization by (rule, file, code, model, prompt version),
  so re-auditing unchanged code costs nothing.
- AI output never changes a finding's status or severity: it is advice for the
  human reviewer (PRD §86).
"""
import hashlib
import random
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from ..scanners.cancel import NEVER, CancelToken
from ..scanners.models import SEVERITY_ORDER, Finding, ProjectInfo
from .context import extract_context
from .prompt import PROMPT_VERSION, RESPONSE_SCHEMA, SYSTEM_PROMPT, build_user_prompt, correction_prompt
from .providers import AIProvider, AIProviderError
from .validation import InvalidAnswer, parse_and_validate

AI_SCANNERS = {"semgrep"}
NEVER_SENT_CATEGORIES = {"Secrets"}
BREAKER_THRESHOLD = 5  # consecutive failed findings before giving up on the audit


class RateLimiter:
    """Shared by all AI requests of an audit: spaces request starts to stay under a
    requests-per-minute quota, and pauses everyone after a rate-limit response."""

    def __init__(self, per_minute: int = 0):
        self._lock = threading.Lock()
        self._interval = 60.0 / per_minute if per_minute else 0.0
        self._next = 0.0

    def set_per_minute(self, per_minute: int) -> None:
        with self._lock:
            self._interval = max(self._interval, 60.0 / max(per_minute, 1))

    def cooldown(self, seconds: float) -> None:
        with self._lock:
            self._next = max(self._next, time.monotonic() + seconds)

    def acquire(self, cancel: CancelToken) -> None:
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self._interval
        delay = start - now
        if delay > 0 and cancel.wait(delay):
            cancel.raise_if_cancelled()


@dataclass
class AIConfig:
    provider: AIProvider
    scope: str                     # organization id: cache namespace (no cross-tenant sharing)
    min_severity: str = "medium"
    max_findings: int = 50
    concurrency: int = 4
    max_retries: int = 2
    rate_limit_retries: int = 8     # waits on 429 (separate budget from invalid-answer retries)
    requests_per_minute: int = 0    # 0 = learn it from the provider's rate-limit responses
    context_max_lines: int = 120
    cache_get: Callable[[str], dict | None] = lambda key: None
    cache_put: Callable[[str, dict], None] = lambda key, value: None


@dataclass
class AIStats:
    provider: str
    model: str
    selected: int = 0
    analyzed: int = 0
    cached: int = 0
    failed: int = 0
    skipped_limit: int = 0
    likely_false_positives: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    rate_limit_waits: int = 0
    error: str | None = None
    duration: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "lock"}


def _eligible(f: Finding, min_rank: int) -> bool:
    return (f.scanner in AI_SCANNERS and f.category not in NEVER_SENT_CATEGORIES
            and SEVERITY_ORDER.get(f.severity, 0) >= min_rank and f.line_start)


def cache_key(scope: str, f: Finding, digest: str, start_line: int, model: str) -> str:
    raw = "\x1f".join([scope, f.rule_id, f.file, str(start_line), digest, model, PROMPT_VERSION])
    return hashlib.sha256(raw.encode()).hexdigest()


def _base(cfg: AIConfig) -> dict:
    return {"provider": cfg.provider.name, "model": cfg.provider.model, "prompt_version": PROMPT_VERSION}


def _call(cfg: AIConfig, user_prompt: str, ctx, cancel: CancelToken, stats: AIStats,
          limiter: RateLimiter) -> tuple[dict, int]:
    """One finding: ask, validate, retry on invalid answers or transient errors."""
    prompt = user_prompt
    attempts = 0
    rate_waits = 0
    last_error = "unknown error"
    header_lines = {int(line.split()[0]) for line in ctx.text.splitlines()
                    if line.strip() and line.split()[0].isdigit() and int(line.split()[0]) < ctx.start_line}
    while attempts <= cfg.max_retries:
        cancel.raise_if_cancelled()
        attempts += 1
        limiter.acquire(cancel)
        try:
            resp = cfg.provider.generate_json(SYSTEM_PROMPT, prompt, RESPONSE_SCHEMA)
        except AIProviderError as err:
            last_error = err.message
            if err.fatal or not err.retryable:
                raise
            if err.rate_limited and rate_waits < cfg.rate_limit_retries:
                rate_waits += 1
                attempts -= 1  # waiting for quota isn't a failed attempt
                with stats.lock:
                    stats.rate_limit_waits += 1
                if err.quota_per_minute:
                    limiter.set_per_minute(err.quota_per_minute)
                limiter.cooldown(err.retry_after if err.retry_after is not None else 10.0)
                continue
            delay = err.retry_after or min(30.0, 2 ** attempts + random.random())
            if cancel.wait(delay):
                cancel.raise_if_cancelled()
            continue
        with stats.lock:
            stats.input_tokens += resp.input_tokens
            stats.output_tokens += resp.output_tokens
        try:
            analysis = parse_and_validate(resp.text, ctx.start_line, ctx.end_line, header_lines)
            return analysis.model_dump(), attempts
        except InvalidAnswer as err:
            last_error = "invalid answer: " + "; ".join(err.errors)
            prompt = user_prompt + "\n\n" + correction_prompt(err.errors)
    raise AIProviderError(last_error, retryable=False)


def analyze_findings(findings: list[Finding], source_dir: str, project: ProjectInfo, cfg: AIConfig, *,
                     progress: Callable[[str], None] = lambda detail: None,
                     cancel: CancelToken = NEVER) -> AIStats:
    """Fill `finding.ai` (and `finding.function`) in place. Never raises for AI failures;
    raises Cancelled if the audit is cancelled."""
    t0 = time.monotonic()
    stats = AIStats(provider=cfg.provider.name, model=cfg.provider.model)
    min_rank = SEVERITY_ORDER.get(cfg.min_severity, 2)

    eligible = [f for f in findings if _eligible(f, min_rank)]
    eligible_ids = {id(f) for f in eligible}
    for f in findings:
        if id(f) not in eligible_ids:
            f.ai = {"status": "skipped", "reason": "not_applicable" if f.scanner not in AI_SCANNERS
                    or f.category in NEVER_SENT_CATEGORIES else "below_threshold"}
    eligible.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.confidence, f.file, f.line_start))
    selected, over = eligible[:cfg.max_findings], eligible[cfg.max_findings:]
    for f in over:
        f.ai = {"status": "skipped", "reason": "limit"}
    stats.selected, stats.skipped_limit = len(selected), len(over)

    # Build contexts; serve cache hits; group identical requests.
    todo: dict[str, tuple] = {}
    for f in selected:
        ctx = extract_context(source_dir, f.file, f.line_start, f.line_end, cfg.context_max_lines)
        if ctx is None:
            f.ai = {"status": "skipped", "reason": "no_context"}
            continue
        f.function = ctx.function
        key = cache_key(cfg.scope, f, ctx.digest, ctx.start_line, cfg.provider.model)
        context_info = {"start_line": ctx.start_line, "end_line": ctx.end_line, "function": ctx.function}
        cached = cfg.cache_get(key)
        if cached:
            f.ai = {**_base(cfg), **cached, "status": "completed", "cached": True, "context": context_info}
            stats.cached += 1
            continue
        if key in todo:
            todo[key][1].append(f)
        else:
            todo[key] = (ctx, [f], context_info)
    progress(f"{stats.cached} cached, {len(todo)} to analyse")

    consecutive_failures = 0
    breaker = threading.Event()
    limiter = RateLimiter(cfg.requests_per_minute)

    def work(key: str):
        ctx, group, _info = todo[key]
        if breaker.is_set():
            raise AIProviderError(stats.error or "AI analysis stopped", retryable=False)
        f = group[0]
        prompt = build_user_prompt(f.to_dict(), ctx.text, ctx.language or project.primary_language, project.frameworks)
        return _call(cfg, prompt, ctx, cancel, stats, limiter)

    pool = ThreadPoolExecutor(max_workers=max(1, cfg.concurrency), thread_name_prefix="ai")
    try:
        pending = {pool.submit(work, key): key for key in todo}
        while pending:
            done, _ = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            cancel.raise_if_cancelled()
            for fut in done:
                key = pending.pop(fut)
                _ctx, group, info = todo[key]
                try:
                    analysis, attempts = fut.result()
                except AIProviderError as err:
                    stats.failed += len(group)
                    consecutive_failures += 1
                    if err.fatal or consecutive_failures >= BREAKER_THRESHOLD:
                        stats.error = stats.error or err.message
                        breaker.set()
                    for f in group:
                        f.ai = {**_base(cfg), "status": "failed", "error": err.message[:300], "context": info}
                    continue
                consecutive_failures = 0
                cfg.cache_put(key, analysis)
                for f in group:
                    f.ai = {**_base(cfg), **analysis, "status": "completed", "cached": False,
                            "attempts": attempts, "context": info}
                    stats.analyzed += 1
                    if analysis["verdict"] == "false_positive":
                        stats.likely_false_positives += 1
                progress(f"{stats.analyzed + stats.cached}/{stats.selected} analysed")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    stats.likely_false_positives += sum(1 for f in findings if (f.ai or {}).get("cached")
                                        and f.ai.get("verdict") == "false_positive")
    stats.duration = round(time.monotonic() - t0, 2)
    return stats
