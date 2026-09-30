"""AI providers. Gemini is the configured provider (PRD §64); the small interface keeps
the analyzer independent of it (and lets tests use a fake).

The Gemini adapter calls the REST API directly (no SDK):
POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
with the key in the `x-goog-api-key` header (never in the URL, never logged).
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


class AIProviderError(Exception):
    def __init__(self, message: str, *, retryable: bool, status: int | None = None, retry_after: float | None = None,
                 fatal: bool = False, rate_limited: bool = False, quota_per_minute: int | None = None):
        super().__init__(message)
        self.message = message
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after
        self.fatal = fatal  # e.g. invalid API key or daily quota used up: stop analysing the rest of the audit
        self.rate_limited = rate_limited  # per-minute quota: wait and continue
        self.quota_per_minute = quota_per_minute  # the provider's reported limit, used to pace requests


@dataclass
class AIResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: str | None = None


class AIProvider(Protocol):
    name: str
    model: str

    def generate_json(self, system: str, user: str, schema: dict) -> AIResponse: ...


class GeminiProvider:
    name = "gemini"
    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, api_key: str, model: str, timeout: float = 60, temperature: float = 0.1,
                 max_output_tokens: int = 4096, base_url: str | None = None):
        self._api_key = api_key
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.base_url = (base_url or self.BASE_URL).rstrip("/")

    def generate_json(self, system: str, user: str, schema: dict) -> AIResponse:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": schema,
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
            },
        }
        req = urllib.request.Request(
            f"{self.base_url}/models/{self.model}:generateContent", method="POST",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "x-goog-api-key": self._api_key,
                     "User-Agent": "ai-code-auditor/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (fixed https URL)
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as err:
            raise self._http_error(err)
        except (urllib.error.URLError, TimeoutError) as err:
            raise AIProviderError(f"Gemini request failed: {getattr(err, 'reason', err)}", retryable=True)
        except ValueError:
            raise AIProviderError("Gemini returned a non-JSON response", retryable=True)

        candidates = data.get("candidates") or []
        if not candidates:
            reason = (data.get("promptFeedback") or {}).get("blockReason", "no candidates")
            raise AIProviderError(f"Gemini returned no answer ({reason})", retryable=False)
        cand = candidates[0]
        finish = cand.get("finishReason")
        parts = (cand.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        usage = data.get("usageMetadata") or {}
        if finish not in (None, "STOP") and not text:
            raise AIProviderError(f"Gemini stopped early ({finish})", retryable=finish == "MAX_TOKENS")
        return AIResponse(text=text, input_tokens=int(usage.get("promptTokenCount") or 0),
                          output_tokens=int(usage.get("candidatesTokenCount") or 0), finish_reason=finish)

    @staticmethod
    def _http_error(err: urllib.error.HTTPError) -> AIProviderError:
        details: list = []
        try:
            payload = json.loads(err.read().decode())
            info = payload.get("error") or {}
            message = info.get("message") or err.reason
            details = [d for d in info.get("details") or [] if isinstance(d, dict)]
        except (ValueError, AttributeError):
            message = str(err.reason)
        message = str(message).split("\n")[0].split(" For more information")[0]  # drop the long help text
        reasons = {d.get("reason") for d in details}
        retry_after = None
        if err.headers and err.headers.get("Retry-After"):
            try:
                retry_after = float(err.headers["Retry-After"])
            except ValueError:
                pass
        # Gemini reports the wait time in google.rpc.RetryInfo ("11s") and the quota in QuotaFailure.
        for d in details:
            if d.get("@type", "").endswith("RetryInfo") and str(d.get("retryDelay", "")).endswith("s"):
                try:
                    retry_after = float(d["retryDelay"][:-1])
                except ValueError:
                    pass
        quota_ids, per_minute = [], None
        for d in details:
            for v in d.get("violations") or []:
                quota_ids.append(v.get("quotaId", ""))
                if "PerMinute" in v.get("quotaId", "") and "Request" in v.get("quotaId", ""):
                    try:
                        per_minute = int(v.get("quotaValue"))
                    except (TypeError, ValueError):
                        pass
        if err.code == 429:
            daily = any("PerDay" in q for q in quota_ids)
            if daily:
                return AIProviderError(f"Gemini daily quota exhausted: {message}", retryable=False, status=429,
                                       fatal=True)
            return AIProviderError(f"Gemini rate limit: {message}", retryable=True, status=429,
                                   retry_after=retry_after, rate_limited=True, quota_per_minute=per_minute)
        fatal = err.code in (401, 403) or "API_KEY_INVALID" in reasons or \
            (err.code == 404 and "model" in str(message).lower())
        retryable = err.code in (408, 500, 502, 503, 504)
        return AIProviderError(f"Gemini API error {err.code}: {message}", retryable=retryable, status=err.code,
                               retry_after=retry_after, fatal=fatal)


def provider_from_config(cfg: dict) -> AIProvider | None:
    """The configured provider, or None when AI analysis isn't configured."""
    if not cfg.get("AI_ENABLED"):
        return None
    if cfg.get("AI_PROVIDER", "gemini") == "gemini" and cfg.get("GEMINI_API_KEY"):
        return GeminiProvider(cfg["GEMINI_API_KEY"], cfg["GEMINI_MODEL"], timeout=cfg["AI_TIMEOUT_SECONDS"],
                              base_url=cfg.get("GEMINI_BASE_URL"))
    return None
