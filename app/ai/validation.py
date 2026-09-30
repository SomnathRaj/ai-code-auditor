"""Validation of AI answers (PRD §51): structure, ranges, consistency, grounding.

An answer that fails is retried with the errors fed back; after the retries the
finding keeps only its scanner evidence (AI output is never required).
"""
import json
import re
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, ValidationError, field_validator

from ..scanners.masking import mask_secrets
from .prompt import SEVERITIES, VERDICTS


def _text(max_len: int):
    return Annotated[str, StringConstraints(strip_whitespace=True, max_length=max_len)]


class AIAnalysis(BaseModel):
    verdict: str
    confidence: float = Field(ge=0, le=1)
    false_positive_probability: float = Field(ge=0, le=1)
    severity: str
    title: _text(120)
    explanation: _text(4000)
    impact: _text(2000)
    attack_scenario: _text(2000) = ""
    recommendation: _text(3000)
    fixed_code: _text(6000) = ""
    missing_context: list[_text(300)] = Field(default_factory=list, max_length=10)
    evidence_lines: list[int] = Field(default_factory=list, max_length=50)
    cwe: _text(20) = ""

    @field_validator("verdict")
    @classmethod
    def _verdict(cls, v):
        if v not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        return v

    @field_validator("severity")
    @classmethod
    def _severity(cls, v):
        v = v.lower()
        if v not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        return v

    @field_validator("cwe")
    @classmethod
    def _cwe(cls, v):
        if v and not re.fullmatch(r"CWE-\d{1,5}", v):
            raise ValueError("cwe must look like CWE-89 or be empty")
        return v


class InvalidAnswer(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _strip_fences(text: str) -> str:
    text = text.strip()
    m = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
    return m.group(1) if m else text


def parse_and_validate(text: str, context_start: int, context_end: int, header_lines: set[int]) -> AIAnalysis:
    try:
        data = json.loads(_strip_fences(text))
    except ValueError:
        raise InvalidAnswer(["the response was not valid JSON"])
    if not isinstance(data, dict):
        raise InvalidAnswer(["the response must be a JSON object"])
    try:
        a = AIAnalysis.model_validate(data)
    except ValidationError as err:
        raise InvalidAnswer([f"{'.'.join(map(str, e['loc'])) or 'answer'}: {e['msg']}" for e in err.errors()][:8])

    errors = []
    # Contradictions between verdict and probabilities.
    if a.verdict == "true_positive" and a.false_positive_probability > 0.5:
        errors.append("verdict true_positive contradicts false_positive_probability > 0.5")
    if a.verdict == "false_positive" and a.false_positive_probability < 0.5:
        errors.append("verdict false_positive contradicts false_positive_probability < 0.5")
    if not a.explanation:
        errors.append("explanation must not be empty")
    # Grounding: cited lines must exist in the code we supplied.
    valid_lines = set(range(context_start, context_end + 1)) | header_lines
    outside = [n for n in a.evidence_lines if n not in valid_lines]
    if outside:
        errors.append(f"evidence_lines {outside[:5]} are not in the supplied code "
                      f"(valid: {context_start}-{context_end})")
    if a.verdict == "true_positive" and not a.evidence_lines:
        errors.append("a true_positive verdict needs at least one evidence line")
    if errors:
        raise InvalidAnswer(errors)

    # Defence in depth: never store anything that looks like a secret.
    for field in ("explanation", "impact", "attack_scenario", "recommendation", "fixed_code"):
        setattr(a, field, mask_secrets(getattr(a, field)) or "")
    a.missing_context = [mask_secrets(m) for m in a.missing_context]
    return a
