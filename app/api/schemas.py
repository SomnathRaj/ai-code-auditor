"""Request body schemas. Field errors become `details` in the error envelope."""
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from ..services.repository_service import BRANCH_RE, GITHUB_URL_RE

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ACCESS_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.]+$")  # GitHub PATs: ghp_…, github_pat_…
MIN_PASSWORD_LENGTH = 10

Trimmed = Annotated[str, StringConstraints(strip_whitespace=True)]


class _Body(BaseModel):
    model_config = ConfigDict(extra="ignore")


def _email(value: str) -> str:
    value = value.strip().lower()
    if not EMAIL_RE.match(value) or len(value) > 255:
        raise ValueError("A valid email is required")
    return value


class RegisterIn(_Body):
    name: Trimmed
    email: str
    password: str
    organization_name: Trimmed | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not v or len(v) > 120:
            raise ValueError("Name is required (max 120 characters)")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return _email(v)

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        if len(v) > 256:
            raise ValueError("Password is too long")
        return v

    @field_validator("organization_name")
    @classmethod
    def _org(cls, v: str | None) -> str | None:
        if v and len(v) > 120:
            raise ValueError("Organization name is too long (max 120 characters)")
        return v or None


class LoginIn(_Body):
    email: str
    password: Annotated[str, StringConstraints(max_length=256)]

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()


class SwitchOrganizationIn(_Body):
    organization_id: str


def _branch(v: str | None) -> str | None:
    if v is None or v == "":
        return None
    if not BRANCH_RE.match(v):
        raise ValueError("Invalid branch name")
    return v


def _name(v: str | None) -> str | None:
    if v and len(v) > 200:
        raise ValueError("Name is too long (max 200 characters)")
    return v or None


def _access_token(v: str | None) -> str | None:
    if v is None or v == "":
        return None
    if len(v) > 500 or not ACCESS_TOKEN_RE.match(v):
        raise ValueError("Access token has an invalid format")
    return v


class RepositoryCreateIn(_Body):
    url: Trimmed
    default_branch: Trimmed | None = None  # None = the repository's default branch on GitHub
    name: Trimmed | None = None
    access_token: Trimmed | None = None  # for private repositories; stored encrypted

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        if not GITHUB_URL_RE.match(v):
            raise ValueError("Enter a GitHub URL like https://github.com/owner/repo")
        return v

    @field_validator("default_branch")
    @classmethod
    def _v_branch(cls, v: str | None) -> str | None:
        return _branch(v)

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str | None) -> str | None:
        return _name(v)

    @field_validator("access_token")
    @classmethod
    def _v_token(cls, v: str | None) -> str | None:
        return _access_token(v)


class RepositoryUpdateIn(_Body):
    """PATCH: only fields present in the body change (see model_fields_set).
    `access_token: null` or "" removes the stored token."""
    name: Trimmed | None = None
    default_branch: Trimmed | None = None
    access_token: Trimmed | None = None

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str | None) -> str:
        if not v:
            raise ValueError("Name cannot be empty")
        return _name(v)

    @field_validator("default_branch")
    @classmethod
    def _v_branch(cls, v: str | None) -> str:
        if not v:
            raise ValueError("Branch cannot be empty")
        return _branch(v)

    @field_validator("access_token")
    @classmethod
    def _v_token(cls, v: str | None) -> str | None:
        return _access_token(v)


class StartAuditIn(_Body):
    branch: Trimmed | None = None  # GitHub only; defaults to the repository's default branch
    audit_type: Trimmed = "full"

    @field_validator("branch")
    @classmethod
    def _v_branch(cls, v: str | None) -> str | None:
        return _branch(v)

    @field_validator("audit_type")
    @classmethod
    def _v_type(cls, v: str) -> str:
        from ..constants import AUDIT_TYPES
        if v not in AUDIT_TYPES:
            raise ValueError(f"audit_type must be one of: {', '.join(AUDIT_TYPES)}")
        return v


class RepositorySettingsIn(_Body):
    """PUT /repositories/{id}/settings — replaces the audit settings (PRD §37)."""
    enabled_scanners: list[str]
    excluded_paths: list[Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]]
    severity_threshold: str
    ai_enabled: bool

    @field_validator("enabled_scanners")
    @classmethod
    def _v_scanners(cls, v: list[str]) -> list[str]:
        allowed = {"semgrep", "gitleaks", "dependencies"}
        if not v or not set(v) <= allowed:
            raise ValueError("Choose at least one of: semgrep, gitleaks, dependencies")
        return sorted(set(v))

    @field_validator("excluded_paths")
    @classmethod
    def _v_paths(cls, v: list[str]) -> list[str]:
        if len(v) > 100:
            raise ValueError("At most 100 excluded paths")
        for p in v:
            if ".." in p.split("/") or p.startswith("/") or "\x00" in p:
                raise ValueError(f"Invalid excluded path: {p}")
        return list(dict.fromkeys(v))

    @field_validator("severity_threshold")
    @classmethod
    def _v_threshold(cls, v: str) -> str:
        if v not in ("critical", "high", "medium", "low", "info"):
            raise ValueError("severity_threshold must be critical, high, medium, low or info")
        return v


class FindingUpdateIn(_Body):
    status: Trimmed
    comment: Annotated[str, StringConstraints(strip_whitespace=True, max_length=5000)] | None = None

    @field_validator("status")
    @classmethod
    def _v_status(cls, v: str) -> str:
        from ..constants import FINDING_STATUSES
        if v not in FINDING_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(FINDING_STATUSES)}")
        return v

    @field_validator("comment")
    @classmethod
    def _v_comment(cls, v: str | None) -> str | None:
        return v or None


class CommentIn(_Body):
    body: Annotated[str, StringConstraints(strip_whitespace=True, max_length=5000)]

    @field_validator("body")
    @classmethod
    def _v_body(cls, v: str) -> str:
        if not v:
            raise ValueError("Comment cannot be empty")
        return v


class RetentionIn(_Body):
    audit_days: int | None = None
    source_days: int | None = None

    @field_validator("audit_days", "source_days")
    @classmethod
    def _v_days(cls, v: int | None) -> int | None:
        from ..services.organization_service import RETENTION_CHOICES
        if v is not None and v not in RETENTION_CHOICES:
            raise ValueError(f"must be one of {', '.join(map(str, RETENTION_CHOICES))} (0 = keep forever)")
        return v


class OrganizationUpdateIn(_Body):
    name: Trimmed | None = None
    retention: RetentionIn | None = None

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str | None) -> str | None:
        if v is not None and (not v or len(v) > 120):
            raise ValueError("Name is required (max 120 characters)")
        return v


def _role(v: str) -> str:
    from ..constants import ROLES
    if v not in ROLES:
        raise ValueError(f"role must be one of: {', '.join(ROLES)}")
    return v


class MemberAddIn(_Body):
    email: str
    role: Trimmed = "developer"

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _email(v)

    @field_validator("role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        return _role(v)


class MemberRoleIn(_Body):
    role: Trimmed

    @field_validator("role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        return _role(v)


class UploadNameIn(_Body):
    name: Trimmed | None = None

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str | None) -> str | None:
        return _name(v)
