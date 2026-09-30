ROLES = ("owner", "admin", "developer", "viewer")
SEVERITIES = ("critical", "high", "medium", "low", "info")
AUDIT_TYPES = ("full", "security", "dependency", "secret", "quick")
AUDIT_STATUSES = (
    "queued", "cloning", "detecting", "scanning", "dependency_analysis",
    "ai_analysis", "processing", "completed", "failed", "cancelled",
)
FINDING_STATUSES = (
    "new", "confirmed", "in_progress", "resolved", "verified",
    "false_positive", "accepted_risk", "ignored",
)
OPEN_FINDING_STATUSES = ("new", "confirmed", "in_progress")

# Finding lifecycle (PRD §31-32): allowed status changes. "new" from a closed state = reopen.
FINDING_TRANSITIONS = {
    "new": ("confirmed", "in_progress", "resolved", "false_positive", "accepted_risk", "ignored"),
    "confirmed": ("in_progress", "resolved", "false_positive", "accepted_risk", "ignored", "new"),
    "in_progress": ("confirmed", "resolved", "false_positive", "accepted_risk", "ignored", "new"),
    "resolved": ("verified", "in_progress", "new"),
    "verified": ("new",),
    "false_positive": ("new",),
    "accepted_risk": ("new",),
    "ignored": ("new",),
}
# Decisions that hide a finding from the score (and are remembered for later audits) need a reason.
REASON_REQUIRED_STATUSES = ("false_positive", "accepted_risk", "ignored")
REPOSITORY_PROVIDERS = ("github", "zip")

# Roles allowed to perform each class of action (PRD §56).
CAN_MANAGE_REPOS = ("owner", "admin")
CAN_RUN_AUDITS = ("owner", "admin", "developer")
