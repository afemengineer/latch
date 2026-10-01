"""Closed V0 enums used by the trusted core.

These types deliberately contain no model/provider concepts.
"""

from enum import StrEnum


class Operation(StrEnum):
    FILESYSTEM_INSPECT = "filesystem.inspect"
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_COPY = "filesystem.copy"
    FILESYSTEM_MOVE = "filesystem.move"
    FILESYSTEM_RENAME = "filesystem.rename"


class RiskLevel(StrEnum):
    OBSERVE = "observe"
    READ = "read"
    REVERSIBLE_WRITE = "reversible_write"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    DESTRUCTIVE = "destructive"
    PROHIBITED = "prohibited"


class DataLabel(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOCAL_ONLY = "local_only"
    SECRET = "secret"
    SEALED_SECRET = "sealed_secret"


class DecisionOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class TaskState(StrEnum):
    CREATED = "created"
    CONTEXT_READY = "context_ready"
    MODEL_DECISION = "model_decision"
    ACTION_PROPOSED = "action_proposed"
    POLICY_EVALUATION = "policy_evaluation"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    OBSERVED = "observed"
    RECOVERY = "recovery"
    COMPLETED = "completed"
    FAILED = "failed"


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class PathPlatform(StrEnum):
    WINDOWS = "windows"
    POSIX = "posix"
