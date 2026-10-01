"""Opaque identifiers used by security-relevant records."""

from typing import NewType
from uuid import uuid4

TaskId = NewType("TaskId", str)
GrantId = NewType("GrantId", str)
EvidenceId = NewType("EvidenceId", str)
RequestId = NewType("RequestId", str)
RuleId = NewType("RuleId", str)
SkillId = NewType("SkillId", str)
PermissionId = NewType("PermissionId", str)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def new_task_id() -> TaskId:
    return TaskId(_new_id("task"))


def new_grant_id() -> GrantId:
    return GrantId(_new_id("grant"))


def new_evidence_id() -> EvidenceId:
    return EvidenceId(_new_id("evidence"))


def new_request_id() -> RequestId:
    return RequestId(_new_id("request"))


def new_rule_id() -> RuleId:
    return RuleId(_new_id("rule"))


def new_skill_id() -> SkillId:
    return SkillId(_new_id("skill"))


def new_permission_id() -> PermissionId:
    return PermissionId(_new_id("permission"))
