"""Declarative skill definitions."""

from __future__ import annotations

from dataclasses import dataclass

from latch.core.ids import SkillId
from latch.core.permissions import PermissionEnvelope


class SkillManifestError(ValueError):
    """A declarative skill manifest is invalid or unsafe to interpret."""


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    skill_id: SkillId
    name: str
    description: str
    instructions: str
    envelope: PermissionEnvelope
    source: str | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.description:
            raise ValueError("skill name/description must not be empty")
        if self.envelope.skill_id != self.skill_id:
            raise ValueError("skill definition and permission envelope IDs differ")
