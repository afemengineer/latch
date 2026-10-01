"""In-memory registry for declarative skill behavior."""

from __future__ import annotations

from latch.core.ids import SkillId
from latch.skills.models import SkillDefinition


class SkillRegistry:
    def __init__(self, skills: tuple[SkillDefinition, ...] = ()) -> None:
        self._skills: dict[SkillId, SkillDefinition] = {}
        for skill in skills:
            self.register(skill)

    def register(self, skill: SkillDefinition) -> None:
        if skill.skill_id in self._skills:
            raise ValueError(f"skill already registered: {skill.skill_id}")
        self._skills[skill.skill_id] = skill

    def get(self, skill_id: SkillId) -> SkillDefinition | None:
        return self._skills.get(skill_id)

    def require(self, skill_id: SkillId) -> SkillDefinition:
        try:
            return self._skills[skill_id]
        except KeyError as exc:
            raise KeyError(f"unknown declarative skill: {skill_id}") from exc

    def all(self) -> tuple[SkillDefinition, ...]:
        return tuple(sorted(self._skills.values(), key=lambda item: str(item.skill_id)))
