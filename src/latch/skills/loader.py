"""Strict YAML-frontmatter + Markdown skill loader.

Skills are declarative. Loading a skill never imports or executes code from the
skill file.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import yaml

from latch.core.capabilities import (
    ConstraintSet,
    FilesystemResourceSelector,
    ServiceResourceSelector,
)
from latch.core.ids import SkillId
from latch.core.permissions import CapabilityCeilingRule, PermissionEnvelope
from latch.core.types import Operation, PathPlatform
from latch.skills.models import SkillDefinition, SkillManifestError

_TOP_LEVEL = {"id", "name", "description", "capabilities", "instructions"}
_CAPABILITY_FIELDS = {"operation", "resource", "constraints"}
_CONSTRAINT_FIELDS = {"max_operations", "max_bytes", "overwrite"}
_FILESYSTEM_FIELDS = {"type", "root", "recursive", "exclude_globs"}
_SERVICE_FIELDS = {"type", "id"}
_FILESYSTEM_OPERATIONS = {
    Operation.FILESYSTEM_INSPECT,
    Operation.FILESYSTEM_READ,
    Operation.FILESYSTEM_COPY,
    Operation.FILESYSTEM_MOVE,
    Operation.FILESYSTEM_RENAME,
}


def load_skill_file(
    path: str | Path,
    *,
    platform: PathPlatform,
) -> SkillDefinition:
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    return load_skill_text(text, platform=platform, source=str(source))


def load_skill_text(
    text: str,
    *,
    platform: PathPlatform,
    source: str | None = None,
) -> SkillDefinition:
    frontmatter, body = _split_frontmatter(text)
    try:
        raw = cast(object, yaml.safe_load(frontmatter))
    except yaml.YAMLError as exc:
        raise SkillManifestError("invalid YAML frontmatter") from exc

    manifest = _mapping(raw, "skill frontmatter")
    _reject_unknown(manifest, _TOP_LEVEL, "skill frontmatter")

    skill_id = SkillId(_required_string(manifest, "id"))
    name = _required_string(manifest, "name")
    description = _required_string(manifest, "description")
    instructions = _optional_string(manifest, "instructions") or ""

    raw_capabilities = manifest.get("capabilities")
    if not isinstance(raw_capabilities, list) or not raw_capabilities:
        raise SkillManifestError("capabilities must be a non-empty list")

    rules: list[CapabilityCeilingRule] = []
    for index, raw_capability in enumerate(cast(list[object], raw_capabilities)):
        rules.append(
            _parse_capability(
                _mapping(raw_capability, f"capabilities[{index}]"),
                platform=platform,
            )
        )

    procedure = body.strip()
    combined_instructions = instructions.strip()
    if procedure:
        combined_instructions = (
            f"{combined_instructions}\n\nProcedure:\n{procedure}"
            if combined_instructions
            else f"Procedure:\n{procedure}"
        )

    envelope = PermissionEnvelope(
        skill_id=skill_id,
        display_name=name,
        authority_ceiling=tuple(rules),
    )
    return SkillDefinition(
        skill_id=skill_id,
        name=name,
        description=description,
        instructions=combined_instructions,
        envelope=envelope,
        source=source,
    )


def _split_frontmatter(text: str) -> tuple[str, str]:
    normalized = text.replace("\r\n", "\n")
    if not normalized.startswith("---\n"):
        raise SkillManifestError("skill must start with YAML frontmatter")
    end = normalized.find("\n---\n", 4)
    if end < 0:
        raise SkillManifestError("skill frontmatter closing delimiter is missing")
    return normalized[4:end], normalized[end + 5 :]


def _parse_capability(
    capability: dict[str, object],
    *,
    platform: PathPlatform,
) -> CapabilityCeilingRule:
    _reject_unknown(capability, _CAPABILITY_FIELDS, "capability")
    operation_text = _required_string(capability, "operation")
    try:
        operation = Operation(operation_text)
    except ValueError as exc:
        raise SkillManifestError(f"unsupported capability operation: {operation_text}") from exc

    resource = _mapping(capability.get("resource"), "capability.resource")
    resource_type = _required_string(resource, "type")

    if resource_type == "filesystem":
        if operation not in _FILESYSTEM_OPERATIONS:
            raise SkillManifestError(
                f"{operation.value} cannot target a filesystem resource"
            )
        _reject_unknown(resource, _FILESYSTEM_FIELDS, "filesystem resource")
        root = _required_string(resource, "root")
        recursive = _optional_bool(resource, "recursive", default=True)
        exclude = _optional_string_list(resource, "exclude_globs")
        selector = FilesystemResourceSelector(
            root=root,
            platform=platform,
            recursive=recursive,
            exclude_globs=exclude,
        )
    elif resource_type == "service":
        if operation is not Operation.WEB_SEARCH:
            raise SkillManifestError(
                f"{operation.value} cannot target a service resource"
            )
        _reject_unknown(resource, _SERVICE_FIELDS, "service resource")
        selector = ServiceResourceSelector(_required_string(resource, "id"))
    else:
        raise SkillManifestError(f"unsupported resource type: {resource_type}")

    constraints = _parse_constraints(capability.get("constraints"))
    return CapabilityCeilingRule(
        operations=frozenset({operation}),
        selector=selector,
        constraints=constraints,
    )


def _parse_constraints(raw: object) -> ConstraintSet:
    if raw is None:
        return ConstraintSet()
    value = _mapping(raw, "capability.constraints")
    _reject_unknown(value, _CONSTRAINT_FIELDS, "capability.constraints")
    return ConstraintSet(
        max_operations=_optional_int(value, "max_operations"),
        max_bytes=_optional_int(value, "max_bytes"),
        overwrite=_optional_nullable_bool(value, "overwrite"),
    )


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise SkillManifestError(f"{name} must be a mapping")
    result: dict[str, object] = {}
    for key, item in cast(Mapping[object, object], value).items():
        if not isinstance(key, str):
            raise SkillManifestError(f"{name} keys must be strings")
        result[key] = item
    return result


def _reject_unknown(
    value: Mapping[str, object],
    allowed: set[str],
    name: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SkillManifestError(f"{name} has unknown fields: {unknown}")


def _required_string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result.strip():
        raise SkillManifestError(f"{key} must be a non-empty string")
    if "\x00" in result:
        raise SkillManifestError(f"{key} cannot contain NUL")
    return result.strip()


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise SkillManifestError(f"{key} must be a string")
    return result


def _optional_bool(
    value: Mapping[str, object],
    key: str,
    *,
    default: bool,
) -> bool:
    result = value.get(key)
    if result is None:
        return default
    if not isinstance(result, bool):
        raise SkillManifestError(f"{key} must be a boolean")
    return result


def _optional_nullable_bool(
    value: Mapping[str, object],
    key: str,
) -> bool | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, bool):
        raise SkillManifestError(f"{key} must be a boolean")
    return result


def _optional_int(value: Mapping[str, object], key: str) -> int | None:
    result = value.get(key)
    if result is None:
        return None
    if isinstance(result, bool) or not isinstance(result, int):
        raise SkillManifestError(f"{key} must be an integer")
    return result


def _optional_string_list(
    value: Mapping[str, object],
    key: str,
) -> tuple[str, ...]:
    result = value.get(key)
    if result is None:
        return ()
    if not isinstance(result, list):
        raise SkillManifestError(f"{key} must be a list")
    items: list[str] = []
    for item in cast(list[object], result):
        if not isinstance(item, str) or not item:
            raise SkillManifestError(f"{key} must contain non-empty strings")
        items.append(item)
    return tuple(items)
