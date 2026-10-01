"""Strict parsing of model-authored action proposals.

The proposal language intentionally contains no grant IDs, permission mutation,
credential values, shell commands, or other authority-bearing fields.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from latch.core.types import Operation


class ProposalParseError(ValueError):
    """Model output did not conform to the narrow action protocol."""


@dataclass(frozen=True, slots=True)
class InspectProposal:
    path: str


@dataclass(frozen=True, slots=True)
class ReadProposal:
    path: str


@dataclass(frozen=True, slots=True)
class CopyProposal:
    source: str
    destination: str


@dataclass(frozen=True, slots=True)
class MoveProposal:
    source: str
    destination: str


@dataclass(frozen=True, slots=True)
class RenameProposal:
    source: str
    destination: str


@dataclass(frozen=True, slots=True)
class WebSearchProposal:
    query: str


@dataclass(frozen=True, slots=True)
class FinishProposal:
    message: str


type ActionProposal = (
    InspectProposal
    | ReadProposal
    | CopyProposal
    | MoveProposal
    | RenameProposal
    | WebSearchProposal
    | FinishProposal
)


def proposal_operation(proposal: ActionProposal) -> Operation | None:
    if isinstance(proposal, InspectProposal):
        return Operation.FILESYSTEM_INSPECT
    if isinstance(proposal, ReadProposal):
        return Operation.FILESYSTEM_READ
    if isinstance(proposal, CopyProposal):
        return Operation.FILESYSTEM_COPY
    if isinstance(proposal, MoveProposal):
        return Operation.FILESYSTEM_MOVE
    if isinstance(proposal, RenameProposal):
        return Operation.FILESYSTEM_RENAME
    if isinstance(proposal, WebSearchProposal):
        return Operation.WEB_SEARCH
    return None


def proposal_action_name(proposal: ActionProposal) -> str:
    operation = proposal_operation(proposal)
    return operation.value if operation is not None else "finish"


def parse_proposal(text: str) -> ActionProposal:
    try:
        raw = cast(object, json.loads(text))
    except json.JSONDecodeError as exc:
        raise ProposalParseError("model output must be one JSON object") from exc

    obj = _object(raw, "proposal")
    _exact_keys(obj, {"action", "arguments"}, "proposal")

    action = obj.get("action")
    if not isinstance(action, str):
        raise ProposalParseError("proposal.action must be a string")

    arguments = _object(obj.get("arguments"), "proposal.arguments")

    if action == Operation.FILESYSTEM_INSPECT.value:
        _exact_keys(arguments, {"path"}, action)
        return InspectProposal(path=_string(arguments, "path"))
    if action == Operation.FILESYSTEM_READ.value:
        _exact_keys(arguments, {"path"}, action)
        return ReadProposal(path=_string(arguments, "path"))
    if action == Operation.FILESYSTEM_COPY.value:
        _exact_keys(arguments, {"source", "destination"}, action)
        return CopyProposal(
            source=_string(arguments, "source"),
            destination=_string(arguments, "destination"),
        )
    if action == Operation.FILESYSTEM_MOVE.value:
        _exact_keys(arguments, {"source", "destination"}, action)
        return MoveProposal(
            source=_string(arguments, "source"),
            destination=_string(arguments, "destination"),
        )
    if action == Operation.FILESYSTEM_RENAME.value:
        _exact_keys(arguments, {"source", "destination"}, action)
        return RenameProposal(
            source=_string(arguments, "source"),
            destination=_string(arguments, "destination"),
        )
    if action == Operation.WEB_SEARCH.value:
        _exact_keys(arguments, {"query"}, action)
        return WebSearchProposal(query=_string(arguments, "query"))
    if action == "finish":
        _exact_keys(arguments, {"message"}, action)
        return FinishProposal(message=_string(arguments, "message"))

    raise ProposalParseError(f"unsupported action: {action}")


def _object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProposalParseError(f"{name} must be an object")

    result: dict[str, object] = {}
    for key, item in cast(dict[object, object], value).items():
        if not isinstance(key, str):
            raise ProposalParseError(f"{name} keys must be strings")
        result[key] = item
    return result


def _exact_keys(value: dict[str, object], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        extras = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise ProposalParseError(
            f"{name} fields mismatch; missing={missing}, extra={extras}"
        )


def _string(value: dict[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise ProposalParseError(f"{key} must be a non-empty string")
    if "\x00" in result:
        raise ProposalParseError(f"{key} cannot contain NUL")
    return result
