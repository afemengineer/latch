"""Human-readable rendering for evidence timelines."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC

from latch.core.evidence.models import EvidenceEvent, EvidenceScalar
from latch.core.ids import TaskId


def _render_scalar(value: EvidenceScalar) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_timeline(
    events: Iterable[EvidenceEvent],
    *,
    task_id: TaskId | None = None,
    include_hashes: bool = False,
) -> str:
    """Render effects and decisions without exposing hidden model reasoning."""

    lines: list[str] = []

    for event in events:
        if task_id is not None and event.task_id != task_id:
            continue

        timestamp = (
            event.occurred_at.astimezone(UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        lines.append(f"{timestamp}  {event.kind.value}  {event.summary}")

        for key, value in event.details:
            lines.append(f"  {key}: {_render_scalar(value)}")

        if include_hashes:
            lines.append(f"  hash: {event.event_hash}")

    return "\n".join(lines)
