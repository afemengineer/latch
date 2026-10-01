from dataclasses import replace
from datetime import UTC, datetime

import pytest

from latch.core.evidence import (
    GENESIS_HASH,
    ChainFailure,
    EvidenceKind,
    EvidenceLedger,
    normalize_evidence_details,
    render_timeline,
    verify_evidence_chain,
)
from latch.core.ids import new_task_id

NOW = datetime(2026, 10, 1, 20, 30, tzinfo=UTC)


def test_empty_ledger_verifies_and_has_genesis_tail() -> None:
    ledger = EvidenceLedger()

    verification = ledger.verify()

    assert verification.valid
    assert verification.checked_events == 0
    assert ledger.tail_hash == GENESIS_HASH


def test_append_builds_linked_hash_chain() -> None:
    ledger = EvidenceLedger()
    task_id = new_task_id()

    first = ledger.append(
        task_id=task_id,
        kind=EvidenceKind.POLICY_DECISION,
        summary="Allowed file read",
        details={"resource": "/tmp/invoice.pdf", "outcome": "allow"},
        at=NOW,
    )
    second = ledger.append(
        task_id=task_id,
        kind=EvidenceKind.FLOW_DECISION,
        summary="Blocked secret export",
        details={"label": "secret", "outcome": "deny"},
        at=NOW,
    )

    assert first.sequence == 0
    assert first.previous_hash == GENESIS_HASH
    assert second.sequence == 1
    assert second.previous_hash == first.event_hash
    assert ledger.tail_hash == second.event_hash
    assert ledger.verify().valid


def test_evidence_details_are_sorted_and_immutable() -> None:
    details = normalize_evidence_details({"z": 1, "a": "first", "m": True})

    assert details == (("a", "first"), ("m", True), ("z", 1))


def test_evidence_details_reject_nested_or_binary_payloads() -> None:
    with pytest.raises(TypeError, match="str, int, bool, or None"):
        normalize_evidence_details({"payload": {"secret": "value"}})  # type: ignore[dict-item]

    with pytest.raises(TypeError, match="str, int, bool, or None"):
        normalize_evidence_details({"payload": b"secret"})  # type: ignore[dict-item]


def test_naive_event_timestamp_is_rejected() -> None:
    ledger = EvidenceLedger()

    with pytest.raises(ValueError, match="timezone-aware"):
        ledger.append(
            task_id=new_task_id(),
            kind=EvidenceKind.TASK_TRANSITION,
            summary="Created",
            at=datetime(2026, 10, 1, 20, 30),
        )


def test_tampering_with_event_summary_is_detected() -> None:
    ledger = EvidenceLedger()
    task_id = new_task_id()
    ledger.append(
        task_id=task_id,
        kind=EvidenceKind.POLICY_DECISION,
        summary="Denied out-of-scope read",
        at=NOW,
    )
    original = ledger.append(
        task_id=task_id,
        kind=EvidenceKind.FLOW_DECISION,
        summary="Blocked export",
        at=NOW,
    )

    tampered = list(ledger.snapshot())
    tampered[1] = replace(original, summary="Export allowed")

    verification = verify_evidence_chain(tampered)

    assert not verification.valid
    assert verification.failure_index == 1
    assert verification.failure is ChainFailure.HASH_MISMATCH
    assert verification.checked_events == 1


def test_removing_event_is_detected() -> None:
    ledger = EvidenceLedger()
    task_id = new_task_id()
    for summary in ("one", "two", "three"):
        ledger.append(
            task_id=task_id,
            kind=EvidenceKind.TASK_TRANSITION,
            summary=summary,
            at=NOW,
        )

    events = list(ledger.snapshot())
    del events[1]

    verification = verify_evidence_chain(events)

    assert not verification.valid
    assert verification.failure_index == 1
    assert verification.failure is ChainFailure.SEQUENCE_MISMATCH


def test_reordering_events_is_detected() -> None:
    ledger = EvidenceLedger()
    task_id = new_task_id()
    for summary in ("one", "two"):
        ledger.append(
            task_id=task_id,
            kind=EvidenceKind.TASK_TRANSITION,
            summary=summary,
            at=NOW,
        )

    events = list(ledger.snapshot())
    events.reverse()

    verification = verify_evidence_chain(events)

    assert not verification.valid
    assert verification.failure_index == 0
    assert verification.failure is ChainFailure.SEQUENCE_MISMATCH


def test_snapshot_is_immutable_tuple() -> None:
    ledger = EvidenceLedger()
    ledger.append(
        task_id=new_task_id(),
        kind=EvidenceKind.TASK_TRANSITION,
        summary="Created",
        at=NOW,
    )

    snapshot = ledger.snapshot()

    assert isinstance(snapshot, tuple)
    with pytest.raises(TypeError):
        snapshot[0] = snapshot[0]  # type: ignore[index]


def test_task_filter_returns_only_requested_task() -> None:
    ledger = EvidenceLedger()
    first_task = new_task_id()
    second_task = new_task_id()
    ledger.append(
        task_id=first_task,
        kind=EvidenceKind.TASK_TRANSITION,
        summary="First",
        at=NOW,
    )
    ledger.append(
        task_id=second_task,
        kind=EvidenceKind.TASK_TRANSITION,
        summary="Second",
        at=NOW,
    )

    filtered = ledger.for_task(second_task)

    assert len(filtered) == 1
    assert filtered[0].summary == "Second"


def test_timeline_is_concise_and_does_not_include_hashes_by_default() -> None:
    ledger = EvidenceLedger()
    event = ledger.append(
        task_id=new_task_id(),
        kind=EvidenceKind.FLOW_DECISION,
        summary="Blocked secret export",
        details={
            "label": "secret",
            "overridable": False,
            "reason": "secret_network_denied",
        },
        at=NOW,
    )

    timeline = render_timeline(ledger.snapshot())

    assert "2026-10-01T20:30:00Z  flow_decision  Blocked secret export" in timeline
    assert "  label: secret" in timeline
    assert "  overridable: false" in timeline
    assert event.event_hash not in timeline


def test_timeline_can_include_hashes_for_diagnostics() -> None:
    ledger = EvidenceLedger()
    event = ledger.append(
        task_id=new_task_id(),
        kind=EvidenceKind.VERIFICATION_RESULT,
        summary="File move verified",
        at=NOW,
    )

    timeline = render_timeline(ledger.snapshot(), include_hashes=True)

    assert event.event_hash in timeline
