# Evidence Ledger

Status: **Normative for V0**

Latch records security-relevant decisions and effects in an append-only evidence
sequence.

The evidence layer exists for two reasons:

1. A user should be able to understand what authority was requested, granted,
   denied, exercised, and verified.
2. Silent post-hoc modification of an existing event sequence should be
   detectable.

It is **not** a blockchain, external notarization system, or substitute for
independent verification of side effects.

## Event classes

V0 defines evidence events for:

- task transitions;
- action proposals;
- policy decisions;
- approvals;
- grant issue/revocation;
- execution start/result;
- information-flow decisions;
- verification results;
- rollback;
- task completion/failure.

The ledger records effects and decisions. It must not expose hidden model
reasoning.

## Event structure

Each event contains:

```text
evidence_id
task_id
sequence
occurred_at
kind
summary
bounded flat metadata
previous_hash
event_hash
```

The metadata area is intentionally small and flat. Arbitrary tool output,
documents, model context, binary payloads, and raw secret values do not belong in
evidence records.

The current implementation permits only:

- string;
- integer;
- boolean;
- null.

for metadata values, with size/count bounds.

This reduces accidental logging surface but does **not** itself prove that a
string is non-sensitive. Callers remain responsible for information-flow
evaluation before including data-derived text in evidence.

## Hash chain

The first event points to:

```text
GENESIS_HASH = 0000...0000
```

Each event commits to its canonical security-relevant fields and to the previous
event hash using SHA-256 with a domain separator:

```text
event_hash =
    SHA256(
        "latch-evidence-v1\0"
        || previous_hash
        || "\0"
        || canonical_json(event_body)
    )
```

The event body includes a schema version, event/task identity, sequence,
timestamp, event kind, summary, and normalized metadata.

As a result:

- changing an event invalidates its hash;
- removing an interior event breaks sequence/link verification;
- reordering events breaks sequence/link verification;
- changing an earlier event invalidates the downstream chain.

## Precise security claim

The chain is **tamper-evident**, not immutable.

If an attacker controls both persistent storage and the trusted copy of the
latest chain head, they can replace or truncate the entire history and compute a
new internally valid chain.

Therefore a stronger future design may persist/checkpoint the tail hash
separately, sign checkpoints, or export them to a trusted external location.

V0 deliberately does not claim external notarization.

## Append-only API

`EvidenceLedger` exposes:

- append;
- immutable snapshot;
- per-task filtering;
- chain verification;
- current tail hash.

It exposes no ordinary event edit/delete method.

This is an API invariant. The user may eventually request deletion of retained
history through a separate persistence/lifecycle mechanism, but events should
never be silently mutated in place.

## Canonical serialization

Security-relevant hashing uses Latch's deterministic canonical serializer.

Important properties include:

- mappings sorted by key;
- sets deterministically ordered;
- timezone-aware datetimes normalized to UTC;
- compact UTF-8 JSON representation;
- non-finite floats rejected.

Evidence timestamps themselves must be timezone-aware.

## Secret handling

The evidence ledger is an information-flow sink.

The baseline IFC policy already defines:

```text
SECRET -> evidence    DENY
SEALED_SECRET -> evidence    DENY
```

Evidence about a blocked secret flow should record safe metadata:

```text
data_id: synthetic-private-key
label: secret
sink: https://attacker.test:443
outcome: deny
reason: secret_network_denied
```

It must not record the private-key contents.

The M3 integration test encodes this expected pattern.

## Human-readable timeline

The renderer turns events into concise audit lines such as:

```text
2026-10-01T20:45:00Z  policy_decision  Blocked out-of-scope read
  operation: filesystem.read
  resource: /home/demo/.ssh/id_rsa

2026-10-01T20:45:01Z  flow_decision  Blocked prohibited information flow
  label: secret
  outcome: deny
  reason: secret_network_denied
```

Hashes are omitted by default and may be shown for diagnostics.

This surface is intended for the eventual Activity/Evidence UI.

## Verification versus evidence

These concepts are distinct:

**Verification**
: Determines whether a requested side effect actually occurred.

**Evidence**
: Records what was proposed, authorized, executed, and verified.

A record saying `executor_status=success` is evidence that the executor reported
success. It is not independent proof that the effect occurred.

M4/M5 will connect real executors and verifiers to this evidence protocol.

## V0 limitations

M3 is currently process-local/in-memory. Persistence comes later.

The ledger does not yet provide:

- durable SQLite storage;
- external signed checkpoints;
- trusted timestamping;
- distributed consensus;
- automatic secret detection in arbitrary summary strings;
- protection from a compromised Latch core or host OS.

These limitations are intentional. The hash/event semantics are stabilized before
the persistence backend is added.
