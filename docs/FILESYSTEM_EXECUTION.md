# Filesystem Execution

Status: **Normative for V0**

M4 introduces Latch's first real side effects.

The filesystem executor is a trusted first-party adapter, but it does not receive
ambient authorization merely because it runs inside the process. Every operation
must present concrete task-scoped grant(s), re-resolve the actual filesystem
target, reserve grant usage, execute, and verify the resulting state.

## Security pipeline

```text
requested path
    |
    v
lexical FilesystemResource
    |
    v
OS/path resolution
(symlinks / junctions / reparse targets)
    |
    v
resolved FilesystemResource
    |
    v
grant selector re-check
    |
    v
atomic grant reservation
    |
    v
filesystem side effect
    |
    v
independent state re-read
    |
    v
postcondition verification
    |
    v
evidence + labeled result
```

The crucial M4 property is:

> **Authorization applies to the resolved resource, not merely the path string
> proposed by the model.**

## Supported operations

V0 supports:

- inspect;
- read;
- copy;
- move;
- rename.

Permanent deletion remains intentionally absent.

`rename` is constrained to one directory. Cross-directory relocation uses
`move`.

## Multi-resource authority

Copy/move/rename affect both a source and a destination.

M4 therefore does not pretend that one path-scoped authorization covers the
whole operation.

```text
copy:
  source      requires filesystem.copy
  destination requires filesystem.copy

move:
  source      requires filesystem.move
  destination requires filesystem.move

rename:
  source      requires filesystem.rename
  destination requires filesystem.rename
```

Both grant uses are validated and reserved atomically before execution.

If one fails, neither usage counter is consumed.

For reading file contents, `filesystem.read` is distinct from copy/move:
copying data locally does not implicitly grant the model permission to inspect
its contents.

## Authoritative path resolution

M1 selectors are lexical policy objects. They are not a filesystem sandbox.

M4 resolves the actual target before consuming authority.

For an existing path, the executor follows filesystem indirection using the host
OS path implementation.

For a destination that does not yet exist, the parent directory is resolved
strictly and the requested basename is appended to that resolved parent.

This blocks the common shape:

```text
granted:
  /allowed/**

model requests:
  /allowed/link/secret.txt

link -> /outside

resolved:
  /outside/secret.txt

result:
  DENY resolved_scope_escape
```

The same check applies to destination parents.

## TOCTOU limitation

M4 materially improves scope enforcement but does **not** claim race-free
filesystem sandboxing against a malicious concurrent local process.

There remains a time-of-check/time-of-use interval between resolution,
authorization, and some OS operations.

A stronger future implementation may use platform-specific primitives such as:

- descriptor-relative `openat`/similar APIs on POSIX;
- Windows handle-based final-path validation and constrained opens;
- a sandbox/restricted worker process.

This limitation matters when the host already contains adversarial local code.
It does not change Latch's core threat model that the AI decision-maker itself is
untrusted.

## Grant consumption

`CapabilityBroker.consume_requests()` validates a set of concrete
`(grant, request)` pairs under one lock.

Before mutating counters it checks:

- current deny rules;
- grant existence;
- task binding;
- operation binding;
- resolved resource scope;
- request constraints;
- expiry;
- cumulative operation limit;
- cumulative byte limit.

Only if every use passes are all usage counters incremented.

This prevents a failed destination authorization from partially consuming a
source grant.

## Byte accounting

Read/copy/move/rename requests use the actual pre-operation regular-file size for
`bytes_requested`.

This means a grant with a byte ceiling is checked against the real file rather
than model-provided size metadata.

## Verification

The executor does not treat a successful standard-library call as proof.

`FilesystemVerifier` re-reads authoritative state through a separate module.

### Read

The bytes returned by the executor must hash to the pre-read file snapshot.

### Copy

Postconditions:

- source still exists;
- source content still matches the pre-state;
- destination exists as a regular file;
- destination size/hash match the pre-state.

### Move / rename

Postconditions:

- source no longer exists;
- destination exists as a regular file;
- destination size/hash match the pre-state.

A failed verification raises a distinct `FilesystemVerificationError` and
produces a verification evidence event.

Rollback remains a later milestone.

## Data labels

Filesystem outputs are never returned as naked bytes to the agent layer.

A read returns:

```text
LabeledBytes {
    data
    DataRef(label, origin, id)
}
```

The later agent/provider layer must perform IFC before exposing those bytes to a
model or network sink.

M4 adds an in-memory `FilesystemLabelStore` with:

- default classification;
- path-based classification rules;
- exact per-resource labels;
- conservative propagation on copy/move/rename.

If SECRET data is copied into a PRIVATE location, the destination remains
SECRET.

If PRIVATE data is copied into a SECRET-classified location, the destination
becomes SECRET.

There is no implicit downgrade.

Persistence of exact labels is deferred; this in-memory store establishes the
semantics first.

## Evidence

The executor records safe metadata for:

- authority allow/deny;
- execution start;
- execution result;
- verification result.

It does not record file payload bytes or content hashes.

Example:

```text
policy_decision
  operation: filesystem.read
  outcome: allow

verification_result
  operation: filesystem.read
  result: pass

execution_result
  bytes: 8421
  label: private
```

The payload itself remains outside the evidence ledger.

## V0 limitations

M4 does not yet provide:

- durable label storage;
- durable evidence storage;
- rollback after failed postconditions;
- recursive directory copy/move;
- permanent delete;
- race-free hostile-local-process containment;
- automatic semantic secret classification;
- model integration.

The next layers can now build on actual verified side effects rather than fake
tool success.
