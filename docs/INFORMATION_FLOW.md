# Information-Flow Control

Status: **Normative for V0**

Latch treats authorization and information flow as independent security gates.

A capability answers:

> May this task perform this class of operation on this resource?

Information-flow control answers:

> May data with this security classification be exposed to this destination?

A prompt-injected agent can therefore possess legitimate read authority and still
be prevented from exfiltrating the data it reads.

## Labels

V0 defines five labels:

```text
PUBLIC < PRIVATE < LOCAL_ONLY < SECRET < SEALED_SECRET
```

The ordering is conservative for ordinary derivation. Combining data inherits the
most restrictive label.

### PUBLIC

May flow to destinations otherwise permitted by capability/tool policy.

### PRIVATE

May remain local automatically. Remote sinks require explicit approval. Approval
is by exact sink identity, not prefix matching.

Examples:

- an explicitly approved remote model provider;
- an explicitly approved network origin.

### LOCAL_ONLY

May be processed locally, including by a local model, but may not flow to a remote
model or network sink.

A model cannot override this restriction.

### SECRET

Must not be exposed to any model, local or remote, and must not be sent to generic
network sinks. Raw SECRET values must also not be written into evidence payloads.

SECRET may be handled locally by trusted executors where required for operations
such as local copying or cryptographic use. If a trusted executor later wants to
send derived data remotely, that is a separate flow decision.

There is no ordinary "Allow once" path for `SECRET -> generic network`.

### SEALED_SECRET

Represents credentials or similarly sensitive values that should never be
materialized into model-visible state.

A SEALED_SECRET carries a binding to a trusted executor/service identity and may
flow only to that exact trusted executor.

Example:

```text
model-visible state:
credential_handle = "google-calendar"

trusted side:
SEALED_SECRET(token)
    |
    +----> trusted executor "google-calendar"    ALLOW
    |
    +----> model                                DENY
    +----> unrelated executor                   DENY
    +----> generic network request              DENY
```

The bound executor is responsible for using the credential only for its declared
service. Hostile executor containment is outside the V0 trust boundary.

## DataRef

`DataRef` is metadata, not a payload container.

It records:

- logical data identity;
- security label;
- origin/provenance string;
- sealed executor binding when applicable.

Keeping payload bytes outside the IFC metadata object reduces the chance that the
policy layer itself becomes another accidental secret transport.

## Sinks

V0 distinguishes:

- local model;
- remote model;
- network;
- trusted executor;
- local storage;
- user output;
- evidence.

Sink target identifiers are opaque to `latch.core`. Adapters must canonicalize
provider IDs and network origins before policy evaluation.

Approvals use exact `(kind, target)` identity. For example, approval of:

```text
https://api.example.test:443
```

does not approve:

```text
https://api.example.test.evil:443
```

## Default matrix

| Label | Local model | Remote model | Generic network | Trusted executor | Local storage | Evidence |
|---|---:|---:|---:|---:|---:|---:|
| PUBLIC | Allow | Allow | Allow | Allow | Allow | Allow |
| PRIVATE | Allow | Approved only | Approved only | Allow | Allow | Allow |
| LOCAL_ONLY | Allow | Deny | Deny | Allow | Allow | Allow |
| SECRET | Deny | Deny | Deny | Allow | Allow | Deny |
| SEALED_SECRET | Deny | Deny | Deny | Bound executor only | Deny | Deny |

"Approved only" is represented as `NEEDS_APPROVAL` until trusted/user-owned policy
contains the exact sink.

## Conservative propagation

Ordinary derivation cannot lower a label.

Examples:

```text
PUBLIC + PRIVATE    -> PRIVATE
PRIVATE + LOCAL_ONLY -> LOCAL_ONLY
LOCAL_ONLY + SECRET -> SECRET
SECRET + SEALED_SECRET -> SEALED_SECRET
```

There is deliberately no generic `declassify()` helper in V0.

Future transformations that can safely produce less-sensitive output must be
explicit trusted operations with their own narrowly specified postconditions.

When derived data includes SEALED_SECRET inputs, all sealed inputs must have one
unambiguous binding. Combining sealed credentials for unrelated services is
rejected.

## Non-overridable flows

The V0 policy marks these as deterministic denials rather than ordinary approval
requests:

- `LOCAL_ONLY -> remote model/network`;
- `SECRET -> any model`;
- `SECRET -> generic network`;
- `SECRET -> raw evidence payload`;
- `SEALED_SECRET -> anything except its exact bound trusted executor`.

The user can later deliberately change data classification through a trusted UI
or workflow if the product supports it. That is distinct from a model-triggered
"allow once" bypass.

## Prompt-injection property

The core adversarial scenario is intentionally stronger than path scoping alone:

1. The task has broad filesystem read permission.
2. The model follows an injected instruction and reads a synthetic private key.
3. The read passes capability policy.
4. The resulting data is labeled `SECRET`.
5. The model proposes sending the data to an attacker-controlled origin.
6. IFC returns `DENY`.

Therefore:

> **Possession of data does not imply authority to export it.**

The integration test
`tests/integration/test_authority_and_information_flow.py` encodes this property.

## V0 limitations

The IFC layer currently operates on explicit metadata labels. It is not yet a
whole-program dynamic taint tracker.

V0 does not claim:

- automatic perfect classification of arbitrary data;
- formal noninterference;
- sandboxing of malicious trusted executors;
- automatic tracking through arbitrary Python objects;
- URL/origin canonicalization inside the core policy layer.

Later model-based classifiers may propose stricter labels or flag suspicious
content, but models must never authorize a downgrade.
