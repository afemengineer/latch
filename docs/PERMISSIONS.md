# Permission Envelopes

Status: **Normative for V0**

M5 adds the user-owned policy layer above Latch's low-level capability system.

The goal is to avoid the failure mode of secure-but-unusable agent runtimes:

```text
action -> prompt
action -> prompt
action -> prompt
action -> prompt
```

Instead, the user establishes a visible **authority envelope** for each skill.
Actions inside that standing envelope can receive short-lived task grants without
repeated UI interruption. Crossing the envelope requires explicit approval.

## Three authority layers

```text
Skill authority ceiling
        |
        | maximum possible authority
        v
Standing permissions
        |
        | normal no-prompt authority
        v
Task grants
        |
        | concrete short-lived runtime lease
        v
Executor
```

These layers are deliberately different.

### Authority ceiling

The ceiling is installed with the skill/configuration and is the maximum class of
authority that the skill is allowed to request through normal execution.

An incidental approval dialog cannot cross it.

Example:

```text
organize-receipts ceiling

filesystem.read:
  ~/Downloads/**

filesystem.move:
  ~/Downloads/**
  ~/Documents/Receipts/**

never:
  shell
  arbitrary credential access
  permanent delete
```

If an injected document causes the model to request something outside this
ceiling, Latch returns `DENY`, not "Would you like to allow this?"

This specifically reduces approval-dialog social engineering.

### Standing permission

A standing permission is an Android-style persistent user choice.

Example:

```text
Organize Receipts

FILES
  Read: ~/Downloads/**
  Move: ~/Downloads/** and ~/Documents/Receipts/**

NETWORK
  Private data: only approved exact sinks
```

A standing permission does not directly become ambient executor authority.

When a task needs it, the trusted permission manager mints a short-lived,
task-bound capability grant through the existing broker.

### Task-only approval

The user may approve one concrete capability request or private-data sink for the
current task without changing standing policy.

Task-only state is cleared when the task ends.

For capabilities, one-time approval mints an exact-resource grant with one
operation of capacity.

For private-data flows, the exact sink is added only to the task's temporary
approved-sink set.

## Why standing permissions do not live directly in the model context

The model can be told what semantic authority is currently available, but the
source of truth remains deterministic permission state.

A model saying:

```text
I have access to all files
```

does not change the envelope.

Likewise, a model cannot call the permission mutation methods. Methods that add,
edit, revoke, enable, disable, or persist permissions belong to the trusted UI /
control plane.

## Dynamic capability requests

Skills do not need to predict every concrete path before execution.

A request may be undeclared at planning time and still be approvable if it is
inside the skill's ceiling.

Therefore:

```text
not currently granted != forbidden

outside ceiling == forbidden
```

This preserves flexibility for smaller System-1 models and imperfect planners
without making the skill manifest meaningless.

## Persistent scope validation

When a user turns a one-off capability into standing permission, Latch validates
the requested persistent scope against the authority ceiling.

V0 uses deliberately conservative subset rules.

A persistent selector is accepted when:

- it exactly equals a ceiling selector;
- or it is an exact resource inside that ceiling;
- or it is a recursive child of a recursive ceiling with no exclusion globs.

If the ceiling contains exclusions, recursive child-scope inference is rejected
unless the selector is exactly equal to the ceiling. Latch does not attempt to
prove arbitrary glob-subset relationships.

This may reject some safe configurations. That is preferable to accidentally
widening authority.

## Constraints

Standing permissions can preserve capability constraints such as:

- overwrite prohibition;
- byte limits;
- operation limits.

Constraints on persistent permissions must be no broader than the ceiling.

Runtime grants are still checked and consumed by `CapabilityBroker`.

A cached standing grant is reused for a task instead of minting a fresh grant for
every action. This matters because repeatedly minting grants could otherwise reset
operation/byte counters and defeat limits.

## Private-data sink approvals

M5 also provides Android-like flow permissions.

For `PRIVATE` data, an exact remote sink can be:

- approved for one task;
- approved persistently;
- revoked later.

Approvals are exact `Sink(kind, target)` identities.

Approving:

```text
REMOTE_MODEL nebius:nemotron
```

does not approve another provider or arbitrary network destination.

## Non-persistable flows

Some flows are not ordinary permissions at all.

Examples:

```text
LOCAL_ONLY -> remote
SECRET -> model
SECRET -> generic network
SEALED_SECRET -> unrelated destination
```

These remain deterministic denials.

The permission manager cannot convert them into standing policy and does not
offer an "always allow" path.

This is important because a prompt injection must not be able to repeatedly
present the user with a dangerous permission until they click through.

## Consequence text

Every approval assessment carries deterministic user-facing consequence text.

Examples:

```text
Read file contents
Allows this task to read /.../invoice.pdf.
Any bytes returned remain subject to Latch information-flow policy before
they can reach a model or network.
```

and:

```text
Send private data to a remote model
Private data approved for this flow may leave the device and be disclosed
to the exact model/provider sink nebius:nemotron.
Other destinations remain unapproved.
```

The UI should display effects, scope, and whether data leaves the device rather
than showing only implementation names such as `filesystem.read`.

## Android-style state inspection

`PermissionManager.snapshot()` provides the future Permissions UI with:

- skill name;
- enabled/disabled state;
- revision;
- standing capability entries;
- their scopes and consequence text;
- persistently approved private-data sinks;
- the immutable authority ceiling.

The user can edit or revoke standing permissions without editing a skill manifest
by hand.

Disabling a skill immediately revokes cached grants and clears its task-only flow
approvals.

## Revocation

Editing or revoking a standing capability invalidates cached runtime grants that
were minted from it.

Clearing a task:

- revokes cached task grants;
- removes task-only sink approvals.

This prevents stale runtime leases from silently surviving a user permission
change.

## Evidence

When an evidence ledger is configured, M5 records safe metadata for:

- task-only approvals;
- persistent approvals;
- runtime grants minted from standing policy;
- permission revocations.

No secret payloads are written to approval evidence.

A future durable control-plane store should additionally provide a global audit
scope for permission changes made outside any task.

## V0 persistence limitation

"Persistent" in M5 means **standing across tasks in the permission state**, not
yet durable across process restarts.

The permission objects are immutable and revisioned, but their storage is still
in-memory.

Durable SQLite/SQLCipher persistence is a later milestone.

This distinction should remain explicit in demos and documentation.

## Security property

The important M5 rule is:

> **The model may request an escalation, but only trusted user-owned permission
> state can make that escalation reusable.**

Combined with M1-M4:

```text
model proposal
    |
    v
skill ceiling
    |
    +-- outside -> DENY
    |
    v
standing permission?
    |
    +-- yes -> task grant -> executor
    |
    +-- no -> explicit user approval
                |
                +-- task only
                |
                +-- persistent standing rule
```

This is the mechanism intended to avoid Codex-style manual-mode friction without
giving the reasoning model ambient authority.
