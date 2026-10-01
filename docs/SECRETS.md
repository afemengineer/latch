# Sealed Secrets and Credential Vault

Status: **Normative for V0**

M6 implements the boundary between model-visible credential identity and model-invisible credential material.

The core rule is:

> **A model may select a connected credential handle. It never receives the credential value.**

Credential values live behind a SecretBackend, are resolved only by trusted executors, and are represented to information-flow policy as SEALED_SECRET.

## Public handle versus secret value

The model-facing object contains only metadata:

    CredentialHandle
      credential_id: credential_abcd...
      service: calendar
      account_label: personal
      bound_executor: google-calendar

The OAuth/API secret is not a field on this object. Serializing, logging, rendering into tool schemas, or placing a CredentialHandle in model context therefore cannot reveal the credential value.

## Resolution path

    model/tool proposal
        | credential_id only
        v
    trusted executor google-calendar
        | executor supplies its own identity
        v
    CredentialVault
        v
    canonical CredentialHandle
        v
    SEALED_SECRET -> TRUSTED_EXECUTOR(google-calendar)
        | mismatch: DENY before backend read
        v
    SecretBackend.get()
        v
    short-lived SecretLease
        v
    trusted protocol client / API call

The model does not supply the executor identity used for authorization. That identity belongs to trusted executor code.

## Purpose binding

Each credential is bound to one trusted executor identity. A calendar token bound to google-calendar cannot be resolved by generic-http, filesystem, email, or another unrelated tool.

The vault evaluates the existing M2 information-flow rule before reading the backend:

    SEALED_SECRET -> exact bound trusted executor    ALLOW
    SEALED_SECRET -> anything else                   DENY

This means a mismatched executor does not merely fail after retrieval; the secret is not materialized from the backend at all.

## Secret backends

M6 defines a narrow backend protocol with set, get, and delete operations indexed by opaque credential ID.

### MemorySecretBackend

Process-local and intended only for tests, development, and explicitly accepted ephemeral demos. Its representation exposes only the number of stored credentials. It is not a production credential store.

### KeyringSecretBackend

Optional host-keyring integration uses the Python keyring package. Install it with:

    uv sync --extra os-secrets

The adapter rejects keyring's fail/no-op backend by requiring positive backend priority. The actual protection properties depend on the host keyring selected by the OS/environment. Latch does not claim identical security properties for every Linux desktop, headless machine, or third-party keyring implementation.

For the Windows-first V0 this provides an OS-backed path without putting platform credential APIs into the model-independent core.

## SecretLease

Successful resolution returns a short-lived SecretLease.

Properties:

- repr and str never include the value;
- the secret is accessible only through explicit reveal() inside trusted code;
- context-manager exit closes the lease and drops Latch's reference to the value.

Example trusted-executor pattern:

    with vault.resolve_for_executor(
        credential_id,
        executor_id="google-calendar",
        task_id=task_id,
    ) as lease:
        client.set_bearer_token(lease.reveal())
        client.create_event(...)

The result returned to the model contains only safe operation output.

### Zeroization limitation

Python strings are immutable and the interpreter may retain copies internally. Closing a lease removes Latch's reference but does not guarantee cryptographic zeroization of process memory.

M6 therefore does not claim secure-memory semantics. A future high-assurance implementation could move secret use into a smaller native or isolated credential broker.

## Rotation and disconnect

rotate() replaces backend material without changing the public credential handle. disconnect() removes backend material and catalog metadata.

A secret lease already resolved into trusted executor memory cannot be retroactively erased. Executors should therefore keep leases narrow and short-lived.

## Model-visible credential catalog

CredentialVault.catalog() returns only CredentialHandle objects. This permits a UI to show connected accounts without exposing tokens.

Knowing that a service/account is connected is distinct from possessing its credential value.

## Evidence

Credential use emits safe FLOW_DECISION evidence containing credential ID, service, account label, executor identity, sealed_secret classification, and flow outcome/reason.

It never intentionally records the credential value.

## Evidence sanitizer

M6 adds an optional deterministic text sanitizer to EvidenceLedger. A SecretRedactor can be registered as the sanitizer and shared with the vault.

Connected and resolved secret values are registered with the redactor. If trusted code accidentally writes an exact secret string into an evidence summary or string field, it is replaced with:

    <redacted-secret>

before hashing and storage.

This is defense in depth only. Exact-value redaction does not reliably catch encoded values, partial values, transformed values, hashes, character-by-character leakage, or values unknown to the redactor.

The security boundary remains information-flow control plus purpose-bound resolution. Redaction is not a substitute for preventing SECRET data from reaching evidence.

## Why there is no generic get-secret model tool

Latch must never expose a generic credentials.get_value(id) operation to the agent.

Instead, a semantic executor accepts a credential ID, for example calendar.create_event(...), and resolves the credential internally. This keeps secret authority aligned to the operation being performed.

## Relationship to permissions

M5 controls whether an operation may be performed. M6 controls whether trusted implementation code for that operation may obtain the credential required to perform it.

Both must hold:

    calendar.create_event authorized?       M5 / capability policy
    credential bound to calendar executor?  M6 / sealed-secret policy

## V0 limitations

M6 does not yet provide:

- durable credential metadata storage;
- per-credential capability scopes;
- hardware-backed key custody guarantees;
- secure memory or guaranteed zeroization;
- an isolated secret-broker process;
- OAuth browser/setup flows;
- automatic token refresh semantics;
- containment of a malicious trusted executor.

These can be layered later without exposing credential values to the model.