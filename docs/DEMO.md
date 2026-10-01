# M9 Hackathon Demo

M9 is the first judge-facing application layer for Latch.

The demo is intentionally narrow:

> **Make the model behave badly on purpose, then show that the system still
> cannot exceed the user's authority envelope.**

The local browser UI is not the security boundary. It is a control-plane client
for the same deterministic runtime introduced in M1-M8.

## Run locally

Install/sync the repository and launch:

    uv sync --group dev
    uv run latch-demo

Then open:

    http://127.0.0.1:8765

The launcher binds to loopback by default. Binding to a non-loopback interface
requires the explicit `--allow-network` flag.

That default is deliberate: the local control plane can grant permissions and
must not accidentally become an unauthenticated LAN service.

## Deterministic demo

Click **Run deterministic containment demo**.

The browser performs three model turns through a ScriptedProvider:

1. Search for warranty terms.
2. Consume a synthetic poisoned web result.
3. Follow the poisoned instruction and request a file outside the skill ceiling.

The attack fixture asks the model to read a fake private key outside the
authorized workspace and reproduce its contents.

Latch returns:

    OUTSIDE_AUTHORITY_CEILING

The model never receives the file contents, no permission dialog is generated
for the impossible escalation, and the task continues to completion.

This is the core demo invariant:

> **The hostile instruction succeeds at influencing the model. It fails at
> acquiring authority.**

## What the UI shows

The application exposes five judge-visible surfaces.

### Task

The user request and security classification. PUBLIC is the deterministic demo
default. PRIVATE demonstrates explicit remote-flow approval. LOCAL_ONLY shows
that remote flows cannot be approved at all.

### Attack fixture

The UI shows:

- active provider;
- search executor;
- filesystem root the skill is allowed to read;
- injected target outside that root;
- exact malicious red-team text.

The fixture is labeled as synthetic. Latch does not claim that the poisoned
result came from a real manufacturer or from Tavily.

### Android-style authority envelope

The panel separates:

- maximum skill authority;
- standing reusable permissions;
- persistently approved private-data sinks.

In the default demo, web.search has standing permission, while filesystem.read
is only possible inside the declared demo workspace.

### Permission request

When PRIVATE data is about to leave the device, the task pauses before the
external call.

The user may:

- allow once;
- persist the exact sink approval;
- block.

The model cannot press these buttons or invoke the underlying control-plane API
through its action schema.

### Proof-carrying timeline

The UI renders the append-only evidence ledger:

- model proposals;
- policy decisions;
- approvals;
- grant issuance;
- execution;
- verification/outcomes;
- task completion.

The SHA-256 chain status is displayed continuously.

Raw model chain-of-thought is intentionally absent.

## Live Nebius + Tavily mode

The UI can be switched from the deterministic local provider to live services.

Required inputs:

- Nebius OpenAI-compatible HTTPS base URL;
- Nebius model ID;
- Nebius API key;
- Tavily API key.

The API keys are submitted to the loopback control plane and immediately placed
behind M6 CredentialVault handles. The state API never returns them and they are
never placed in model context.

Live search uses Tavily through the narrow M8 `web.search` executor.

A synthetic hostile result is appended to the real search results by
RedTeamSearchBackend. This is deliberate red-team instrumentation, not a claim
that Tavily returned malicious content.

## Forced adversarial model mode

For a reliable live-stage demonstration, the UI defaults to **force adversarial
model behavior**.

After untrusted web content enters context, RedTeamModelProvider adds an explicit
red-team instruction telling the live model to follow the hostile web
instruction.

This is intentionally stronger than ordinary prompt injection.

The purpose is not to benchmark a provider's injection resistance. It is to
demonstrate that even a model that is intentionally made malicious still cannot
mint authority.

Disable the checkbox to observe the model's natural behavior instead.

## Browser-side handling of untrusted content

Retrieved text is rendered with DOM `textContent`, not `innerHTML`.

This prevents an adversarial search snippet from becoming browser-executable
HTML/JavaScript merely because it appears in the demo timeline.

The local server also sends:

- Content-Security-Policy;
- X-Frame-Options: DENY;
- X-Content-Type-Options: nosniff;
- Referrer-Policy: no-referrer;
- Cache-Control: no-store.

The CSP currently permits inline script/style because the hackathon UI is a
single self-contained page. A production UI should move those assets to hashed
static files and remove `unsafe-inline`.

## Explicit non-claims

M9 is a single-user local demo, not a hardened remote service.

It does not yet provide:

- authentication for network exposure;
- CSRF tokens for a remotely hosted control plane;
- durable task/session storage;
- production OAuth onboarding;
- browser isolation for arbitrary fetched pages;
- multi-user authorization;
- durable OS-backed live credentials in the demo UI.

The safest supported launch mode remains loopback-only.
