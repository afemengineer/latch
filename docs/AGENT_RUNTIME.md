# Agent Runtime

Status: **Normative for V0**

M7 introduces the first model-facing runtime. The model remains outside the
authority boundary.

The central property is:

> **A provider can emit proposals, but it never receives a broker, grant,
> executor, permission mutation API, or credential value.**

## Request path

    task
      |
      v
    collect labeled dynamic context
      |
      v
    information-flow decision for provider sink
      |
      +-- DENY -> stop before provider request is built
      |
      +-- NEEDS_APPROVAL -> trusted UI/control plane
      |
      v
    ContextCompiler
      |
      v
    ModelProvider.generate()
      |
      v
    strict JSON proposal parser
      |
      v
    capability assessment
      |
      +-- outside skill ceiling -> DENY, no approval popup
      |
      +-- needs authority -> trusted user approval
      |
      v
    short-lived task grant(s)
      |
      v
    verified executor
      |
      v
    labeled observation
      |
      +---- next model turn is IFC checked again

This creates an explicit security barrier on both directions around the model.

## Chat is not the runtime

AgentRuntime operates on a Task. A future chat client, CLI, scheduled automation,
or computer-use endpoint can create/drive the same task state machine.

No chat transcript owns authority state.

## Provider context and information flow

Dynamic model context currently consists of:

- the user task input;
- verified tool observations;
- deterministic Latch denial/error observations.

Every dynamic item carries a DataRef.

Before constructing a ProviderRequest, the runtime creates one FlowRequest to the
provider's exact sink.

Examples:

    PRIVATE -> local model                  ALLOW
    PRIVATE -> approved Nebius sink         ALLOW
    PRIVATE -> unapproved Nebius sink       NEEDS_APPROVAL
    LOCAL_ONLY -> remote model              DENY
    SECRET -> local or remote model         DENY

This means reading a SECRET file does not accidentally make the next model call
legal. The next turn is blocked before the provider receives the data.

## Semantic tool surface

The ContextCompiler exposes actions from the active skill's authority ceiling,
not the entire global tool universe.

The model may see that filesystem.read exists for this skill. That visibility is
not authority.

Standing permission determines whether a proposal can execute without a prompt.
The ceiling determines whether the proposal is approvable at all.

The model never sees actions for:

- granting permissions;
- changing a ceiling;
- minting a grant;
- revealing credentials;
- bypassing IFC;
- raw shell execution.

## Proposal protocol

V0 deliberately uses a narrow JSON protocol rather than giving model-native
function calls direct executor access.

Example:

    {
      "action": "filesystem.read",
      "arguments": {
        "path": "/absolute/path/invoice.txt"
      }
    }

and completion:

    {
      "action": "finish",
      "arguments": {
        "message": "The invoice was filed and verified."
      }
    }

The parser requires exact fields. Additional fields are rejected.

Therefore this is invalid:

    {
      "action": "filesystem.read",
      "arguments": {
        "path": "...",
        "grant_id": "grant_attacker_supplied"
      }
    }

A model cannot smuggle authority-bearing identifiers through the action schema.

## Denied prompt-injected actions

An action outside the authority ceiling does not terminate the whole task and
does not produce a permission prompt.

Latch records the denial and adds a safe observation:

    Latch denied filesystem.read: outside_authority_ceiling.
    Continue the legitimate task without this authority.

The model may then take another action.

This behavior is important for the flagship prompt-injection demo: the system
should block the malicious effect while still allowing the legitimate task to
continue.

## Approval pauses

AgentRuntime uses TaskState.WAITING_APPROVAL.

There are two pending approval classes:

- model-context flow approval;
- capability approval.

Only the trusted client/control plane calls approve_pending().

The method is intentionally absent from the model tool surface.

An approval can be:

- task-only;
- standing/persistent in the M5 sense.

For persistent capability escalation, M7 defaults to the exact requested
resource. A future permission UI can offer a consciously broader scope inside the
skill ceiling.

## Model providers

M7 defines a small ModelProvider interface:

    provider_id
    sink
    generate(ProviderRequest) -> ProviderResponse

The runtime depends on this interface, not on Nebius/OpenAI/vLLM-specific code.

### ScriptedProvider

Deterministic test provider for:

- state-machine tests;
- adversarial prompt-injection fixtures;
- reproducible demos.

### OpenAICompatibleProvider

Minimal remote adapter. It receives context only after IFC approval.

Its API credential is a M6 CredentialHandle bound to the provider executor.
The provider resolves the secret internally and places it into the HTTP
Authorization header. The API key is not included in ProviderRequest, model
messages, model response, or evidence.

### NebiusProvider

A thin named configuration over the OpenAI-compatible adapter.

The base URL and model are explicit configuration rather than security state.
Its provider sink identity is exact:

    REMOTE_MODEL nebius:<model>

so M5 can approve PRIVATE-data flow to that provider/model without implicitly
approving arbitrary remote destinations.

## Current executor support

M7 routes these proposals through M1-M6:

- filesystem.inspect;
- filesystem.read;
- filesystem.copy;
- filesystem.move;
- filesystem.rename.

No model action bypasses PermissionManager or FilesystemExecutor.

## Malformed model output

Malformed/extra-field JSON is not executable.

Latch records a rejected action and returns a safe observation to the model so a
small model can recover on a later turn.

Repeated failures are bounded by max_turns / caller max_steps.

## Evidence

M7 records:

- task state transitions;
- model-context flow decisions;
- sanitized action names;
- malformed proposal rejection;
- policy denial;
- completion/failure.

Raw hidden reasoning is never recorded.

Provider raw output is also not placed wholesale into evidence.

## V0 limitations

M7 is synchronous and process-local.

It does not yet provide:

- durable task persistence;
- streaming model output;
- cancellation;
- web/search executor;
- declarative skill file parser;
- memory retrieval;
- automatic model routing;
- computer use;
- async provider fan-out.

Those features must preserve the same proposal -> deterministic policy ->
verified execution boundary.
