# Latch

**Secure authority control for AI agents: scoped permissions, verified actions, and auditable execution.**

Latch is a local-first authority-control runtime for AI agents. It is designed around a deliberately pessimistic assumption:

> **The reasoning model can be prompt-injected. The system must remain safe when the model makes a malicious or incorrect request.**

Latch therefore does not make the model part of the security boundary. Models may propose actions; deterministic Latch components decide whether those actions are authorized, whether information may flow to the requested destination, and whether the resulting side effects actually occurred.

## Core thesis

Most agent security systems focus on making the model better at refusing malicious instructions. Latch treats model-level resistance as useful defense-in-depth, but not as an authorization primitive.

The runtime separates:

- **Intelligence** — replaceable and untrusted models that plan and propose actions.
- **Authority** — deterministic, scoped capabilities granted by Latch.
- **Information flow** — rules governing where acquired data may go.
- **Execution** — trusted adapters that perform authorized operations.
- **Verification** — independent checks of consequential effects.
- **Evidence** — an auditable record of proposals, grants, executions, and outcomes.

The intended failure mode is:

> **The prompt injection succeeds against the model and fails against the system.**

## V0 principles

- The model is untrusted.
- Retrieved content is adversarial by default.
- Models request authority; they never create it.
- Capabilities are low-level, scoped, constrained, and time-bounded.
- Skills are semantic procedures layered above capabilities.
- Persistent permissions are explicit and user-visible, similar to mobile app permissions.
- Secrets are never exposed to models.
- Data classification is preserved through execution.
- `SECRET` data cannot be generically exported by an agent.
- Consequential actions are independently verified.
- Chat is only one client of the runtime.
- V0 trusts first-party executors and explicitly trusted MCP servers; hostile plugin sandboxing is out of scope.

## Architecture

See:

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)

## Run the hackathon demo

```bash
uv sync --group dev
uv run latch-demo
```

Open `http://127.0.0.1:8765` and run the deterministic containment demo.

The demo deliberately gives the model a malicious web instruction that asks it
to read a fake secret outside the active skill's filesystem authority. The model
attempts the read; Latch rejects it deterministically and the legitimate task
continues.

See [Hackathon demo](docs/DEMO.md) for the scripted and live Nebius + Tavily
flows.

## Status

Hackathon V0 under active implementation. The authority broker, information-flow
policy, verified filesystem execution, sealed credentials, deterministic agent
runtime, declarative skills, narrow web search, and local demo control plane are
implemented with adversarial tests.
