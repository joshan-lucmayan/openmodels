# OpenSystem — Target Model

OpenSystem uses a **generic target model** rather than hardcoding the platform
around one technology. This is what allows the same adversarial engine to
reason about web applications, APIs, identity systems, AI/agent systems,
distributed systems, simulations, and more.

## The Target Abstraction

```
Target
 ├── Identity          — name, kind, version
 ├── Interfaces        — the surfaces OpenSystem can interact with
 ├── Assets            — the things that have value and can be harmed
 ├── Trust boundaries  — where trust assumptions change
 ├── Rules             — declared invariants the target claims to hold
 ├── State             — observable state over time
 ├── Dependencies      — things the target relies on
 ├── Permissions       — what the target (or its users) may do
 └── Observable behavior — what OpenSystem can actually observe
```

`Target` (in `opensystem/models.py`) captures identity, interfaces, assets,
trust boundaries, and rules. The remaining aspects are captured through the
adapter's `observe()` / `describe()` lifecycle and persisted as observations
and knowledge.

## The TargetAdapter Interface

Every target implements the common interface (in
`opensystem/target/interface.py`):

| Method | Responsibility |
|---|---|
| `discover()` | Build/load the `Target` model (identity, interfaces, assets, trust boundaries, rules). |
| `observe()` | Return current observations from the target. |
| `describe()` | Return a structured description of the target's current state. |
| `execute_test(test)` | Execute a single `TestSpec`, return a `TestResult`. |
| `collect_evidence()` | Gather evidence supporting the last executed test. |
| `reset()` | Return the target to a known, authorized state. |

The reasoning engine depends only on this interface — never on a concrete
adapter.

## Target Adapter Registry

Adapters are registered by name in `TargetRegistry`:

```python
from opensystem.target.registry import register_target
from opensystem.target.interface import TargetAdapter

class WebAppAdapter(TargetAdapter):
    name = "webapp"
    ...

register_target(WebAppAdapter)
```

New adapters (web/API, LLM service, simulation, …) are added without touching
the engine.

## The Mock Target

The v0.1 shipped adapter is `MockTarget` (`opensystem/target/mock.py`). It
models a system as a set of weaknesses, each either *active* (exploitable) or
*blocked* (defended):

- A test names a `weakness` key.
- Active → `SUCCESS`; blocked → `FAILURE`; unknown → `INCONCLUSIVE`.

It also exposes `defend()` (simulating the defender patching a weakness) which
drives the evolution/regression demonstration. The mock is deterministic and
safe, giving the engine a real — but controllable — target.

## Supported Target Classes (future)

The target model is designed so these can be attached via adapters without
changing the reasoning core:

Web applications, APIs, authentication systems, authorization systems, cloud
infrastructure, databases, distributed systems, mobile applications, desktop
applications, network services, IoT systems, AI systems, LLM applications,
agentic systems, business workflows, financial systems, payment systems,
enterprise software, supply-chain systems, source code, configuration,
protocols, physical-system simulations, scientific systems, space-system
simulations, and other computational systems.

## How OpenSystem Builds Its Model

1. **DISCOVER** — `discover()` produces the initial `Target`.
2. **OBSERVE** — `observe()` produces observations, persisted to the store.
3. **MODEL** — the description is persisted as knowledge (assumptions about
   the target).
4. **UPDATE** — every experiment result updates the model via knowledge
   records and evolution events.

A future attacker can reconstruct the model from the knowledge store: "What
did we previously try? What failed? What defense stopped it? What changed?"

## v0.2 — Actors, Entitlements, and Protected Resources

The v0.2 campaign architecture adds a security-boundary perspective to the
target model. OpenSystem models what is *protected*, who may access it, and
whether the target actually enforces the declared boundaries.

```
Target
 ├── Protected Resources   — what an unauthorized actor must NOT access
 ├── Actors                — who may (or may not) be entitled
 ├── Entitlements          — declared access rights
 ├── Security Invariants   — boundaries that MUST hold
 ├── Interfaces            — the surfaces where boundaries are tested
 └── Attack surface        — the reachable graph of the above
```

### Target Configuration

Deployment-time targets are described with `TargetConfig` (via
`opensystem target add`), which records target name, type, organization,
environment, authorized scope, available interfaces, test credentials,
protected resources, testing policy, time window, and emergency-stop
configuration. The core engine does NOT assume every target is a website.

### Adapter Security-Boundary Protocol

Adapters that model security boundaries expose additional optional methods:

- `describe_resources()` — the protected resources
- `describe_actors()` — the actors
- `describe_interfaces()` — the reachable interfaces
- `describe_auth_states()` / `describe_transitions()` — states and transitions
- `entitlement_decision(actor, resource, action)` — the declared entitlement

These feed attack-surface discovery and objective formulation. See
[`campaign-model.md`](campaign-model.md).
