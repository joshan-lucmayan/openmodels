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

## The HTTP Target Adapter

The shipped adapter is `HttpSiteTarget` (`opensystem/target/http_site.py`),
the real HTTP(S) target for live web applications. It speaks genuine HTTP
over the network (stdlib `urllib`) — no simulation:

- `discover()` probes the base URL and builds the `Target` model from real
  responses.
- `execute_test()` dispatches on `parameters["weakness"]` to real web probes
  (security headers, disclosure, listing, sensitive paths, methods, CORS,
  cookies, redirects, admin exposure, errors, TLS).
- Declares `DISCOVERY` and `TEST_PLANNING` capabilities; the experiment
  engine uses `plan_test()` to build adapter-specific test specs.

Live targets require an explicit authorization statement (`--confirm-
authorized`) and a recorded scope at registration time.

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
did we previously try? What failed? What changed?"

## Target Configuration

Deployment-time targets are described with `TargetConfig` (via
`opensystem target add`), which records target name, type, organization,
environment, authorized scope, available interfaces, test credentials,
testing policy, and emergency-stop configuration. Live HTTP targets also
carry their base URL and TLS-verification setting.
