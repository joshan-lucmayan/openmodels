# OpenSystem

**OpenSystem is an evolving adversarial intelligence platform.**

OpenSystem is designed to think like an exceptional attacker. It continuously
constructs a model of a target system, forms hypotheses about weaknesses,
plans and executes tests, learns from both success and failure, and evolves.

> **Find weaknesses.** The defender eliminates them. OpenSystem evolves and
> searches for new weaknesses.

OpenSystem is **not**:
- a vulnerability scanner
- a collection of scripts
- a penetration-testing checklist
- an AI chatbot
- a single-purpose cybersecurity tool

OpenSystem is an **adversarial reasoning and testing engine** capable of
continuously searching for weaknesses in complex systems — web applications,
APIs, authentication and authorization systems, cloud infrastructure,
distributed systems, AI and agentic systems, and eventually simulations and
scientific systems.

## Status

This is **v0.3** — the adversarial campaign engine plus the proof-credential
system. It provides:

- The core adversarial loop (`OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST →
  OBSERVE → ANALYZE → UPDATE KNOWLEDGE → GENERATE NEXT HYPOTHESIS`)
- **Campaign architecture** centered on the question *"can an actor who is
  NOT entitled to a protected resource cause that resource to be accessed,
  consumed, modified, or disclosed?"*
- Protected resource, actor, entitlement, security-invariant, and objective
  models (not hardcoded to any one scenario or URL)
- Attack-surface discovery and attack graphs with alternative paths
- **Impact verification**: independent re-probes confirming a finding
  genuinely reached the protected resource
- **Show-once proof sessions**: single-display, hash-stored, revocable proof
  credentials bound to confirmed findings (authorized test target only)
- **Evidence-based case studies** for confirmed findings
- A generic, technology-agnostic target abstraction with explicit,
  declared adapter capabilities
- A persistent SQLite knowledge store with tested additive migrations
- An explicit, auditable evolution mechanism
- A separate policy/authorization boundary (environment/scope aware)
- A functional CLI
- Documentation-first architecture

OpenSystem does **not** yet claim to be an autonomous attacker. The current
reasoning components are deterministic and mock-driven by design; the
architecture makes it possible to replace them with increasingly capable
reasoning systems later.

## Quickstart

```console
$ python3 -m venv .venv
$ .venv/bin/pip install -e ".[dev]"
$ .venv/bin/opensystem init
$ .venv/bin/opensystem target add premium-svc --adapter mock --org ACME --env staging
$ .venv/bin/opensystem campaign create mock premium-boundary
$ .venv/bin/opensystem campaign run <campaign_id>
$ .venv/bin/opensystem campaign graph <campaign_id>
$ .venv/bin/opensystem finding list
$ .venv/bin/opensystem knowledge search "authorization"
$ .venv/bin/opensystem status
```

## Philosophy

The ultimate loop:

```
OPENSYSTEM (attacker) → FIND WEAKNESS → DEFENDER (fix) → HARDENED TARGET
     ↑                                                            │
     └─────────────────────── EVOLVE ◄────────────────────────────┘
```

OpenSystem is the adversarial pressure that forces the defender to become
better. Every failed attack and every blocked path is valuable information.

## Documentation

See [`docs/`](docs/):

- [`docs/vision.md`](docs/vision.md) — project vision
- [`docs/architecture.md`](docs/architecture.md) — system architecture
- [`docs/security-model.md`](docs/security-model.md) — policy and authorization
- [`docs/roadmap.md`](docs/roadmap.md) — planned evolution
- [`docs/adr/`](docs/adr/) — architecture decision records
- [`docs/components/`](docs/components/) — component responsibilities

## License

MIT
