# OpenModels

**OpenModels is an evolving adversarial intelligence platform.**

OpenModels is designed to think like an exceptional attacker. It continuously
constructs a model of a target system, forms hypotheses about weaknesses,
plans and executes tests, learns from both success and failure, and evolves.

> **Find weaknesses.** The defender eliminates them. OpenModels evolves and
> searches for new weaknesses.

OpenModels is **not**:
- a vulnerability scanner
- a collection of scripts
- a penetration-testing checklist
- an AI chatbot
- a single-purpose cybersecurity tool

OpenModels is an **adversarial reasoning and testing engine** capable of
continuously searching for weaknesses in complex systems — web applications,
APIs, authentication and authorization systems, cloud infrastructure,
distributed systems, AI and agentic systems, and eventually simulations and
scientific systems.

## Status

This is the **v0.1 foundation**. It provides:

- The core adversarial loop (`OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST →
  OBSERVE → ANALYZE → UPDATE KNOWLEDGE → GENERATE NEXT HYPOTHESIS`)
- A generic, technology-agnostic target abstraction
- Structured, persistable entities: hypotheses, observations, experiments,
  evidence, findings, defenses, regressions, knowledge
- A persistent SQLite knowledge store supporting historical reasoning
- An explicit, auditable evolution mechanism
- A separate policy/authorization boundary for deployment
- A functional CLI
- Documentation-first architecture

OpenModels does **not** yet claim to be an autonomous attacker. The current
reasoning components are deterministic and mock-driven by design; the
architecture makes it possible to replace them with increasingly capable
reasoning systems later.

## Quickstart

```console
$ python3 -m venv .venv
$ .venv/bin/pip install -e ".[dev]"
$ .venv/bin/openmodels init
$ .venv/bin/openmodels target list
$ .venv/bin/openmodels research start --target mock --rounds 3
$ .venv/bin/openmodels finding list
$ .venv/bin/openmodels knowledge search "authorization"
$ .venv/bin/openmodels status
```

## Philosophy

The ultimate loop:

```
OPENMODELS (attacker) → FIND WEAKNESS → DEFENDER (fix) → HARDENED TARGET
     ↑                                                            │
     └─────────────────────── EVOLVE ◄────────────────────────────┘
```

OpenModels is the adversarial pressure that forces the defender to become
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
