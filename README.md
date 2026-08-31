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

This is **v0.4** — a production-ready engine for real HTTP(S) targets. It
provides:

- The core adversarial loop (`OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST →
  OBSERVE → ANALYZE → UPDATE KNOWLEDGE → GENERATE NEXT HYPOTHESIS`)
- **Real HTTP(S) testing** against live web targets (stdlib `urllib`, no
  simulation): security headers, server disclosure, directory listing,
  sensitive paths, dangerous HTTP methods, CORS misconfiguration, cookie
  flags, open redirects, admin exposure, error disclosure, and TLS
- Adapter-scoped attack strategies (a live web target is only tested with
  `http-*` probes)
- Explicit, declared adapter capabilities (`DISCOVERY`, `TEST_PLANNING`)
- A persistent SQLite knowledge store with tested additive migrations
- An explicit, auditable evolution mechanism
- A separate policy/authorization boundary (environment/scope aware,
  `--confirm-authorized` gate for live targets)
- A functional CLI

OpenSystem does **not** yet claim to be an autonomous attacker. The current
reasoning components are deterministic by design; the architecture makes it
possible to replace them with increasingly capable reasoning systems later.

## Quickstart

```console
$ python3 -m venv .venv
$ .venv/bin/pip install -e ".[dev]"
$ .venv/bin/opensystem init
$ .venv/bin/opensystem target add mysite --adapter http \
      --url https://mysite.example --scope "https://mysite.example/*" \
      --confirm-authorized
$ .venv/bin/opensystem research start mysite --rounds 20 --max-experiments 100
$ .venv/bin/opensystem finding list
$ .venv/bin/opensystem knowledge search "headers"
$ .venv/bin/opensystem status
```

> **Authorization**: only register targets you own or have explicit permission
> to test. The `http` adapter refuses to run without `--confirm-authorized`,
> and every session is scoped to the recorded authorization scope.

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
