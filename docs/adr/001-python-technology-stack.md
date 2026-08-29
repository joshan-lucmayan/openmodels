# ADR 001 — Technology Stack: Python

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenSystem is a long-term, evolving adversarial intelligence platform. It must
support plugin-style extension (target adapters, attack strategies, future
reasoning engines), persistent structured data, a CLI, and iterative research
development. The technology choice affects the entire project.

## Options Considered

| Option | Available in environment | Notes |
|---|---|---|
| **Python 3.14** | ✅ | pydantic and click already installed; SQLite built in. |
| Rust | ❌ not installed | No toolchain; excellent performance but slower iteration and steeper plugin development for this domain. |
| Go 1.26 | ✅ | Available; good for network services but weaker fit for polymorphic plugin + research ecosystem. |
| Node.js 26 | ✅ | Available; but the security/research ecosystem and data-science evolution path favor Python. |

## Decision

Use **Python 3.14** with **pydantic**, **click**, and standard-library
**SQLite**.

## Rationale

1. **Fit for the architecture**: OpenSystem is a plugin-oriented reasoning
   platform. Python's duck typing + pydantic give flexible, validated,
   polymorphic models — ideal for the `TargetAdapter`, strategy registry, and
   future pluggable reasoners.
2. **Already present**: the environment ships Python 3.14 with pydantic 2.13
   and click 8.5, and SQLite in the stdlib. No additional toolchain
   installation is needed.
3. **Research ecosystem**: the evolution path (LLM-backed reasoning, data
   science, ML, simulation interop) is strongest in Python.
4. **Iteration speed**: the platform will evolve rapidly through v0.2–v0.7.
   Python maximizes iteration speed for a reasoning engine.
5. **Performance is not the bottleneck**: v0.1 targets deterministic mock
   systems; the bottleneck is reasoning sophistication, not raw throughput.
   Hot paths can later be moved to Rust/C if ever required.

## Consequences

- Type safety is provided by pydantic models and static analysis rather than a
  strict compile-time type system.
- The project will rely on `ruff`/`mypy`-style checks as it grows.
- Rust remains a viable option for performance-critical subsystems later; the
  adapter/engine boundaries would allow that without redesign.

## Rejected

- **Rust**: not installed; would add significant toolchain and iteration
  overhead without proportional benefit at this stage.
- **Go**: weaker fit for the plugin/research model; smaller security-research
  ecosystem for the planned evolution (LLM, simulation).
- **Node.js**: weaker fit for research-oriented evolution; Python ecosystem
  dominates security research tooling.
