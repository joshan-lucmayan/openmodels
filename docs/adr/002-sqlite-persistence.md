# ADR 002 — Persistence: SQLite (initially)

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenModels must persist a growing research graph: observations, hypotheses,
experiments, evidence, findings, defenses, regressions, knowledge, and
evolution events. It must support historical reasoning queries ("what did we
try?", "what failed?", "what defense stopped it?"). The storage choice should
not over-commit the project to infrastructure it does not yet need.

## Options Considered

| Option | Assessment |
|---|---|
| **SQLite (stdlib)** | Zero configuration, single file, transactional, built in, no server. |
| PostgreSQL | Powerful, but requires a database server; overkill for single-instance development. |
| Plain JSON/YAML files | No querying, no atomicity, poor fit for a research graph. |
| In-memory only | Loses the persistent research history, which is a core requirement. |
| Redis / key-value | No relational querying; poor fit for the analytical queries. |

## Decision

Use **SQLite** as the initial persistent store, via a dedicated
`KnowledgeStore` abstraction.

## Rationale

1. **Zero configuration**: no server, no credentials, no network — the store
   works everywhere the project runs.
2. **Single-instance fit**: the expected usage pattern during early
   development is one operator, one machine. SQLite comfortably handles this.
3. **Transactional + queryable**: SQL is ideal for the historical-reasoning
   queries OpenModels needs.
4. **Built into Python**: no extra dependency.
5. **Clean migration path**: all persistence flows through `KnowledgeStore`;
   swapping in PostgreSQL (e.g., via SQLAlchemy) behind the same interface is
   a contained change, not a redesign.

## Consequences

- Concurrency is limited to a single writer (fine for the current deployment
  model). Multi-operator / multi-process deployments would need to move to a
  server database or add write serialization.
- `KnowledgeStore` is a seam: its public API must stay database-agnostic.

## Rejected

- **PostgreSQL now**: premature; adds operational burden without proportional
  benefit at v0.1. Revisit when multi-operator or multi-node deployments are
  real requirements.
- **JSON files**: no queryability, no atomicity, and fragile at scale.
- **In-memory only**: contradicts the persistent-research-history requirement.
