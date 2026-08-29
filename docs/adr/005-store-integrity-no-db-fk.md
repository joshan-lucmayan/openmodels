# ADR 005 — Store Integrity Without DB-Level Foreign Keys

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

The initial schema defined SQLite `FOREIGN KEY REFERENCES` constraints.
Testing revealed that entities (observations, hypotheses, experiments,
findings) are legitimately persisted with a `target_id` before the
corresponding `targets` row exists — e.g., tests create hypotheses directly,
and the mock target emits observations before the target model row is saved.
DB-level FKs caused spurious `IntegrityError`s in exactly these valid flows.

## Decision

Remove DB-level `FOREIGN KEY REFERENCES` clauses. Keep the schema columns and
indexes; enforce referential integrity at the application layer through the
`KnowledgeStore` API and pydantic models.

## Rationale

1. **The store is an internal seam**: pydantic models + the store's public API
   are the real contract. DB FKs add friction without catching genuine errors
   in the current usage patterns.
2. **Persist-then-link ordering is legitimate**: OpenModels may record an
   observation or hypothesis before the target row is committed; this is
   normal, not corruption.
3. **Keeping FKs would force awkward write-ordering** across many call sites
   for no security or correctness benefit at v0.1.

## Consequences

- Referential integrity is the responsibility of the application layer. This
  is acceptable while `KnowledgeStore` is the single write path.
- If the store is later moved to a server DB (PostgreSQL), real FKs can be
  reintroduced together with transactional write patterns.

## Rejected

- **Enforcing FKs**: caused valid workflows to fail; would require brittle
  ordering hacks.
- **Full ORM**: heavier than needed; see ADR 003.
