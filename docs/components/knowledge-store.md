# Knowledge Store

**Module**: `opensystem/knowledge/store.py`

## Responsibility

Persistent storage for the OpenSystem research graph. Supports all entity
types (targets, observations, hypotheses, experiments, evidence, findings,
knowledge, evolution events) plus analytical queries.

## Storage

SQLite, single-file, WAL journal mode. Schema is defined in `_create_tables()`.

## Analytical Queries

- `previous_attempts(target_id)` — all experiments, newest first.
- `what_failed(target_id)` — experiments with FAILURE outcome.
- `open_findings()` — findings not yet CLOSED.
- `search_knowledge(query, target_id)` — text search over knowledge records.
- `build_report(target_id)` — aggregate `ResearchReport` for a target.

## Key Design Decisions

- Schema versioning via `PRAGMA user_version`.
- All entity serialization is explicit (JSON for dict fields, ISO strings
  for timestamps) — no ORM magic.
- The store is a seam: swapping to PostgreSQL means implementing the same
  public API.
- See ADR 002 (SQLite) and ADR 005 (no FK constraints).