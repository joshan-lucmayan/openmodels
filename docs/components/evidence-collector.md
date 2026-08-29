# Evidence Collector

**Module**: `openmodels/evidence/engine.py`

## Responsibility

Collects evidence from a target after a test and persists it.

## API

- `EvidenceCollector(store)` — construct.
- `collect(target)` — call `target.collect_evidence()`, persist, return.

## Key Design Decisions

- Thin wrapper: evidence collection is delegated to the target adapter.
- Evidence is persisted with a reference to the experiment (after the
  experiment is saved).