# Observation Engine

**Module**: `opensystem/observation/engine.py`

## Responsibility

Captures observations from a target and persists them to the knowledge store.

## API

- `ObservationEngine(store)` — construct.
- `observe(target, target_id=None)` — call `target.observe()`, stamp the
  target ID on each observation, persist them, and return the list.

## Key Design Decisions

- Observations may arrive before the target model row is persisted; the
  engine stamps the correct ID.
- Lightweight — the engine does not interpret observations; it records them.
  Interpretation is the responsibility of the hypothesis engine and attack
  planner.