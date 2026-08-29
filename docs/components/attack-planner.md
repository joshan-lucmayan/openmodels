# Attack Planner

**Module**: `openmodels/attack/planner.py`

## Responsibility

Holds attack strategies and generates hypotheses from them.

## API

- `AttackPlanner(store)` — construct.
- `register_strategy(strategy)` — register a declarative strategy.
- `register_factory(name, factory)` — register a programmatic hypothesis
  factory.
- `list_strategies()` — list all registered strategies.
- `generate_hypotheses(target, observations, limit)` — generate hypotheses.

## Strategy Types

1. **Declarative** (`AttackStrategy`): a named family with a `weakness_key`.
   The default set covers 8 attack classes across 8 families.
2. **Factory** (callable): receives `(target, observations, store)` and
   returns `list[Hypothesis]`. This is the extension point for future
   reasoning-based planners.

## Key Design Decisions

- The planner is a strategy system, not a hardcoded list of attacks.
- Hypotheses for already-blocked paths are still generated (re-testing =
   regression testing).
- Deduplication: statements already accepted are skipped.