# Evolution Engine

**Module**: `openmodels/evolution/engine.py`

## Responsibility

Records auditable evolution events and generates the next hypothesis after a
blocked attack.

## API

- `EvolutionEngine(store)` — construct.
- `on_experiment(experiment)` — record evolution event based on outcome.
- `on_defense(defense, hypothesis)` — record defense application.
- `next_hypothesis(blocked_hypothesis, alternate_keys)` — generate the next
  hypothesis from a blocked one.

## Evolution Triggers

- ATTACK_SUCCESS — successful strategy recorded in knowledge.
- ATTACK_FAILURE — failed strategy recorded; alternate path generated.
- DEFENSE_APPLIED — defense recorded in knowledge.
- REGRESSION — regression test recorded.

## The Evolution Question

When a test fails: "What assumption made the previous attack fail, and what
other path could invalidate that assumption?"

The engine picks an untested alternate surface, creates a child hypothesis,
and records an evolution event with full provenance.

## Key Design Decisions

- Every evolution step has a trigger, reason, and provenance.
- OpenModels modifies its knowledge, not its code.
- Evolution is auditable: a future operator can reconstruct why any hypothesis
  exists.