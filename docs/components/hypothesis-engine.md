# Hypothesis Engine

**Module**: `openmodels/hypothesis/engine.py`

## Responsibility

Manages the hypothesis lifecycle — creation and evaluation.

## API

- `HypothesisEngine(store)` — construct.
- `save(hypothesis)` — persist a hypothesis.
- `evaluate(hypothesis, experiment)` — set the hypothesis status based on
  experiment outcome (ACCEPTED/REJECTED/INCONCLUSIVE).

## Status Transitions

| Experiment outcome | Hypothesis status |
|---|---|
| SUCCESS | ACCEPTED |
| FAILURE | REJECTED |
| BLOCKED | REJECTED |
| ERROR | INCONCLUSIVE |
| INCONCLUSIVE | INCONCLUSIVE |

## Key Design Decisions

- A failed attack is never discarded; it updates the hypothesis status and is
  retained with its experiment.
- Evaluation is deterministic — no heuristics, no free text.