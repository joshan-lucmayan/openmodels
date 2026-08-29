# Finding Engine

**Module**: `opensystem/finding/engine.py`

## Responsibility

Creates findings from successful experiments and manages the finding lifecycle.

## Lifecycle

```
DISCOVERED → CONFIRMED → DOCUMENTED → MITIGATION → VERIFICATION → CLOSED
```

## API

- `FindingEngine(store)` — construct.
- `create_from_experiment(experiment, target_id)` — create a finding if the
  experiment was SUCCESS.
- `transition(finding_id, target_status)` — advance a finding through the
  lifecycle; raises `ValueError` for invalid transitions.
- `list_findings(target_id)` — list findings.

## Validation

Transitions are validated against a transition table. Invalid transitions
raise `ValueError`. This prevents lifecycle corruption.

## Key Design Decisions

- A finding is only created from SUCCESS outcomes.
- A solved vulnerability never disappears: closing a finding does not delete
  it.
- The finding lifecycle is independent of the experiment lifecycle.