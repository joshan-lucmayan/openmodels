# Experiment Executor

**Module**: `openmodels/experiment/engine.py`

## Responsibility

Executes a single hypothesis as a concrete test against the target, records
the full experiment, and persists evidence.

## API

- `ExperimentEngine(store, policy)` — construct.
- `run(hypothesis, target, target_model)` — execute the test, collect
  evidence, persist experiment, return `Experiment`.

## Execution Flow

1. Derive `TestSpec` from hypothesis (name, parameters, expected outcome).
2. Check policy (`PolicyEnforcer.check(Operation.TEST, target_model)`).
3. Call `target.execute_test(test)` → `TestResult`.
4. Call `target.collect_evidence()` → `list[Evidence]`.
5. Build `Experiment` with outcome, observed result, conclusion.
6. Persist experiment and evidence.
7. Return experiment.

## Key Design Decisions

- Every experiment is fully recorded and persisted.
- Failed experiments are never discarded — a failed attack is valuable.
- Policy enforcement is a single gate call before execution.