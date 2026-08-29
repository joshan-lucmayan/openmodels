# Core Engine

**Module**: `openmodels/core/engine.py`

## Responsibility

Orchestrates the full adversarial loop: OBSERVE → MODEL → HYPOTHESIZE → PLAN
→ TEST → OBSERVE RESULT → ANALYZE → UPDATE KNOWLEDGE → GENERATE NEXT
HYPOTHESIS.

## API

- `AdversarialEngine(store, policy, planner)` — construct with dependencies.
- `research(target, rounds)` — run a research session; returns `ResearchReport`.
- `run_experiment(target, hypothesis)` — run a single experiment.
- `security_test(target, rounds)` — run the full attack → defend → evolve cycle.

## Key Design Decisions

- Composes all sub-engines (hypothesis, experiment, finding, evolution, etc.);
  does not implement their logic.
- The `research()` method is the canonical loop. It is deterministic and
  honors the policy boundary.
- `security_test()` is a convenience for demonstrating the full cycle; it
  applies defenses to findings and re-runs research.

## Data Flow

```
target.discover() → Target
target.observe() → Observation[]
planner.generate() → Hypothesis[]
for each hypothesis:
    experiment = experiment_engine.run(hypothesis, target)
    hypothesis_engine.evaluate(hypothesis, experiment)
    if success: finding_engine.create_from_experiment(...)
    evolution_engine.on_experiment(experiment)
    if blocked: evolution_engine.next_hypothesis(...)
→ ResearchReport
```