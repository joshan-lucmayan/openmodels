# OpenModels — Architecture

This document describes the system architecture of OpenModels at v0.1. It is
the authoritative description of component responsibilities.

## Overview

OpenModels is built as a **layered pipeline of engines** operating around a
**persistent knowledge store**, against a **generic target abstraction**, all
guarded by a **policy boundary**.

```
Target
   │
   ▼
Target Adapter (discover / observe / describe / execute_test / collect_evidence / reset)
   │
   ▼
Observation Engine ──▶ Knowledge Store
   │
   ▼
Adversarial Engine (OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST
                    → OBSERVE → ANALYZE → UPDATE → EVOLVE)
   │
   ├── Hypothesis Engine
   ├── Attack Planner (strategies)
   ├── Experiment Engine
   ├── Evidence Collector
   ├── Finding Engine
   └── Evolution Engine
   │
   ▼
Policy Enforcer (authorization boundary)
```

## Design Principles

1. **The reasoning engine is independent of any single target.** All
   technology-specific behavior lives behind `TargetAdapter`.
2. **Everything is structured and persistable.** The research process is
   represented as first-class entities, never unstructured text.
3. **Failed attacks are retained.** They are as valuable as successful ones.
4. **Evolution is explicit and auditable.** Every evolution step is an
   `EvolutionEvent` with a reason and provenance. OpenModels never modifies
   its own code; it modifies knowledge and generates new hypotheses.
5. **Policy is separate from attack logic.** Attack strategies never embed
   authorization assumptions.

## Component Responsibilities

| Component | Module | Responsibility |
|---|---|---|
| Adversarial Engine | `openmodels/core/engine.py` | Orchestrates the loop; runs research sessions. |
| Target Abstraction | `openmodels/target/interface.py` | The `TargetAdapter` contract. |
| Target Adapters | `openmodels/target/{mock,registry}.py` | Concrete targets + registration. |
| Observation Engine | `openmodels/observation/engine.py` | Captures and persists observations. |
| Hypothesis Engine | `openmodels/hypothesis/engine.py` | Creates and evaluates hypotheses. |
| Attack Planner | `openmodels/attack/planner.py` | Strategy registry; generates hypotheses/plans. |
| Experiment Engine | `openmodels/experiment/engine.py` | Executes tests; records experiments. |
| Evidence Collector | `openmodels/evidence/engine.py` | Collects and persists evidence. |
| Finding Engine | `openmodels/finding/engine.py` | Manages the finding lifecycle. |
| Evolution Engine | `openmodels/evolution/engine.py` | Records evolution; generates next hypotheses. |
| Knowledge Store | `openmodels/knowledge/store.py` | SQLite persistence + analytical queries. |
| Policy Layer | `openmodels/policy/` | The authorization boundary. |
| CLI | `openmodels/cli/` | User interface. |

## Data Model

All entities are defined in `openmodels/models.py` as pydantic models:

- `Target` — model of the target system (identity, interfaces, assets,
  trust boundaries, rules)
- `Observation` — something observed about a target
- `Hypothesis` — a testable claim; carries status and lineage (`parent_id`)
- `TestSpec` / `TestResult` — the concrete test and its outcome
- `Experiment` — a fully recorded test (hypothesis, test, expected vs
  observed, outcome, conclusion, evidence, next hypothesis)
- `Evidence` — structured evidence attached to experiments
- `Finding` — a confirmed weakness with a lifecycle
- `Defense` — a mitigation applied by the defender
- `Regression` — a proof that a fixed weakness stays fixed
- `Knowledge` — learned knowledge (strategies, defenses, assumptions, …)
- `EvolutionEvent` — an auditable evolution step
- `ResearchReport` — an evidence-based session summary

See [`target-model.md`](target-model.md) for the target model and
[`attack-model.md`](attack-model.md) for the attack model.

## The Adversarial Loop

The `AdversarialEngine.research()` method implements one session:

1. **DISCOVER** — `target.discover()` builds the `Target` model.
2. **OBSERVE** — `ObservationEngine` captures initial observations.
3. **MODEL** — the target description is persisted as knowledge.
4. **HYPOTHESIZE** — `AttackPlanner` generates hypotheses.
5. **PLAN** — each hypothesis becomes a `TestSpec` (via the Experiment Engine).
6. **TEST** — `target.execute_test()` runs against the target.
7. **OBSERVE RESULT** — outcome + evidence are recorded.
8. **ANALYZE** — `HypothesisEngine` evaluates the hypothesis.
9. **UPDATE KNOWLEDGE** — `EvolutionEngine` records the event.
10. **EVOLVE** — a blocked hypothesis generates an alternate-path hypothesis.

The session respects the policy boundary (max rounds, max experiments).

## Storage

SQLite via `KnowledgeStore`. Rationale is documented in
[`adr/002-sqlite-persistence.md`](adr/002-sqlite-persistence.md). The store
supports historical reasoning queries: previous attempts, what failed, open
findings, and per-target reports.

## Policy Boundary

Every test operation passes through `PolicyEnforcer.check()`. The policy
declares the target, environment, allowed operations, bounds, and destructive
action permission. A `PolicyViolation` stops the operation. See
[`security-model.md`](security-model.md).

## Extensibility Points

- **New targets**: implement `TargetAdapter`, register it via
  `register_target()`.
- **New attack families**: register `AttackStrategy` (declarative) or a
  strategy factory (programmatic) on the `AttackPlanner`.
- **New reasoning**: replace/augment the deterministic hypothesis generator
  behind the same `Hypothesis` interface (e.g., an LLM-backed reasoner).
- **New storage**: swap `KnowledgeStore` behind the same interface.

## Limitations (v0.1)

- The only shipped adapter is the deterministic mock target.
- Reasoning is deterministic and strategy-driven, not autonomous.
- The store is single-process SQLite; no network/UI layer.
- No real-world target adapters yet.

See [`roadmap.md`](roadmap.md) for evolution of the architecture.
