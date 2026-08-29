2# OpenSystem — Architecture

This document describes the system architecture of OpenSystem at v0.1. It is
the authoritative description of component responsibilities.

## Overview

OpenSystem is built as a **layered pipeline of engines** operating around a
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
   `EvolutionEvent` with a reason and provenance. OpenSystem never modifies
   its own code; it modifies knowledge and generates new hypotheses.
5. **Policy is separate from attack logic.** Attack strategies never embed
   authorization assumptions.

## Component Responsibilities

| Component | Module | Responsibility |
|---|---|---|
| Adversarial Engine | `opensystem/core/engine.py` | Orchestrates the v0.1 loop; runs research sessions. |
| Campaign Engine | `opensystem/campaign/` | Orchestrates v0.2 adversarial campaigns (boundary testing). |
| Target Abstraction | `opensystem/target/interface.py` | The `TargetAdapter` contract. |
| Target Adapters | `opensystem/target/{mock,registry}.py` | Concrete targets + registration. |
| Observation Engine | `opensystem/observation/engine.py` | Captures and persists observations. |
| Hypothesis Engine | `opensystem/hypothesis/engine.py` | Creates and evaluates hypotheses. |
| Attack Planner | `opensystem/attack/planner.py` | Strategy registry; generates hypotheses/plans. |
| Experiment Engine | `opensystem/experiment/engine.py` | Executes tests; records experiments. |
| Evidence Collector | `opensystem/evidence/engine.py` | Collects and persists evidence. |
| Finding Engine | `opensystem/finding/engine.py` | Manages the finding lifecycle. |
| Evolution Engine | `opensystem/evolution/engine.py` | Records evolution; generates next hypotheses. |
| Knowledge Store | `opensystem/knowledge/store.py` | SQLite persistence + analytical queries. |
| Policy Layer | `opensystem/policy/` | The authorization boundary. |
| CLI | `opensystem/cli/` | User interface. |

## Data Model

All entities are defined in `opensystem/models.py` as pydantic models:

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

### v0.2 campaign entities

- `ProtectedResource` — something valuable that actors without entitlement
  must NOT access
- `Actor` / `Entitlement` — who is trying to access, and what they are
  declared allowed to do
- `SecurityInvariant` — a boundary that MUST hold, tested across interfaces
- `AttackObjective` — a structured objective (actor, resource, invariant)
- `AttackSurface` / `AttackPath` / `AttackGraph` — the discovered surface and
  the graph of alternative paths
- `Campaign` / `CampaignReport` — the complete resumable assessment and its
  evidence-based result

See [`target-model.md`](target-model.md) for the target model,
[`attack-model.md`](attack-model.md) for the attack model, and
[`campaign-model.md`](campaign-model.md) for the campaign architecture.

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
