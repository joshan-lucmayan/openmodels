# OpenModels — Attack Model

This document defines how OpenModels reasons about attacks. It is the model
for the "attacker" side of the platform.

## The Attack Hypothesis

The atomic unit of adversarial reasoning in OpenModels is the **hypothesis**:
a testable claim that a specific assumption of the target is false.

> "What assumption does this system currently rely upon, and can that
> assumption be demonstrated to be false?"

Every hypothesis has:

- a **statement** — the claim
- an **assumption** — the target assumption being challenged
- a **status** — proposed, active, tested, accepted, rejected, inconclusive,
  superseded
- a **lineage** — `parent_id` links it to the hypothesis it evolved from
- an **origin** — the strategy that produced it

## The Attack Lifecycle

```
Hypothesis
   │
   ├── Test (Experiment)
   │     ├── SUCCESS   → finding (weakness confirmed)
   │     ├── FAILURE   → path blocked by a defense → evolve
   │     ├── BLOCKED   → policy prevented execution
   │     └── INCONCLUSIVE / ERROR
   │
   └── New hypotheses (via evolution)
```

## Attack Classes

v0.1 ships declarative strategies across distinct attack families. Each maps
to a `weakness_key` on the target adapter:

| Family | Strategy | Weakness key |
|---|---|---|
| Authentication | auth-bypass | `auth-bypass` |
| Authorization | authz-ownership | `authz-ownership` |
| Input validation | input-traversal | `input-traversal` |
| Resource usage | resource-abuse | `resource-abuse` |
| AI / agent | agent-tool-boundary | `agent-tool-boundary` |
| Session management | session-fixation | `session-fixation` |
| Business logic | state-transition | `state-transition` |
| Supply chain | dependency-supply-chain | `dependency-supply-chain` |

This set is a *foundation*, not a ceiling. New attack families are added by
registering new strategies — the core engine does not change. See
[`attack-catalog.md`](attack-catalog.md) for the full catalog and the
expansion plan.

## Strategy System

The `AttackPlanner` holds strategies. Two kinds of strategy:

1. **Declarative** (`AttackStrategy`) — a named family with a `weakness_key`.
   v0.1's built-ins are declarative.
2. **Factory** — a callable `(target, observations, store) -> list[Hypothesis]`
   that produces hypotheses programmatically. This is the extension point for
   future reasoning-based planners (LLM-backed, cross-component, etc.).

## Planning

A hypothesis is planned into a concrete `TestSpec` by the Experiment Engine:
- the test name and description derive from the hypothesis
- the parameters reference the target surface (the `weakness` key)
- the expected outcome is derived from hypothesis confidence

The target adapter executes the `TestSpec` and returns a `TestResult`.

## Success

A successful test:

1. produces a `Finding` (via the Finding Engine)
2. is recorded as a **successful strategy** in knowledge
3. records an `EvolutionEvent` with trigger `ATTACK_SUCCESS`

The finding lifecycle is described in [`findings.md`](findings.md).

## Failure

A failed test is **not discarded**. It:

1. marks the hypothesis REJECTED
2. is retained as a `FAILURE` experiment (`what_failed()` query)
3. is recorded as a **failed strategy** in knowledge
4. records an `EvolutionEvent` with trigger `ATTACK_FAILURE`
5. triggers evolution: an alternate-path hypothesis is generated

## Inconclusive / Error

An inconclusive or error result keeps the hypothesis `INCONCLUSIVE` and is
retained for the record. No finding is created and no evolution event fires.

## The Evolution Question

When a defense blocks an attack, OpenModels asks:

> "What assumption made the previous attack fail, and what other path could
> invalidate that assumption?"

The `EvolutionEngine.next_hypothesis()` picks an untested alternate surface
from the available strategies and creates a child hypothesis. This is the
auditable evolution step (see [`evolution.md`](evolution.md)).

## Status Reporting

OpenModels never claims a target is "secure". It reports what it did:

> "OpenModels tested N attack hypotheses across M attack classes. K were
> confirmed as findings, J were blocked, and the remaining classes were
> tested or remain untested."

Statuses distinguish: TESTED, VERIFIED, FAILED, BLOCKED, UNKNOWN, UNTESTED.

## v0.2 — The Security-Boundary Perspective

The campaign architecture reframes the attack model around protected
resources and entitlements. The fundamental question becomes:

> "Can an actor who is NOT entitled to a protected resource cause that
> resource to be accessed, consumed, modified, or disclosed?"

Instead of "can weakness X be demonstrated?", OpenModels asks: for each
actor/resource pair where the actor lacks entitlement, does the target
actually enforce the boundary across every interface that exposes the
resource?

The attack model is now:

```
Actor → Interface → Operation → Authorization boundary → Protected resource
```

Each path is an `AttackPath` with an entitlement decision and a test outcome.
Boundaries may hold on some interfaces and fail on others — alternative paths
are represented separately in the attack graph.

See [`campaign-model.md`](campaign-model.md) for the full campaign
architecture.
