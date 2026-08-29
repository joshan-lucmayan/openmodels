# OpenSystem — Evolution

This is one of the most important components of OpenSystem.

## The Objective

When a defender blocks an attack, OpenSystem must **not** simply repeat the
same attack indefinitely. It must ask:

> **"What assumption made the previous attack fail, and what other path could
> invalidate that assumption?"**

The long-term objective is **continuous security improvement**:

```
Attack A → Defense A → Attack B → Defense B → Attack C → Defense C → ...
```

## What Evolves

OpenSystem evolves its **knowledge and hypotheses**, never its own code. Every
evolution step is an explicit, auditable `EvolutionEvent` with:

- a `trigger` (ATTACK_SUCCESS, ATTACK_FAILURE, DEFENSE_APPLIED, TARGET_CHANGE,
  REGRESSION, MANUAL)
- a `reason` — why this step happened
- `from_hypothesis_id` / `to_hypothesis_id` — the lineage
- a `provenance` — which component created it

This makes evolution auditable: every step has a reason and provenance.

## Evolution Events

The `EvolutionEngine` records events in these situations:

| Trigger | When | What is recorded |
|---|---|---|
| ATTACK_SUCCESS | A test confirms a weakness | Successful strategy added to knowledge |
| ATTACK_FAILURE | A test is blocked by a defense | Failed strategy added to knowledge |
| DEFENSE_APPLIED | The defender patches a finding | Defense added to knowledge |
| REGRESSION | A fixed weakness is re-tested | Regression record |
| TARGET_CHANGE | The target's model changes | Knowledge record |
| MANUAL | Operator-driven | Knowledge record |

## The Evolution Step

`EvolutionEngine.next_hypothesis(blocked_hypothesis, alternate_keys)`:

1. Given a blocked hypothesis, enumerate alternate attack surfaces from the
   strategy set.
2. Skip surfaces already tested (accepted or rejected).
3. Create a child hypothesis targeting the first untested alternate surface.
4. Record an `EvolutionEvent` linking the blocked hypothesis to the child.

This is the audit-trail version of "try a different path".

## The Full Cycle (as demonstrated by `security-test`)

```
ROUND 1 (attack)
  OBSERVE → HYPOTHESIZE → TEST → 5 findings confirmed
DEFEND
  5 defenses applied to the 5 findings
REGRESS
  5 re-tests → all FAILURE (defenses held)
ROUND 2 (evolve)
  New attack surfaces generated → 3 previously-untested classes tested
  → 3 new findings
```

## Provenance and Auditability

OpenSystem does **not** implement arbitrary self-modifying code. The explicit,
auditable evolution mechanism means:

- every knowledge record has `provenance`
- every evolution event has a `reason` and lineage
- a future operator can reconstruct *why* any hypothesis exists

## Statuses vs Claims

Evolution is driven by evidence. OpenSystem tracks TESTED / VERIFIED / FAILED
/ BLOCKED / UNKNOWN / UNTESTED and never claims "secure". Each evolution step
is a response to evidence about the target.
