# OpenSystem — Defenses

This document describes how OpenSystem records, tracks, and reasons over
defenses.

## The Principle

When OpenSystem discovers Attack A, the defender gains Defense A. OpenSystem
then records "Defense A exists" and searches for Attack B. This creates an
adversarial improvement loop:

```
Attack A → Defense A → Attack B → Defense B → Attack C → Defense C → ...
```

Defenses are first-class knowledge. They are never silently dropped.

## The Defense Model

A `Defense` (in `opensystem/models.py`) records:

- ID
- the finding it mitigates (`finding_id`)
- a description of the mitigation
- verification status
- when it was applied

## The Defense Workflow

1. **Discovery** — a finding confirms a weakness.
2. **Application** — the defender applies a mitigation (on the mock target,
   this is `MockTarget.defend()`).
3. **Recording** — a `Defense` is persisted, linked to the finding.
4. **Knowledge update** — the defense is added to the knowledge store with
   provenance.
5. **Evolution event** — an `EvolutionEvent` with trigger `DEFENSE_APPLIED`
   is recorded.
6. **Regression** — the original hypothesis is re-tested. The regression
   outcome proves whether the defense holds.

## Regression Testing

A regression test re-runs the hypothesis that originally confirmed the
weakness. The expected result after a defense is `FAILURE` (the path is
blocked). Regression records (see `Regression` model) preserve this proof over
time:

- `defense_id`
- `hypothesis_id`
- `target_id`
- outcome
- detail

## Reasoning Over Defenses

Because defenses are persisted with provenance, a future attacker can ask:

- "What defense stopped it?"
- "What changed since then?"
- "Which hypotheses must be re-tested after this change?"

The `defenses.md` ledger (this directory) and the knowledge store support
historical reasoning.

## The Ledger

Historical defense records are maintained under `docs/defenses.md` and the
knowledge base. Each entry should record: date, OpenSystem version, target
version, finding ID, defense applied, verification result.
