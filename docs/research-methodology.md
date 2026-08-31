# OpenSystem — Research Methodology

This document defines the research methodology OpenSystem follows. It is the
operating doctrine for the adversarial engine.

## The Research Loop

A research session implements:

```
OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST → OBSERVE RESULT
        → ANALYZE → UPDATE KNOWLEDGE → GENERATE NEXT HYPOTHESIS → TEST AGAIN
```

The loop must support iteration. OpenSystem is not a one-shot scanner.

## Methodology Phases

### 1. Discover and Model

OpenSystem builds a model of the target before generating sophisticated
attacks. It records identity, interfaces, assets, trust boundaries, rules, and
initial observations. The model is persisted as knowledge so it can be
reasoned over later.

### 2. Hypothesize

Hypotheses are generated from the strategy set. Each hypothesis challenges a
specific assumption of the target. Hypotheses are structured objects with
status and lineage — never free text.

### 3. Plan

Each hypothesis is planned into a concrete, executable `TestSpec`. The plan
names the target surface and the expected outcome.

### 4. Test

The test runs against the target through the target adapter. The result —
success, failure, blocked, inconclusive, or error — is recorded.

### 5. Analyze

The hypothesis is evaluated against the result. A confirmed hypothesis becomes
a finding; a rejected hypothesis is retained as a blocked path.

### 6. Update Knowledge

Every result updates the knowledge base: successful strategies, failed
strategies, target changes. Every update carries provenance.

### 7. Evolve

A blocked hypothesis generates the next hypothesis by asking which assumption
held and what alternate path could invalidate it.

## Learning from Failure

A failed attack is valuable information:

```
Hypothesis: Authorization can be bypassed.
Test:       FAILED.
Observation: Central authorization layer rejected request.
Inference:  This attack path is blocked.
Next:       Look for an alternate execution path whose policy differs.
```

The research graph maintains:

```
Hypothesis
    ├── Test
    │     ├── Success
    │     ├── Failure
    │     └── Inconclusive
    └── New hypotheses
```

## Learning from Success

A confirmed weakness flows through:

```
Discovery → Evidence → Reproduction → Impact assessment → Finding
→ Defender notification
```

After the defender fixes it:

```
Fix → Verification → Regression test → Attack pattern updated
→ New attack generation
```

A solved vulnerability never disappears.

## Experiment Recording

Every experiment records (see `Experiment` in `opensystem/models.py`):

- experiment ID
- target
- OpenSystem version
- timestamp
- hypothesis
- test
- expected result
- observed result
- evidence
- conclusion
- next hypothesis

Failed experiments MUST be retained.

## Evidence-Based Reporting

OpenSystem never claims "the target is secure." It reports evidence-based
status across the classes:

- TESTED
- VERIFIED
- FAILED
- BLOCKED
- UNKNOWN
- UNTESTED

An example report:

> "OpenSystem tested 1,842 attack hypotheses across 73 attack classes.
> 1,831 were blocked, 11 produced findings, and 42 attack classes remain
> untested."

The `ResearchReport` model and the `status` CLI command implement this
reporting style.
