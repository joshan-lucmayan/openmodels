# OpenModels — Vision

## What OpenModels Is

OpenModels is an **evolving adversarial intelligence platform**.

It is designed to think like an exceptional attacker. Its primary objective is
to **find weaknesses**. The defender's objective is to **eliminate those
weaknesses**. OpenModels then evolves and searches for new weaknesses. This
creates a continuous adversarial cycle.

```
OPENMODELS ──discover──▶ WEAKNESS ──exploit/test──▶ DEFENDER
    ▲                                                    │
    │                                                    │ patch
    │                                                    ▼
    └─────────────── NEW ATTACK ◀────── evolve ──── HARDENED SYSTEM
```

## What OpenModels Is Not

OpenModels is **not**:

- a vulnerability scanner
- a collection of scripts
- a penetration-testing checklist
- an AI chatbot
- a single-purpose cybersecurity tool

OpenModels is an **adversarial reasoning and testing engine** capable of
continuously searching for weaknesses in complex systems. It understands a
target, constructs hypotheses, tests them, learns from the result, and
generates new hypotheses.

## Generality

OpenModels must NOT be architecturally limited to AI systems. Its attack and
research framework must eventually reason about many classes of systems:

Web applications, APIs, authentication systems, authorization systems, cloud
infrastructure, databases, distributed systems, mobile applications, desktop
applications, network services, IoT systems, AI systems, LLM applications,
agentic systems, business workflows, financial systems, payment systems,
enterprise software, supply-chain systems, source code, configuration,
protocols, physical-system simulations, scientific systems, space-system
simulations, and other computational systems.

The architecture therefore uses a **generic target model** rather than
hardcoding the platform around one technology.

## The Adversarial Loop

The fundamental engine:

```
OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST → OBSERVE RESULT
        → ANALYZE → UPDATE MODEL → GENERATE NEW HYPOTHESIS → TEST AGAIN
```

This loop must support iteration. OpenModels is not a one-shot scanner.

## Learning from Failure

A failed attack is valuable information. When a test fails, OpenModels records:

- the hypothesis
- the observation that blocked it
- the inference (this attack path is closed)
- the next hypothesis (look for an alternate execution path whose policy differs)

## Learning from Success

A confirmed weakness becomes a finding, which becomes part of the knowledge
base. After the defender fixes it, OpenModels verifies the fix, records a
regression test, updates its attack patterns, and generates new attacks.

A solved vulnerability never simply disappears.

## The Attacker and Defender Share the System

```
Attack A → Defense A → Attack B → Defense B → Attack C → Defense C → ...
```

When OpenModels discovers Attack A, the defender gains Defense A. OpenModels
then records "Defense A exists" and searches for Attack B. The long-term
objective is continuous security improvement.

## The Final Objective

The question OpenModels continuously asks is:

> **"What assumption does this system currently rely upon, and can that
> assumption be demonstrated to be false?"**

OpenModels is not the defender. OpenModels is the adversarial pressure that
forces the defender to become better.

## Status

OpenModels is at **v0.1**: a functional foundation with a deterministic mock
target, a real adversarial loop, structured research entities, a persistent
knowledge store, an auditable evolution mechanism, and a policy boundary.
It does **not** claim to be an autonomous attacker yet. See
[`roadmap.md`](roadmap.md) for the path forward.
