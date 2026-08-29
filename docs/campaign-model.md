# OpenModels — Campaign Model (v0.2)

This document defines the adversarial campaign architecture — the v0.2
evolution of OpenModels from a weakness-oriented loop into a
security-boundary-oriented campaign engine.

## Mission

OpenModels is an attacker-oriented adversarial testing system. Its core
question is:

> **Can an actor who is not entitled to a protected resource cause that
> resource to be accessed, consumed, modified, or disclosed?**

The initial protected resource of interest is paid/premium AI inference, but
the architecture is NOT hardcoded around AI. The same architecture supports:

- paid APIs
- premium software features
- protected data
- cloud resources
- compute resources
- privileged functionality
- subscription-only functionality
- enterprise resources
- AI models
- other protected resources

## Core Concepts

The engine reasons about these concepts rather than thinking only in terms of
URLs:

```
ACTOR ──▶ RESOURCE ──▶ ENTITLEMENT ──▶ POLICY ──▶ INTERFACE
   │                                                 │
   └─────────────────── STATE ◀──────────────────────┘
   └─────────────────── OBSERVATION ◀────────────────┘
   └─────────────────── RESULT ◀─────────────────────┘
```

### Protected Resource

Something valuable that an actor without entitlement must NOT access.

```
ProtectedResource(
    id="res_premium_model",
    type="ai_model",
    value="premium inference",
    interfaces=["chat_api", "stream_api", "job_api"]
)
```

### Actor

An actor that may (or may not) be entitled to protected resources.

```
Actor(
    id="actor_free_user",
    kind=FREE_USER,
    entitlements=["basic_model"]
)
```

Actor privileges are NEVER assumed from client-supplied values; they are
declared in the entitlement model, and OpenModels investigates whether the
target actually enforces them.

### Entitlement

A declared entitlement: actor may perform an action on a resource. The engine
asks whether the target enforces the declared boundary.

### Security Invariant

A security boundary that MUST hold:

> "Actor without premium entitlement MUST NOT consume premium inference."

The invariant is tested across multiple interfaces and states. The engine
records: INVARIANT → TEST → RESULT.

### Attack Objective

A structured adversarial objective (not plain text):

```
AttackObjective(
    actor_id="actor_free_user",
    resource_id="res_premium_model",
    security_invariant_id=...,
    success_condition="demonstrate that the actor can access the resource
                       without entitlement"
)
```

## The Campaign

A campaign represents a complete adversarial assessment. It is resumable.

```
Campaign
├── Target
├── Scope
├── Protected Resources
├── Actors
├── Objectives
├── Security Invariants
├── Attack Strategies
├── Experiments
├── Findings
├── Evidence
└── Evolution History
```

## Campaign Flow

```
CREATE → DISCOVER → FORMULATE → TEST ALL PATHS → REPORT
```

1. **CREATE** — register the target, actors, and protected resources.
2. **DISCOVER** — build the attack surface model (interfaces, resources,
   auth states, transitions). Do not attack yet — understand first.
3. **FORMULATE** — create objectives for every (actor, resource) pair where
   the actor lacks entitlement.
4. **TEST ALL PATHS** — for each objective, test every interface exposing the
   resource. Record the invariant result per path.
5. **REPORT** — evidence-based campaign report.

## Attack Surface Discovery

The engine constructs a model of the target's reachable interfaces and state
transitions:

```
Target → Interfaces → Resources → Authentication states
       → Authorization states → State transitions → Attack surface graph
```

## Attack Graph

Attacks are represented as a graph:

```
Actor → Interface → Operation → Authorization boundary → Protected resource
```

Alternative paths are represented separately. The same resource may be
reachable via multiple interfaces, and enforcement may differ per interface:

```
                    Premium Model
                         ▲
                         │
              ┌──────────┼──────────┐
              │          │          │
           Chat API   Stream API   Job API
              │          │          │
              └──────────┼──────────┘
                         │
                    Authorization
```

## Invariant Testing

For each objective (actor, resource) pair where the actor is DENIED:

| Test outcome | Meaning |
|---|---|
| SUCCESS | Boundary crossed — the actor accessed the resource without entitlement → INVARIANT VIOLATED → finding |
| FAILURE | Boundary held — the actor was denied → INVARIANT PASSED on that path |

The aggregate status is VIOLATED if any path crossed the boundary.

## Adversarial Improvement Cycle

```
campaign run → boundary violated (finding)
defender enforces the boundary (adapter.enforce)
revalidate → the previously-violated boundary now holds (regression)
```

This mirrors the v0.1 evolution loop at the security-boundary level:

```
Violation A → Enforcement A → Violation B → Enforcement B → ...
```

## CLI

```
openmodels target add <name> --adapter mock --org ACME --env staging
openmodels campaign create <adapter> <name>
openmodels campaign run <campaign_id>
openmodels campaign enforce <campaign_id>
openmodels campaign graph <campaign_id>
openmodels campaign list
openmodels campaign show <campaign_id>
```

## Status Vocabulary

Campaigns report evidence-based status. OpenModels never claims a target is
"secure"; it reports which boundaries were tested, held, or crossed, and what
remains untested.
