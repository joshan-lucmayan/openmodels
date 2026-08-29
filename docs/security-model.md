# OpenModels — Security Model

This document defines how OpenModels is *deployed* and what it is *authorized*
to do. It is deliberately distinct from:

- the **threat model** — threats to OpenModels itself
  ([`threat-model.md`](threat-model.md))
- the **attack model** — how OpenModels reasons about targets
  ([`attack-model.md`](attack-model.md))

## Principle

The adversarial reasoning engine is independent of target authorization. The
core engine is capable of sophisticated adversarial reasoning; the deployment
layer determines which targets and operations the current OpenModels instance
is authorized to perform.

This allows the same engine to be used for:

- personal security testing
- company security testing
- authorized penetration testing
- security laboratories
- CTFs
- academic research
- open-source projects
- enterprise security programs
- simulation
- scientific research

…without embedding authorization assumptions throughout the attack engine.

## The Policy Layer

The policy (`Policy` in `openmodels/policy/models.py`) declares:

| Field | Meaning |
|---|---|
| `target_name` | The target the session is authorized against (`*` = wildcard). |
| `environment` | The environment context (e.g., `local-mock`). |
| `allowed_operations` | OBSERVE, TEST, RESET, DESTRUCTIVE, AUTHENTICATED. |
| `max_rounds` | Cap on research rounds. |
| `max_experiments` | Cap on experiments. |
| `allowed_credentials` | Credentials the session may use (references only). |
| `destructive_actions_allowed` | Whether destructive actions are permitted. |
| `stop_on_finding` | Whether to stop when a finding is produced. |

## Enforcement

`PolicyEnforcer.check(operation, target)` is the **single gate**. Every test
execution passes through it. A disallowed operation raises `PolicyViolation`
and stops.

Defaults are conservative:

- destructive actions are **denied by default**
- credentials must be explicitly listed
- sessions are bounded by `max_rounds` / `max_experiments`

## Research vs Deployment

The reasoning engine (`AdversarialEngine`, strategies, hypothesis/experiment/
evolution engines) contains **no authorization logic**. All authorization
lives in the policy layer. This separation is enforced by design: strategy
objects never see a policy object; the Experiment Engine alone consults the
enforcer.

## Handling of Credentials

- Policies reference credentials by name; OpenModels does not store secrets.
- `allowed_credentials` is a list of identifiers, not secret material.
- Secrets are provisioned out of band by the operator.

## Stop Conditions

A session stops when:

- the policy is exhausted (`max_rounds` / `max_experiments`)
- there are no more hypotheses to test
- `stop_on_finding` is set and a finding is produced
- an operator interrupts

The stop reason is recorded in the `ResearchReport`.

## Status Vocabulary

OpenModels reports status in these terms only: TESTED, VERIFIED, FAILED,
BLOCKED, UNKNOWN, UNTESTED. It never claims "secure".

## Responsibilities

- **Operator**: configure an honest, correct policy.
- **OpenModels**: enforce the policy everywhere, store no secrets, record
  provenance, and stop when required.
