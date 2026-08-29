# OpenSystem — Glossary

Terms used throughout the project.

## A

- **Adapter** — see Target Adapter.
- **Adversarial loop** — the OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST →
  OBSERVE → ANALYZE → UPDATE → EVOLVE cycle.
- **Assumption** — a claim a target relies upon, which OpenSystem tries to
  demonstrate is false.
- **Attack class / family** — a category of attack (e.g., authentication,
  authorization, AI/agent). Implemented as strategies.

## B

- **Blocked** — a test outcome meaning the operation was prevented (by a
  defense or by policy).

## D

- **Defense** — a mitigation applied by the defender; a first-class persisted
  entity.
- **Defender** — the operator who fixes weaknesses OpenSystem finds.

## E

- **Evidence** — structured data supporting an experiment or finding.
- **Evolution** — the mechanism by which OpenSystem generates new hypotheses
  after defenses are introduced; auditable via EvolutionEvents.
- **Evolution event** — an auditable record of an evolution step with trigger,
  reason, and provenance.
- **Experiment** — a single fully-recorded test of a hypothesis.

## F

- **Failed attack** — an attack that was blocked; valuable information.
- **Finding** — a confirmed weakness with evidence and a lifecycle.

## H

- **Hypothesis** — a testable claim about a potential weakness; structured,
  with status and lineage.

## K

- **Knowledge store** — the persistent store of observations, hypotheses,
  experiments, findings, defenses, and knowledge records.
- **Knowledge record** — a persisted piece of learned knowledge with kind and
  provenance.

## M

- **Mock target** — the deterministic v0.1 target adapter used to exercise the
  engine.

## O

- **Observation** — something observed about a target, persisted for
  reasoning.
- **OpenSystem** — the evolving adversarial intelligence platform.

## P

- **Policy** — the authorization boundary declaring what a session may do.
- **Policy violation** — an operation disallowed by the active policy.

## R

- **Regression** — a re-test proving a previously-found weakness stays fixed.
- **Research report** — the evidence-based aggregate result of a session.

## S

- **Strategy** — an attack family registered with the planner; generates
  hypotheses. May be declarative or a factory.
- **Successful attack** — a test that confirms a weakness; produces a finding.

## T

- **Target** — the system under adversarial evaluation.
- **Target adapter** — the common interface between OpenSystem and a target
  (`discover`, `observe`, `describe`, `execute_test`, `collect_evidence`,
  `reset`).
- **Test spec** — a concrete executable test planned from a hypothesis.
- **Test result** — the outcome (success, failure, blocked, inconclusive,
  error) of a test.

## V

- **Verification status** — the stage of a finding's lifecycle (DISCOVERED →
  CLOSED).
