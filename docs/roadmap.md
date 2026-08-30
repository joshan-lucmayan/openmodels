# OpenSystem — Roadmap

This document describes the planned evolution of OpenSystem across releases.
Every release should improve the adversarial engine.

## v0.1 — Foundation (current)

- [x] Project structure and configuration
- [x] Core entity models (hypothesis, observation, experiment, evidence,
      finding, defense, regression, knowledge, evolution event)
- [x] Generic target abstraction (`TargetAdapter`)
- [x] Deterministic mock target with 8 seeded weaknesses
- [x] Target adapter registry
- [x] Observation engine
- [x] Hypothesis engine (creation and evaluation)
- [x] Attack planner with 8 declarative strategies
- [x] Experiment engine
- [x] Evidence collector
- [x] Finding engine with lifecycle transitions
- [x] Evolution engine (auditable events, next-hypothesis generation)
- [x] SQLite knowledge store with analytical queries
- [x] Policy/authorization boundary
- [x] Core adversarial loop (`AdversarialEngine`)
- [x] CLI with all commands
- [x] 60 tests
- [x] Documentation (vision, architecture, threat model, attack model,
      target model, evolution, methodology, security model, glossary,
      roadmap, ADRs, component docs)

## v0.2 — Adversarial Campaign Architecture

- [x] Protected resource model (`ProtectedResource`)
- [x] Actor and entitlement models (`Actor`, `Entitlement`)
- [x] Security invariants (`SecurityInvariant`) tested across interfaces
- [x] Structured attack objectives (`AttackObjective`)
- [x] Campaign entity (complete, resumable assessment)
- [x] Attack-surface discovery (interfaces, resources, auth states, transitions)
- [x] Attack graph / paths (actor → interface → resource, alternative paths)
- [x] Campaign engine (CREATE → DISCOVER → FORMULATE → TEST → REPORT)
- [x] Adversarial improvement cycle (enforce → revalidate)
- [x] Target configuration via CLI (`target add`)
- [x] Mock target security-boundary model (enforcement per interface)
- [ ] State tracking across experiments (retain target state between rounds)
- [ ] Multi-step attack planning (hypothesis chains)
- [ ] Initial web/API target adapter (HTTP-based)
- [ ] More attack families (API security, session depth)
- [ ] Expanded knowledge query API

## v0.3 — Multi-Step Attack Planning

- [ ] Hypothesis chains (attack A → attack B → attack C)
- [ ] State transition analysis
- [ ] Business logic depth (multi-step workflows)
- [ ] Cross-component reasoning (e.g., auth + storage combined)

> Note: the v0.3 **release** shipped a different scope than originally
> planned here: impact verification, show-once proof sessions, and case
> studies (see `CHANGELOG.md`). Multi-step attack planning remains future
> work.

## v0.4 — Adaptive Attack Generation

- [ ] Strategy factories that generate hypotheses from observations
- [ ] LLM-backed hypothesis generation (optional, pluggable)
- [ ] Dynamic strategy selection based on target model
- [ ] Target fingerprinting (auto-select strategies)

## v0.5 — Cross-Component Reasoning

- [ ] Reasoning engine that models relationships between components
- [ ] Composite attacks (e.g., bypass auth → escalate to storage)
- [ ] Dependency graph analysis for targets
- [ ] Full API adapter (REST, GraphQL, gRPC)

## v0.6 — Historical Defense Analysis

- [ ] Defense-aware strategy selection (avoid previously-blocked paths)
- [ ] Change detection on targets (re-observe, re-model)
- [ ] Automated regression testing on target changes
- [ ] Knowledge graph visualization
- [ ] Web UI prototype

## v0.7 — Autonomous Hypothesis Generation

- [ ] Autonomous strategy selection (no hardcoded strategies)
- [ ] Self-guided research (choose next attack based on knowledge)
- [ ] Unsupervised observation → hypothesis pipeline
- [ ] AI/LLM agent adapter
- [ ] Cloud infrastructure adapter (via Terraform, AWS, etc.)

## v0.8+ — Platform

- [ ] Persistent web UI
- [ ] REST API
- [ ] Multi-target orchestration
- [ ] Team collaboration (findings, defenses, history)
- [ ] Enterprise deployment features
- [ ] New domains: simulations, scientific systems, aerospace

## Design Principles for the Roadmap

1. **Every release improves the adversarial engine.** Not just adding targets.
2. **The architecture must not be locked around today's capabilities.** New
   domains are added through adapters, not redesign.
3. **Reasoning sophistication grows independently of target count.** A v0.7
   engine with a mock target is more advanced than a v0.1 engine with 100
   real targets.
4. **Security research documentation is maintained alongside code.** The
   `docs/` directory is a first-class citizen.