# OpenSystem — Roadmap

This document describes the planned evolution of OpenSystem across releases.
Every release should improve the adversarial engine.

## v0.1 — Foundation (shipped, superseded)

- [x] Project structure and configuration
- [x] Core entity models (hypothesis, observation, experiment, evidence,
      finding, knowledge, evolution event)
- [x] Generic target abstraction (`TargetAdapter`)
- [x] Deterministic mock target with seeded weaknesses (removed in v0.4)
- [x] Target adapter registry
- [x] Observation engine
- [x] Hypothesis engine (creation and evaluation)
- [x] Attack planner with declarative strategies
- [x] Experiment engine
- [x] Evidence collector
- [x] Finding engine with lifecycle transitions
- [x] Evolution engine (auditable events, next-hypothesis generation)
- [x] SQLite knowledge store with analytical queries
- [x] Policy/authorization boundary
- [x] Core adversarial loop (`AdversarialEngine`)
- [x] CLI with all commands
- [x] Documentation (vision, architecture, threat model, attack model,
      target model, evolution, methodology, security model, glossary,
      roadmap, ADRs, component docs)

## v0.2 — Adversarial Campaign Architecture (removed in v0.4)

The campaign/boundary model (protected resources, actors, entitlements,
invariants, objectives, attack graphs) was built on the mock target's
actor/resource/entitlement model. With the mock removed in v0.4, these
subsystems and their store tables were deleted. See `CHANGELOG.md`.

## v0.3 — Impact Verification & Proof Sessions (removed in v0.4)

The v0.3 release shipped impact verification, show-once proof sessions, and
case studies. All were coupled to the mock's boundary model; they were
removed in v0.4 when the mock was deleted.

## v0.4 — Real HTTP Targets (current)

- [x] Real HTTP(S) target adapter (`http`) using stdlib `urllib`
- [x] 11 real web probes (headers, disclosure, listing, sensitive paths,
      methods, CORS, cookies, redirects, admin, errors, TLS)
- [x] Adapter-scoped attack strategies (`applies_to`)
- [x] `TEST_PLANNING` capability (hypothesis → adapter-specific TestSpec)
- [x] Live-target CLI flow with `--confirm-authorized` + scope recording
- [x] Schema v4 migration (mock-era tables dropped)
- [ ] Hypothesis chains (attack A → attack B → attack C)
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
- [ ] Automated re-validation on target changes
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