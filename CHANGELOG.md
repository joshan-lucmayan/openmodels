# Changelog

## v0.2.0 — Adversarial Campaign Engine (2026-08-29)

### Added

- **Protected resource model** (`ProtectedResource`): what an unauthorized
  actor must NOT access (AI models, paid APIs, premium features, data,
  compute, etc.).
- **Actor and entitlement models** (`Actor`, `Entitlement`): who is trying to
  access, and their declared rights. Privileges are never assumed from
  client-supplied values.
- **Security invariants** (`SecurityInvariant`): boundaries that MUST hold,
  tested across interfaces and states. Records INVARIANT → TEST → RESULT.
- **Structured attack objectives** (`AttackObjective`): actor, resource,
  invariant, and success condition — not plain text.
- **Campaign entity** (`Campaign`, `CampaignReport`): a complete, resumable
  adversarial assessment.
- **Attack-surface discovery**: builds the model of reachable interfaces,
  resources, auth states, and transitions before attacking.
- **Attack graph / paths** (`AttackGraph`, `AttackPath`): actor → interface →
  resource paths with alternative paths represented separately.
- **Campaign engine**: CREATE → DISCOVER → FORMULATE → TEST ALL PATHS → REPORT,
  plus an adversarial improvement cycle (`enforce_and_revalidate`).
- **Target configuration** via CLI (`openmodels target add`) describing name,
  type, organization, environment, interfaces, credentials, policy, time
  window, and emergency stop.
- **Mock target security-boundary model**: 4 actors, 3 protected resources,
  entitlement + per-interface enforcement matrices. The premium-model boundary
  is enforced on `chat_api`/`job_api` but NOT on `stream_api` (the discovered
  vulnerability).
- **New CLI commands**: `campaign create/run/enforce/graph/list/show`,
  `target add`.
- **15 new tests** (75 total) covering the boundary model and campaign engine.

## v0.1.0 — Foundation (2026-08-29)

### Added

- Core adversarial loop (`AdversarialEngine`): OBSERVE → MODEL → HYPOTHESIZE
  → PLAN → TEST → OBSERVE → ANALYZE → UPDATE → EVOLVE.
- Generic target abstraction (`TargetAdapter`) with a deterministic mock
  target exposing 8 seeded weaknesses across 8 attack families.
- Target adapter registry with `register_target()`.
- Structured, persistable entity models: Target, Observation, Hypothesis,
  Experiment, Evidence, Finding, Defense, Regression, Knowledge,
  EvolutionEvent, ResearchReport.
- Observation engine, hypothesis engine (creation + evaluation), attack
  planner (declarative strategies + factory extension point), experiment
  engine, evidence collector, finding engine (lifecycle with validation),
  evolution engine (auditable events + next-hypothesis generation).
- SQLite knowledge store with schema versioning, WAL, and analytical queries
  (`previous_attempts`, `what_failed`, `open_findings`, `search_knowledge`,
  `build_report`).
- Policy/authorization boundary (`Policy`, `PolicyEnforcer`) with
  conservative defaults.
- CLI (`init`, `target`, `research`, `experiment`, `finding`, `attack`,
  `knowledge`, `status`, `security-test`).
- Full documentation set: vision, architecture, threat model, attack model,
  target model, evolution, research methodology, security model, attack
  catalog, findings, defenses, roadmap, glossary, ADRs, component docs.
- 60 tests covering all foundational components and the full adversarial
  cycle.

### Architecture Decisions

- Python 3.14 + pydantic + click + SQLite (see `docs/adr/`).
- Deterministic mock target first (ADR 006).
