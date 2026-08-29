# Changelog

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
