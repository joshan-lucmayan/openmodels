# Changelog

## v0.4.1 — Attack Journal (encrypted at rest) (2026-08-31)

### Added

- **Attack journal** (`opensystem/journal/`): every attack OpenSystem
  performs is recorded with its documented methodology (from the playbook),
  the runtime specifics (target URL, test parameters, observed result), the
  outcome, and the collected evidence.
- **Attack playbook**: a canonical, human-readable account of how each of
  the 11 HTTP attack types is performed and why it matters.
- **Encrypted-at-rest journal**: the journal content (methodology, observed
  results, targets, details) is encrypted with AES-256-GCM when locked. The
  owner sets a password; reading requires it. The password is never stored —
  only a PBKDF2 verifier. Without the password, journal content is
  unreadable even to someone with the database file.
- **Journal CLI commands**: `journal list`, `journal show`, `journal export`,
  `journal playbook`, `journal lock`, `journal unlock`, `journal status`.
- New dependency: `cryptography` (AES-256-GCM + PBKDF2).

### Changed

- Schema `SCHEMA_VERSION` bumped to 5 (adds `journal_entries` table).

## v0.4.0 — Real HTTP Targets, Mock Removed (2026-08-31)

### Removed

- **The mock target adapter is gone.** `MockTarget` and all mock-only
  subsystems that depended on its actor/resource/entitlement model were
  removed: the campaign engine, proof-key sessions, impact verification,
  case studies, defenses/regressions, and the `security-test` command. The
  product now ships with a single production adapter: the real HTTP(S)
  target.
- Mock weakness-model attack strategies (`auth-bypass`, `authz-ownership`,
  …) removed from the planner; only `http-*` strategies remain, scoped to
  the `http` adapter via `AttackStrategy.applies_to`.
- Removed `Capability` members with no remaining consumer (`SECURITY_MODEL`,
  `ENTITLEMENT`, `ENFORCEMENT`, `DEFENSE`, `IMPACT_PROBE`,
  `PROOF_SESSION`).
- Removed campaign/proof/impact/defense/regression models and their store
  tables (dropped by schema migration v3 → v4).

### Added

- **Real HTTP(S) target adapter** (`opensystem/target/http_site.py`):
  genuine network probes over stdlib `urllib` — no simulation. Tests:
  security headers, server disclosure, directory listing, sensitive paths,
  dangerous HTTP methods, CORS, cookie flags, open redirects, admin
  exposure, error disclosure, and TLS.
- **`Capability.TEST_PLANNING`**: adapters translate a `Hypothesis` into an
  adapter-specific `TestSpec`; the experiment engine delegates when declared
  and falls back otherwise.
- **Adapter-scoped strategies** (`applies_to`): a live web target is only
  tested with `http-*` probes; blocked-path evolution stays within the
  adapter's strategy set.
- **Live-target CLI flow**: `target add <name> --adapter http --url … --
  confirm-authorized --scope …` then `research start <name>` runs the full
  loop against the real site. Authorization scope is recorded and enforced
  via policy scoping.

### Changed

- `Policy` and research sessions scope to the resolved target's adapter,
  environment, and authorization scope.
- Schema `SCHEMA_VERSION` bumped to 4; legacy databases are migrated in
  place (research data preserved, mock-era tables dropped).
- Target ID includes host+port so distinct live servers never collide.

## v0.3.1 — Truth-in-Output, Structured Findings, Store Hardening (2026-08-30)

### Changed

- **`--stop-on-finding` is now enforced** by the research engine: after a
  finding's own bookkeeping completes, no further hypotheses are tested and
  the report records `FINDING_STOP`.
- **Campaign budgets are enforced**: `Policy.max_experiments` now bounds
  campaign boundary tests; an exhausted budget stops the campaign cleanly
  (status `STOPPED`, reason `POLICY_STOP`) with all tested state persisted.
- **CLI claims are evidence-derived**: the `security-test` summary reports
  actual regression outcomes (blocked / STILL EXPLOITABLE / inconclusive)
  instead of a hardcoded "defenses held" line; Defense records state when a
  defense was NOT applicable, and findings are only marked MITIGATION when a
  defense was actually applied.
- **Case studies are truthful**: impact verification status (`verified` /
  `not_verified` / `unknown`) is derived from the store's verification
  records; case studies require a CONFIRMED finding and never claim
  verification that did not happen.
- **Campaign reruns no longer duplicate findings**: findings are deduplicated
  on the boundary identity (target, actor, resource, interface); a CLOSED
  finding never suppresses a new violation.

### Added

- **Structured finding identities**: findings link to `objective_id`,
  `actor_id`, `resource_id`, and `interface`. The human-readable
  `affected_component` is display-only; impact verification and proof
  sessions resolve entities from structured IDs, never by parsing text.
- **Explicit target capabilities** (`Capability`, `adapter_capability()`):
  adapters declare optional capabilities; declared-but-missing methods raise
  `AdapterCapabilityError` instead of silently looking unsupported, and
  runtime errors propagate. Silent `except Exception` swallowing removed.
- **Schema migration system** (`MIGRATIONS`): ordered, additive, tested
  upgrades (v0.2 → v0.3 → v0.3.1) with a best-effort backfill of legacy
  finding identities; unresolvable ones stay empty rather than guessed.
- **Unified reporting**: campaign boundary tests appear in `build_report()`
  and `status` output as first-class boundary tests (not experiments).
- **Policy scoping**: `Policy.environment` / `Policy.scope` matching with
  fail-closed semantics; targets declare environment/scope.
- **Transactions**: `KnowledgeStore.transaction()` groups related saves
  (experiment+evidence, proof-session creation) into atomic units.
- **Constant-time** proof-key hash comparison (`hmac.compare_digest`).

### Hardening

- Append-only write semantics for audit/history tables (observations,
  evidence, knowledge, evolution events, defenses, regressions, attack
  paths, proof sessions): repeated saves can no longer overwrite history.
- `list_campaigns` single-query (N+1 removed); datetime/JSON helpers
  centralized.
- DB-level FK remnants removed to match ADR 005 (application-layer
  integrity); `ruff` lint gate is real (`|| true` removed), dev deps include
  `ruff` and `pytest-cov`; unused `rich` dependency removed (see ADR 004
  update); dead code removed (`AttackGraph.render`, `TargetDescription`,
  `ObjectiveFormulator._verb`); `EvidenceCollector` wired into the
  experiment flow.

## v0.3.0 — Show-Once Proof Sessions (2026-08-29)

### Added

- **Impact verification** (`ImpactVerifier`): independently re-probes a
  confirmed finding to confirm the protected resource was genuinely reached.
  Failed verifications are persisted for the audit trail.
- **Show-once proof sessions** (`ProofSessionService`): a short-lived,
  single-display proof credential bound to a confirmed finding, actor, and
  resource — for the authorized test target only.
- **CSPRNG key generation** (`secrets.token_hex(32)`, 256-bit), format
  `omk_<session_id>_<secret>`.
- **Hash-only storage**: only the SHA-256 hash of the key is persisted.
- **Full validation pipeline**: parse → lookup → hash-compare → revocation →
  expiry → target/finding/actor binding checks → authenticate.
- **Attack-proof binding enforcement**: `verify()` accepts optional expected
  target/finding/actor context and rejects mismatches
  (`target-mismatch`, `finding-mismatch`, `actor-mismatch`).
- **Authentication evidence**: each successful validation attaches an
  evidence record to the finding (never containing the raw key).
- **Masked reads**: inspect/list return the masked key (`omk_<id>...`) and a
  truncated hash; the raw key is never returned.
- **Immediate revocation** with `revoked_at` persisted and the historical
  record preserved; revocation takes precedence over expiry.
- **Policy gate**: new `PROOF_SESSION` operation, denied by default; the
  command must explicitly enable it and match the target.
- **Case studies**: reproducible written reports assembled from real store
  data (experiments, evidence, attack surface, hypotheses, defenses),
  exportable to JSON, and guaranteed to never contain raw proof keys.
- **CLI commands**: `impact verify`, `finding prove`, `proof-key inspect/
  list/revoke/verify` (stdin), `case-study create/show/export/list`.
- **Schema migration**: `CREATE TABLE IF NOT EXISTS` schema now runs on
  every open, so v0.2 databases transparently gain the v0.3 tables
  (restart/upgrade preserves proof-key validation).
- **33 new tests** (113 total) covering generation, show-once, storage,
  validation, expiry, revocation precedence, binding, evidence capture,
  CLI-level workflow, leakage prevention, and the complete workflow.

### Security

- Raw keys never touch the database, logs, stdout (after creation), stderr,
  exceptions, case studies, or exports (verified by an end-to-end audit that
  greps the SQLite file and WAL for the raw secret).
- Proof keys are scoped to the authorized test target and affected actor;
  they are not privileged credentials.
- `proof-key verify` deliberately accepts no key argument (shell history
  exposure): the key is read via stdin or getpass (no echo), never echoed,
  logged, or included in output or exceptions.

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
- **Target configuration** via CLI (`opensystem target add`) describing name,
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
