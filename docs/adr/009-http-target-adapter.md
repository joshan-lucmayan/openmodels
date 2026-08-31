# ADR 009 — Real HTTP(S) Target Adapter

- **Status**: Accepted
- **Date**: 2026-08-31

## Context

The core engine was proven against a deterministic mock target (ADR 006).
To run OpenSystem against real systems — starting with web applications the
operator is authorized to test — a live network adapter is required.

Two architectural gaps had to close before a real adapter could plug in:

1. The experiment engine hardcoded mock-specific test parameters
   (`parameters={"weakness": ...}`), so a web adapter could not receive its
   own protocol-specific probes.
2. The default planner emitted hypotheses from every registered strategy
   regardless of target type, so mock weakness-model strategies would leak
   into real targets (and vice versa).

## Decision

1. **Add the `http` target adapter** (`opensystem/target/http_site.py`) that
   performs real HTTP(S) requests (stdlib `urllib`) against a base URL. It
   declares `DISCOVERY` (real path probing) and a new `TEST_PLANNING`
   capability. There is no simulation: every probe is a real request, every
   outcome derives from the actual response.

2. **Add `Capability.TEST_PLANNING`** to the capability protocol. Adapters
   declaring it translate a `Hypothesis` into a concrete adapter-specific
   `TestSpec` via `plan_test()`. The experiment engine uses it when declared
   and falls back to the v0.1 mock weakness model otherwise (mock behavior is
   unchanged).

3. **Scope strategies by adapter** — `AttackStrategy.applies_to`. The mock
   weakness-model strategies apply only to `mock`; web strategies apply only
   to `http`. `generate_hypotheses` and the blocked-path evolution
   (`AdversarialEngine._evolve_from_blocked`) both filter by it.

4. **Authorization is explicit and operator-declared**: `target add` for the
   `http` adapter requires `--url` and `--confirm-authorized`, records the
   authorized scope and environment, and the adapter carries them into the
   `Target` model where the policy layer scopes sessions.

## Rationale

1. **Real, not fake**: the "no fake functionality" rule means the adapter must
   actually talk HTTP and must honestly report `SUCCESS`/`FAILURE`/
   `INCONCLUSIVE`/`ERROR` from real responses.
2. **Extension not alteration**: `TEST_PLANNING` follows the existing
   declare-then-resolve capability pattern; the core loop, store, and policy
   layers are unchanged for existing adapters.
3. **Isolation**: `applies_to` keeps mock and real hypothesis spaces clean, so
   research on a live target never wastes budget on mock-only weakness names.
4. **Authorization-first**: live targets are by definition risk-bearing; the
   tool records the operator's authorization statement and scopes by it.

## Consequences

- `opensystem target add <name> --adapter http --url <url> --confirm-authorized`
  registers a live target; `research start <name>` runs the full loop against
  it over the network.
- New web tests are added by implementing a probe in the adapter and (if
  needed) registering a strategy; the core engine does not change.
- Campaign/impact/proof flows reconstruct live targets from the stored
  `Target.rules` (base URL) so sessions are resumable across processes.

## Rejected

- **Adding `requests`/`httpx` as a dependency**: stdlib `urllib` is sufficient
  for the current probe set and keeps the dependency surface minimal.
- **Making the core engine adapter-aware beyond the capability protocol**:
  that would couple the loop to one technology; the capability pattern keeps
  it generic.
