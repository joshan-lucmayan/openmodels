# ADR 006 — Deterministic Mock Target First

- **Status**: Superseded by ADR 009
- **Date**: 2026-08-29 (superseded 2026-08-31)

## Context

OpenSystem is an adversarial engine, not a single-target tool. To build and
test the core reasoning loop correctly, it needs a controllable target before
connecting real systems.

## Decision

Ship the core engine against a **deterministic mock target** (`MockTarget`)
as the only v0.1 adapter, behind the same `TargetAdapter` interface real
adapters will implement.

## Superseded By

**ADR 009 — Real HTTP(S) Target Adapter** (2026-08-31). The mock target was
removed in v0.4. OpenSystem now ships with a single real HTTP target adapter
as the production adapter. The core engine, knowledge store, evolution, and
policy boundary were proven against the mock and now run against live HTTP
targets.

## Rationale (historical)

1. **Correctness before breadth**: the adversarial loop, knowledge store,
   evolution, and policy boundary can be fully exercised and tested without
   the nondeterminism and risk of real systems.
2. **The interface is real**: `MockTarget` implements the actual contract
   (`discover/observe/describe/execute_test/collect_evidence/reset`) — the
   engine is not built around the mock; the mock conforms to the engine.
3. **Evolution demonstration**: `defend()` simulates the defender, enabling
   the full attack → defend → regress → evolve cycle to be demonstrated and
   tested.
4. **No fake autonomy**: the engine honestly reports what it did; it does not
   pretend to be an autonomous attacker.

## Consequences (historical)

- Real-world adapters (web/API, LLM, cloud, simulation) are added later via
  the registry without changing the core.
- The mock's weaknesses and `defend()` are not part of the adapter contract —
  they are conveniences for development and testing.
