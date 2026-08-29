# ADR 006 — Deterministic Mock Target First

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenModels is an adversarial engine, not a single-target tool. To build and
test the core reasoning loop correctly, it needs a controllable target before
connecting real systems.

## Decision

Ship the core engine against a **deterministic mock target** (`MockTarget`)
as the only v0.1 adapter, behind the same `TargetAdapter` interface real
adapters will implement.

## Rationale

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

## Consequences

- Real-world adapters (web/API, LLM, cloud, simulation) are added later via
  the registry without changing the core.
- The mock's weaknesses and `defend()` are not part of the adapter contract —
  they are conveniences for development and testing.

## Rejected

- **Building HTTP/real adapters now**: premature; would couple the core to a
  specific technology before the loop, storage, and evolution were proven.
- **An "AI attacker" facade**: rejected by design; see vision and the
  "do not build fake functionality" rule.
