# Policy Layer

**Module**: `opensystem/policy/`

## Responsibility

The authorization boundary between the adversarial reasoning engine and the
deployment environment. The reasoning engine contains no authorization logic.

## Sub-components

- `models.py` — `Policy` model, `Operation` enum, `StopReason` enum.
- `engine.py` — `PolicyEnforcer` for runtime checks.

## Policy Model

The policy declares: target name, environment, allowed operations, max rounds,
max experiments, allowed credentials, destructive action permission, and stop
conditions.

## Enforcement

`PolicyEnforcer.check(operation, target)` is the single gate. It raises
`PolicyViolation` for disallowed operations. Every test execution passes
through this gate.

## Key Design Decisions

- Defaults are conservative: destructive actions denied, credentials must be
  explicitly listed, bounds are enforced.
- The policy layer is separate from the attack engine — strategies never see
  a policy object.
- See also [`security-model.md`](../security-model.md).