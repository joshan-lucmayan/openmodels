# Target Abstraction

**Module**: `openmodels/target/interface.py`

## Responsibility

The `TargetAdapter` contract that every target must implement. This is the
seam that keeps the reasoning engine independent of any single technology.

## Contract

| Method | Returns | Purpose |
|---|---|---|
| `discover()` | `Target` | Build the target model. |
| `observe()` | `list[Observation]` | Return current observations. |
| `describe()` | `dict` | Human-readable structural description. |
| `execute_test(test)` | `TestResult` | Execute a test against the target. |
| `collect_evidence()` | `list[Evidence]` | Gather evidence from the last test. |
| `reset()` | `None` | Return to a known state. |

## Key Design Decisions

- Uses `ABC` + `@abstractmethod` for clarity and enforceability.
- `TargetDescription` is a `dict` subclass — keeps the adapter protocol
  dependency-light.
- Adapters conform to the engine, not the other way around.