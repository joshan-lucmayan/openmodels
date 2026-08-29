# CLI

**Module**: `openmodels/cli/`

## Responsibility

The primary user interface for OpenModels.

## Commands

```
openmodels
  init               Initialize the data directory and knowledge store.
  target
    list             List available target adapters.
    inspect <name>   Inspect a target adapter.
  research
    start <target>   Start a research session.
  experiment
    run <target> <hypothesis>  Run a single experiment.
  finding
    list             List findings.
    transition <id> <status>  Transition a finding.
  attack
    list             List attack strategies.
  knowledge
    search <query>   Search the knowledge store.
  status             Show status and summary.
  security-test <target>  Run the full adversarial cycle.
```

## Implementation

- Uses Click (see ADR 004).
- `Context` class holds references to store and registry.
- Commands are thin: they construct the necessary objects and delegate to
  the core engine.

## Key Design Decisions

- CLI is functional, not decorative. Every command does something useful.
- Error messages are actionable (e.g., "Unknown target adapter 'foo'.
  Available: mock").
- The `security-test` command demonstrates the full evolution cycle.