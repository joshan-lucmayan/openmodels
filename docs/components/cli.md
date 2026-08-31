# CLI

**Module**: `opensystem/cli/`

## Responsibility

The primary user interface for OpenSystem.

## Commands

```
opensystem
  init               Initialize the data directory and knowledge store.
  target
    list             List available target adapters.
    inspect <name>   Inspect a target adapter or saved target config.
    add <name>       Register a target configuration (--adapter http,
                     --url, --scope, --confirm-authorized).
  research
    start <target>   Start a research session against a live target.
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
```

## Implementation

- Uses Click (see ADR 004).
- `Context` class holds references to store and registry.
- Commands are thin: they construct the necessary objects and delegate to
  the core engine.
- Saved target configurations (from `target add`) carry the base URL and
  authorization scope; `research start <name>` / `experiment run <name>` /
  `target inspect <name>` resolve them.

## Key Design Decisions

- CLI is functional, not decorative. Every command does something useful.
- Error messages are actionable (e.g., "Unknown target adapter 'foo'.
  Available: http").
- Live targets require an explicit `--confirm-authorized` gate when
  registered, and every session prints the authorization scope.
