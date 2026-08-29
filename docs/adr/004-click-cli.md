# ADR 004 — CLI Framework: Click

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenModels needs a functional, non-decorative CLI (init, target management,
research sessions, experiment execution, finding management, attack listing,
knowledge search, status, security-test cycle).

## Options Considered

| Option | Assessment |
|---|---|
| **Click** | Mature, group-based command nesting (matches the command tree), already installed. |
| Typer | Built on Click, but not installed and adds little for this shape of CLI. |
| argparse (stdlib) | Verbose for nested command groups. |
| Rich-based custom | Good for output styling but not a command framework. |

## Decision

Use **Click** for the CLI, with **Rich** available for output styling.

## Rationale

1. **Nested command groups**: `openmodels target list`, `openmodels research
   start`, etc. map naturally to Click groups.
2. **Already installed** in the environment.
3. **Mature and stable**: minimal churn for a long-lived project.
4. Rich (a dev/optional dependency) handles formatting for better output.

## Consequences

- CLI is thin: it constructs engines/stores and delegates to the core, keeping
  logic testable independently of the CLI.
- CLI behavior is covered by click's `CliRunner` tests.

## Rejected

- **Typer**: redundant with Click for this command structure; not installed.
- **argparse**: too verbose for nested groups and poorer help/UX.
