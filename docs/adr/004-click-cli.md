# ADR 004 — CLI Framework: Click

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenSystem needs a functional, non-decorative CLI (init, target management,
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

Use **Click** for the CLI. Plain-text output only.

## Rationale

1. **Nested command groups**: `opensystem target list`, `opensystem research
   start`, etc. map naturally to Click groups.
2. **Already installed** in the environment.
3. **Mature and stable**: minimal churn for a long-lived project.

## Consequences

- CLI is thin: it constructs engines/stores and delegates to the core, keeping
  logic testable independently of the CLI.
- CLI behavior is covered by click's `CliRunner` tests.

## Rejected

- **Typer**: redundant with Click for this command structure; not installed.
- **argparse**: too verbose for nested groups and poorer help/UX.
- **Rich output styling**: deliberately not adopted (v0.3.1 decision). The
  CLI's plain, deterministic text output is a feature: it is greppable,
  script-friendly, and trivially testable with `CliRunner`. The `rich`
  dependency was removed rather than carried unused.

## Update (v0.3.1)

The original decision mentioned "Rich available for output styling", but no
code ever used it and the dependency sat unused. This amendment resolves the
mismatch in favor of plain text: the dependency is removed. If a future UI
phase (see `docs/components/future-ui-api.md`) needs rich rendering, that
decision can be revisited then.
