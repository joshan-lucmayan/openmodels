# OpenSystem — Attack Catalog

This document catalogs the attack classes OpenSystem can generate. The catalog
is a living document; the initial set (v0.1) is small by design and grows as
strategies are added.

## Catalog Format

Each entry records:

- Family and name
- Weakness key (used by adapters)
- Hypothesis template (the claim tested)
- The assumption challenged
- Status in the catalog (implemented / planned / research)

## v0.1 — Implemented Strategies

### Authentication

- **Name**: `auth-bypass`
- **Weakness key**: `auth-bypass`
- **Hypothesis**: "Can authentication be bypassed (e.g., via default
  credentials)?"
- **Assumption**: "The authentication layer rejects unauthenticated access."
- **Status**: implemented

### Authorization

- **Name**: `authz-ownership`
- **Weakness key**: `authz-ownership`
- **Hypothesis**: "Can object ownership checks be bypassed (horizontal
  escalation)?"
- **Assumption**: "The authorization layer enforces object ownership."
- **Status**: implemented

### Input Validation

- **Name**: `input-traversal`
- **Weakness key**: `input-traversal`
- **Hypothesis**: "Is path traversal possible in file retrieval?"
- **Assumption**: "Paths are canonicalized and constrained."
- **Status**: implemented

### Resource Usage

- **Name**: `resource-abuse`
- **Weakness key**: `resource-abuse`
- **Hypothesis**: "Can resources be abused (unbounded pagination)?"
- **Assumption**: "Resource consumption is bounded."
- **Status**: implemented

### AI / Agent Systems

- **Name**: `agent-tool-boundary`
- **Weakness key**: `agent-tool-boundary`
- **Hypothesis**: "Can an agent tool boundary be escaped?"
- **Assumption**: "The agent tool router restricts invocation to a granted
  tool set."
- **Status**: implemented

### Session Management

- **Name**: `session-fixation`
- **Weakness key**: `session-fixation`
- **Hypothesis**: "Can session ids be fixed across authentication?"
- **Assumption**: "The session layer re-issues session ids on authentication."
- **Status**: implemented

### Business Logic

- **Name**: `state-transition`
- **Weakness key**: `state-transition`
- **Hypothesis**: "Are illegal workflow state transitions allowed?"
- **Assumption**: "The workflow engine enforces the allowed transition set."
- **Status**: implemented

### Supply Chain

- **Name**: `dependency-supply-chain`
- **Weakness key**: `dependency-supply-chain`
- **Hypothesis**: "Can dependencies be substituted (unpinned transitive
  dependency)?"
- **Assumption**: "Dependencies are pinned and verified."
- **Status**: implemented

## Strategy Registry

Implemented strategies live in `opensystem/attack/planner.py`. `attack list`
prints them. New strategies are registered declaratively (an
`AttackStrategy` with a weakness key) or programmatically (a strategy factory).

## Expansion Plan

The following families are *planned* for future phases. Each requires a target
adapter that exposes the corresponding surfaces:

| Family | Planned classes |
|---|---|
| Application security | session management depth, API security, object ownership breadth, business logic depth, state transitions depth, input validation breadth |
| Infrastructure | service configuration, identity boundaries, cloud permissions, network segmentation, distributed-system behavior |
| AI systems | model authorization, agent permissions, tool boundaries, prompt injection, data boundaries, model routing, resource abuse, AI business logic |
| Software | dependency analysis, configuration analysis, source-code reasoning, unsafe assumptions, state-machine analysis |
| Systems research | new domains entirely through adapters rather than redesigning the core |

## Research Families

The strategy architecture intentionally leaves room for entirely new research
domains — physical-system simulations, scientific systems, aerospace —
attached via adapters without changing the reasoning core.
