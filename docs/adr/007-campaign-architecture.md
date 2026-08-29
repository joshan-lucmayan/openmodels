# ADR 007 — Campaign Architecture for v0.2

- **Status**: Accepted
- **Date**: 2026-08-29

## Context

OpenModels v0.1 reasoned in terms of *weaknesses*: hypotheses about seeded
flaws in a target, tested through a weakness-keyed protocol. The mission for
v0.2 is different: OpenModels must discover whether a *security boundary* can
be crossed — specifically, whether an actor without entitlement can cause a
protected resource to be accessed, consumed, modified, or disclosed.

The initial protected resource is paid/premium AI inference, but the
architecture must NOT be hardcoded around AI or URLs.

## Decision

Introduce a campaign architecture built on new first-class concepts:

- **ProtectedResource** — the object of adversarial campaigns.
- **Actor** — who is trying to access; with declared entitlements.
- **Entitlement** — what an actor may do; never assumed from client values.
- **SecurityInvariant** — a boundary that MUST hold; tested across interfaces.
- **AttackObjective** — a structured objective (actor, resource, invariant).
- **AttackSurface** — the discovered reachable surface of a target.
- **AttackGraph** / **AttackPath** — the graph of alternative paths.
- **Campaign** — a complete, resumable adversarial assessment.

A new `CampaignEngine` orchestrates: CREATE → DISCOVER → FORMULATE → TEST ALL
PATHS → REPORT, and supports an adversarial improvement cycle (enforce →
revalidate).

## Rationale

1. **Generality**: reasoning about actors, entitlements, and protected
   resources is technology-agnostic. The same engine handles paid AI, paid
   APIs, cloud resources, privileged functionality, etc. — no URLs required.
2. **The real question**: "can an actor cross a security boundary?" is more
   fundamental than "is this weakness present?". It matches how attackers
   actually operate.
3. **Boundary enforcement is per-interface**: a boundary may hold on one
   interface and fail on another. The per-path invariant model captures this
   (the mock's stream_api is exactly this case).
4. **Resumable campaigns**: campaigns are persisted entities, so an
   assessment can be stopped and resumed.
5. **Composability with v0.1**: the weakness-based loop and entities remain;
   the campaign layer composes on top and can eventually subsume it.

## Consequences

- New entity tables in the knowledge store (protected_resources, actors,
  entitlements, security_invariants, attack_objectives, campaigns,
  attack_surfaces, attack_paths).
- New `TargetConfig` for deployment-time target description (name, type,
  organization, environment, interfaces, credentials, policy, time window,
  emergency stop).
- The mock target gained a security-boundary model (actors, resources,
  entitlement + enforcement matrices) alongside its weakness model.
- Objective formulation is bounded to actor/resource pairs where the actor
  lacks entitlement — entitled access is legitimate, not a finding.

## Rejected

- **Hardcoding a "URL → bypass → paid model" workflow**: explicitly rejected.
  It would couple the engine to one scenario and one transport.
- **Replacing the v0.1 loop**: the weakness model remains useful for
  technology-specific checks; campaigns operate at the boundary level above
  it.
