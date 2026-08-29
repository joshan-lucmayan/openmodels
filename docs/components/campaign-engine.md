# Campaign Engine

**Module**: `openmodels/campaign/`

## Responsibility

Orchestrates the v0.2 adversarial campaign: a complete adversarial assessment
centered on the question "can an actor without entitlement access a protected
resource?"

## Sub-components

- `engine.py` — `CampaignEngine` orchestrator + `enforce_and_revalidate` cycle.
- `discovery.py` — `AttackSurfaceDiscovery` (build the surface before attacking).
- `objectives.py` — `ObjectiveFormulator` + `InvariantTester`.
- `graph.py` — `AttackGraph` builder and renderer.

## Flow

```
CREATE → DISCOVER → FORMULATE → TEST ALL PATHS → REPORT
```

1. `create_campaign(name, target_adapter, target, actors, resources)` —
   persist target, actors, resources; create the campaign.
2. `discover(campaign, target_adapter, target)` — build the attack surface and
   formulate objectives.
3. `run(campaign, target_adapter, target)` — test every objective across every
   path; record invariant results, findings; return `CampaignReport`.
4. `enforce_and_revalidate(campaign, target_adapter, target)` — run, enforce
   violated boundaries, re-run (regression proof).

## Objective Formulation

Objectives are created only for (actor, resource) pairs where the actor is
DENIED (or unknown) entitlement — entitled access is legitimate, not a finding.
Each objective carries a `SecurityInvariant` whose statement is:
"`<actor> MUST NOT access <resource> without entitlement`".

## Invariant Testing

For each objective, every interface exposing the resource is tested:

- SUCCESS → invariant VIOLATED (boundary crossed) → finding.
- FAILURE → invariant PASSED on that path.
- Aggregate: VIOLATED if any path crossed; else PASSED.

## Attack Graph

`AttackGraph.build()` returns the full actor→interface→resource path set with
entitlement decisions and outcomes, plus alternative paths per resource.

## Key Design Decisions

- Campaigns are persisted and resumable.
- The reasoning operates on actors/resources/invariants — never URLs.
- The improvement cycle (enforce → revalidate) demonstrates evolution at the
  security-boundary level.

## See Also

- [`docs/campaign-model.md`](../campaign-model.md)
- [`docs/adr/007-campaign-architecture.md`](../adr/007-campaign-architecture.md)
