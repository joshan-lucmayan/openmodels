"""Objective formulation and invariant testing (v0.2).

Given a discovered attack surface, OpenModels formulates structured objectives
for every (actor, protected resource) pair where the actor is NOT entitled to
the resource. Each objective is tied to a security invariant that the target
declares (or claims) MUST hold, and OpenModels tests whether the target
actually enforces it across interfaces and states.

The engine records: INVARIANT → TEST → RESULT.
"""

from __future__ import annotations

from openmodels.models import (
    Actor,
    AttackObjective,
    AttackPath,
    Campaign,
    EntitlementDecision,
    InvariantStatus,
    ObjectiveStatus,
    ProtectedResource,
    SecurityInvariant,
    Target,
    TestOutcome,
    TestSpec,
    utcnow,
)
from openmodels.knowledge.store import KnowledgeStore


class ObjectiveFormulator:
    """Formulates objectives and invariants from the discovered surface."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def formulate(
        self,
        campaign: Campaign,
        target: Target,
        target_adapter: object,
        actors: list[Actor],
        resources: list[ProtectedResource],
    ) -> list[AttackObjective]:
        """Formulate objectives for actors lacking entitlement to resources.

        Only pairs where the actor is DENIED (or unknown) produce an objective
        — those are the security boundaries worth testing.
        """
        objectives: list[AttackObjective] = []
        decision_fn = getattr(target_adapter, "entitlement_decision", None)

        for actor in actors:
            for resource in resources:
                decision = EntitlementDecision.UNKNOWN
                if decision_fn is not None:
                    try:
                        decision = decision_fn(actor.id, resource.id)
                    except Exception:
                        decision = EntitlementDecision.UNKNOWN

                if decision == EntitlementDecision.ALLOW:
                    continue

                invariant = SecurityInvariant(
                    actor_id=actor.id,
                    resource_id=resource.id,
                    statement=(
                        f"{actor.name} MUST NOT {self._verb(campaign)} "
                        f"{resource.name} without entitlement"
                    ),
                )
                self._store.save_invariant(invariant)

                objective = AttackObjective(
                    campaign_id=campaign.id,
                    actor_id=actor.id,
                    resource_id=resource.id,
                    security_invariant_id=invariant.id,
                )
                self._store.save_objective(objective)
                objectives.append(objective)

                campaign.invariant_ids.append(invariant.id)
                campaign.objective_ids.append(objective.id)

        self._store.save_campaign(campaign)
        return objectives

    @staticmethod
    def _verb(campaign: Campaign) -> str:
        return "access"


class InvariantTester:
    """Tests security invariants across attack paths.

    For each objective, every interface that exposes the resource is tested.
    A SUCCESS outcome means the boundary was crossed (invariant VIOLATED).
    A FAILURE outcome means the boundary held (invariant PASSED on that path).
    """

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def test_objective(
        self,
        objective: AttackObjective,
        target_adapter: object,
        target: Target,
        surface_interfaces: list[dict],
        actor: Actor,
        resource: ProtectedResource,
    ) -> tuple[list[AttackPath], InvariantStatus]:
        """Test an objective across every interface exposing the resource.

        Returns (paths, aggregate status). The aggregate is VIOLATED if any
        path crossed the boundary; otherwise PASSED.
        """
        paths: list[AttackPath] = []
        violated = False
        inconclusive = False

        interfaces = self._interfaces_for(resource, surface_interfaces)

        for interface in interfaces:
            test = TestSpec(
                name="boundary-test",
                description=objective.security_invariant_id,
                parameters={
                    "actor": actor.id,
                    "interface": interface,
                    "resource": resource.id,
                    "operation": "access",
                },
            )
            result = target_adapter.execute_test(test)

            # The adapter may return evidence; link it.
            outcome = result.outcome
            if outcome == TestOutcome.SUCCESS:
                violated = True
            elif outcome == TestOutcome.FAILURE:
                pass
            else:
                inconclusive = True

            path = AttackPath(
                actor_id=actor.id,
                interface=interface,
                resource_id=resource.id,
                operation="access",
                outcome=outcome,
            )
            self._store.save_attack_path(path)
            paths.append(path)

        if violated:
            status = InvariantStatus.VIOLATED
        elif inconclusive and not paths:
            status = InvariantStatus.INCONCLUSIVE
        elif inconclusive:
            status = InvariantStatus.INCONCLUSIVE
        else:
            status = InvariantStatus.PASSED

        return paths, status

    @staticmethod
    def _interfaces_for(resource: ProtectedResource, surface_interfaces: list[dict]) -> list[str]:
        """Return the interface names that expose the resource."""
        declared = resource.interfaces or []
        # Prefer declared interfaces; fall back to every discovered interface.
        if declared:
            return list(declared)
        return [i["name"] for i in surface_interfaces if i.get("name")]
