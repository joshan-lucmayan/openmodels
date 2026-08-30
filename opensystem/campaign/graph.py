"""Attack graph construction (v0.2).

The attack graph represents alternative paths from an actor to a protected
resource through interfaces and authorization boundaries:

    Actor → Interface → Operation → Authorization boundary → Protected resource

Alternative paths are represented separately — the same resource may be
reachable via multiple interfaces, and enforcement may differ per interface.
"""

from __future__ import annotations

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Actor,
    AttackPath,
    EntitlementDecision,
    ProtectedResource,
    TestOutcome,
)
from opensystem.target.interface import Capability, adapter_capability


class AttackGraph:
    """A structured attack graph for a target.

    Nodes: actors, interfaces, resources.
    Edges: actor→interface (reachable), interface→resource (exposes),
           actor→resource (entitlement decision).
    """

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def build(
        self,
        target_id: str,
        actors: list[Actor],
        resources: list[ProtectedResource],
        target_adapter: object,
        tested_paths: list[AttackPath] | None = None,
    ) -> dict:
        """Build the attack graph as a structured dict.

        Returns:
            {
              "target_id": ...,
              "actors": [...],
              "resources": [...],
              "interfaces": [...],
              "paths": [ {actor, interface, resource, decision, outcome} ... ],
              "alternative_paths": { "<resource>": [<interface>...] }
            }
        """
        surface = self._store.get_attack_surface(target_id)
        surface_interfaces = surface.interfaces if surface else []

        decision_fn = adapter_capability(
            target_adapter, Capability.ENTITLEMENT, "entitlement_decision"
        )
        path_outcomes: dict[tuple, TestOutcome] = {}
        if tested_paths:
            for p in tested_paths:
                path_outcomes[(p.actor_id, p.interface, p.resource_id)] = p.outcome

        paths: list[dict] = []
        alternative: dict[str, list[str]] = {}
        for resource in resources:
            interfaces = resource.interfaces or [
                i["name"] for i in surface_interfaces if i.get("name")
            ]
            alternative[resource.name] = []
            for actor in actors:
                decision = EntitlementDecision.UNKNOWN
                if decision_fn is not None:
                    decision = decision_fn(actor.id, resource.id)
                for interface in interfaces:
                    key = (actor.id, interface, resource.id)
                    outcome = path_outcomes.get(key, TestOutcome.INCONCLUSIVE)
                    if decision != EntitlementDecision.ALLOW:
                        alternative[resource.name].append(interface)
                    paths.append(
                        {
                            "actor": actor.name,
                            "interface": interface,
                            "resource": resource.name,
                            "decision": decision.value,
                            "outcome": outcome.value,
                        }
                    )

        # De-duplicate alternative interfaces per resource.
        alternative = {
            resource: sorted(set(ifaces))
            for resource, ifaces in alternative.items()
        }

        return {
            "target_id": target_id,
            "actors": [a.name for a in actors],
            "resources": [r.name for r in resources],
            "interfaces": [i.get("name") for i in surface_interfaces if i.get("name")],
            "paths": paths,
            "alternative_paths": alternative,
        }
