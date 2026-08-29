"""Attack graph construction (v0.2).

The attack graph represents alternative paths from an actor to a protected
resource through interfaces and authorization boundaries:

    Actor → Interface → Operation → Authorization boundary → Protected resource

Alternative paths are represented separately — the same resource may be
reachable via multiple interfaces, and enforcement may differ per interface.
"""

from __future__ import annotations

from openmodels.models import (
    Actor,
    AttackSurface,
    AttackPath,
    EntitlementDecision,
    ProtectedResource,
    TestOutcome,
)
from openmodels.knowledge.store import KnowledgeStore


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

        decision_fn = getattr(target_adapter, "entitlement_decision", None)
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
                    try:
                        decision = decision_fn(actor.id, resource.id)
                    except Exception:
                        decision = EntitlementDecision.UNKNOWN
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
        for res in alternative:
            alternative[res] = sorted(set(alternative[res]))

        return {
            "target_id": target_id,
            "actors": [a.name for a in actors],
            "resources": [r.name for r in resources],
            "interfaces": [i.get("name") for i in surface_interfaces if i.get("name")],
            "paths": paths,
            "alternative_paths": alternative,
        }

    def render(self, graph: dict) -> str:
        """Render a human-readable ASCII attack graph."""
        lines = []
        for resource in graph["resources"]:
            lines.append(f"                {resource}")
            lines.append("                     ▲")
            lines.append("                     │")
            lines.append("          ┌──────────┼──────────┐")
            alt = graph["alternative_paths"].get(resource, [])
            if alt:
                middle = len(alt) // 2
                for i, iface in enumerate(alt):
                    if i == middle:
                        lines.append(f"       {iface:12s}    {iface}")
                    else:
                        lines.append(f"       {iface:12s}   {iface}")
            lines.append("          └──────────┼──────────┘")
            lines.append("                     │")
            lines.append("               Authorization")
            lines.append("")
        return "\n".join(lines)
