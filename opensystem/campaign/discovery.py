"""Attack surface discovery (v0.2).

Before attacking, OpenSystem constructs a model of the target's reachable
interfaces and state transitions:

    Target → Interfaces → Resources → Authentication states
           → Authorization states → State transitions → Attack surface graph

This phase does NOT attack. It understands what exists first.
"""

from __future__ import annotations

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import AttackSurface, Target
from opensystem.target.interface import Capability, TargetAdapter, adapter_capability


class AttackSurfaceDiscovery:
    """Discovers and persists the reachable surface of a target."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def discover(
        self,
        target_adapter: TargetAdapter,
        target: Target,
    ) -> AttackSurface:
        """Build the attack surface model for a target adapter.

        Adapters declaring the DISCOVERY capability describe their surface via
        describe_* methods. Interfaces fall back to the Target model's
        declared interfaces when the adapter does not describe them.
        """
        interfaces = self._describe(target_adapter, "describe_interfaces")
        resources = self._describe(target_adapter, "describe_resources")

        if not interfaces:
            interfaces = [{"name": i, "enforced": True} for i in target.interfaces]

        surface = AttackSurface(
            target_id=target.id,
            interfaces=interfaces,
            resources=resources,
            auth_states=self._describe(target_adapter, "describe_auth_states"),
            transitions=self._describe(target_adapter, "describe_transitions"),
        )
        self._store.save_attack_surface(surface)
        return surface

    @staticmethod
    def _describe(target_adapter: TargetAdapter, method: str) -> list[dict]:
        fn = adapter_capability(target_adapter, Capability.DISCOVERY, method)
        if fn is None:
            return []
        return list(fn())
