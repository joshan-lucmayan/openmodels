"""Attack surface discovery (v0.2).

Before attacking, OpenModels constructs a model of the target's reachable
interfaces and state transitions:

    Target → Interfaces → Resources → Authentication states
           → Authorization states → State transitions → Attack surface graph

This phase does NOT attack. It understands what exists first.
"""

from __future__ import annotations

from openmodels.models import AttackSurface, Target, utcnow
from openmodels.knowledge.store import KnowledgeStore


class AttackSurfaceDiscovery:
    """Discovers and persists the reachable surface of a target."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def discover(
        self,
        target_adapter: object,
        target: Target,
    ) -> AttackSurface:
        """Build the attack surface model for a target adapter.

        The adapter may expose optional descriptive methods
        (describe_interfaces / describe_resources / describe_actors).
        If absent, the Target model's declared interfaces and assets are used.
        """
        interfaces = self._describe(target_adapter, "describe_interfaces")
        resources = self._describe(target_adapter, "describe_resources")
        actors = self._describe(target_adapter, "describe_actors")

        if not interfaces:
            interfaces = [{"name": i, "enforced": True} for i in target.interfaces]

        auth_states = self._auth_states(target_adapter)
        transitions = self._transitions(target_adapter)

        surface = AttackSurface(
            target_id=target.id,
            interfaces=interfaces,
            resources=resources,
            auth_states=auth_states,
            transitions=transitions,
        )
        self._store.save_attack_surface(surface)
        return surface

    @staticmethod
    def _describe(target_adapter: object, method: str) -> list[dict]:
        fn = getattr(target_adapter, method, None)
        if fn is None:
            return []
        try:
            return list(fn())
        except Exception:
            return []

    @staticmethod
    def _auth_states(target_adapter: object) -> list[dict]:
        fn = getattr(target_adapter, "describe_auth_states", None)
        if fn is None:
            return []
        try:
            return list(fn())
        except Exception:
            return []

    @staticmethod
    def _transitions(target_adapter: object) -> list[dict]:
        fn = getattr(target_adapter, "describe_transitions", None)
        if fn is None:
            return []
        try:
            return list(fn())
        except Exception:
            return []
