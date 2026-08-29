"""Observation engine — captures and persists observations about a target."""

from __future__ import annotations

from opensystem.models import Observation
from opensystem.target.interface import TargetAdapter
from opensystem.knowledge.store import KnowledgeStore


class ObservationEngine:
    """Observes a target and persists observations."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def observe(self, target: TargetAdapter, target_id: str | None = None) -> list[Observation]:
        observations = target.observe()
        if target_id:
            for obs in observations:
                obs.target_id = target_id
        self._store.save_observations(observations)
        return observations