"""Evidence collector — gathers and persists evidence from experiments."""

from __future__ import annotations

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import Evidence
from opensystem.target.interface import TargetAdapter


class EvidenceCollector:
    """Collects evidence from a target after a test."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def collect(
        self, target: TargetAdapter, experiment_id: str | None = None
    ) -> list[Evidence]:
        """Collect and persist evidence, optionally bound to an experiment."""
        evidence = target.collect_evidence()
        for ev in evidence:
            ev.experiment_id = experiment_id
        self._store.save_evidence_list(evidence)
        return evidence