"""Evidence collector — gathers and persists evidence from experiments."""

from __future__ import annotations

from openmodels.models import Evidence
from openmodels.target.interface import TargetAdapter
from openmodels.knowledge.store import KnowledgeStore


class EvidenceCollector:
    """Collects evidence from a target after a test."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def collect(self, target: TargetAdapter) -> list[Evidence]:
        evidence = target.collect_evidence()
        self._store.save_evidence_list(evidence)
        return evidence