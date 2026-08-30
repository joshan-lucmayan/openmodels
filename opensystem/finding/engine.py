"""Finding engine — manages the finding lifecycle (Phase 8).

A finding progresses through:
  DISCOVERED → CONFIRMED → DOCUMENTED → MITIGATION → VERIFICATION → CLOSED

A finding NEVER disappears from the historical record after it is closed.
"""

from __future__ import annotations

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Experiment,
    Finding,
    FindingStatus,
    Severity,
    TestOutcome,
)

# Valid transitions for the finding lifecycle.
_VALID_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.DISCOVERED: {FindingStatus.CONFIRMED, FindingStatus.CLOSED},
    FindingStatus.CONFIRMED: {FindingStatus.DOCUMENTED, FindingStatus.CLOSED},
    FindingStatus.DOCUMENTED: {FindingStatus.MITIGATION, FindingStatus.CLOSED},
    FindingStatus.MITIGATION: {FindingStatus.VERIFICATION, FindingStatus.CLOSED},
    FindingStatus.VERIFICATION: {FindingStatus.CLOSED, FindingStatus.MITIGATION},
    FindingStatus.CLOSED: set(),
}


class FindingEngine:
    """Creates, transitions, and persists findings."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def create_from_experiment(
        self,
        experiment: Experiment,
        target_id: str,
    ) -> Finding | None:
        """Create a finding from a successful experiment.

        Returns None if the experiment did not confirm a weakness.
        """
        if experiment.outcome != TestOutcome.SUCCESS:
            return None

        hypothesis = self._store.get_hypothesis(experiment.hypothesis_id)
        if hypothesis is None:
            return None

        finding = Finding(
            target_id=target_id,
            hypothesis_id=hypothesis.id,
            severity=Severity.HIGH,
            affected_component=experiment.test.parameters.get("weakness", "unknown"),
            attack_hypothesis=hypothesis.statement,
            observed_behavior=experiment.observed_result,
            evidence_ids=experiment.evidence_ids,
            impact="Weakness confirmed by adversarial test.",
            reproduction=(
                f"Run experiment {experiment.id} with hypothesis "
                f"{hypothesis.id}: {experiment.test.name}"
            ),
            recommended_mitigation="Investigate the affected component and apply appropriate controls.",
            verification_status=FindingStatus.DISCOVERED,
        )
        self._store.save_finding(finding)
        return finding

    def transition(self, finding_id: str, target: FindingStatus) -> Finding | None:
        """Transition a finding to a new status.

        Raises ValueError for invalid transitions.
        """
        finding = None
        for f in self._store.list_findings():
            if f.id == finding_id:
                finding = f
                break
        if finding is None:
            return None

        allowed = _VALID_TRANSITIONS.get(finding.verification_status, set())
        if target not in allowed:
            raise ValueError(
                f"Cannot transition finding {finding_id} from "
                f"{finding.verification_status.value} to {target.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self._store.update_finding_status(finding_id, target)
        return finding

    def list_findings(self, target_id: str | None = None) -> list[Finding]:
        return self._store.list_findings(target_id)