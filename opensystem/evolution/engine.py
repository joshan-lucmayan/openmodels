"""Evolution engine (Phase 9).

When a defender blocks an attack, OpenSystem must not simply repeat the same
attack. It must ask:

    "What assumption made the previous attack fail, and what other path could
     invalidate that assumption?"

Every evolution step is an explicit, auditable EvolutionEvent with a reason
and provenance. OpenSystem never modifies its own code; it modifies its
*knowledge* and generates new hypotheses. This keeps evolution auditable.
"""

from __future__ import annotations

from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Defense,
    EvolutionEvent,
    EvolutionTrigger,
    Experiment,
    Hypothesis,
    HypothesisStatus,
    Knowledge,
    KnowledgeKind,
    TestOutcome,
)


class EvolutionEngine:
    """Records evolution events and generates successor hypotheses."""

    def __init__(self, store: KnowledgeStore) -> None:
        self._store = store

    def on_experiment(self, experiment: Experiment) -> EvolutionEvent | None:
        """Record an evolution event after an experiment.

        Returns the event, or None if the experiment produced no evolution
        signal (e.g. an inconclusive result).
        """
        hypothesis = self._store.get_hypothesis(experiment.hypothesis_id)
        if hypothesis is None:
            return None

        if experiment.outcome == TestOutcome.SUCCESS:
            event = EvolutionEvent(
                trigger=EvolutionTrigger.ATTACK_SUCCESS,
                reason=(
                    f"Attack confirmed: {hypothesis.statement}. "
                    "Recording successful strategy for future reuse."
                ),
                from_hypothesis_id=hypothesis.id,
                provenance="evolution.on_experiment",
            )
            self._store.save_knowledge(
                Knowledge(
                    kind=KnowledgeKind.SUCCESSFUL_STRATEGY,
                    content=f"{hypothesis.origin} confirmed weakness on target.",
                    target_id=experiment.target_id,
                    provenance=f"experiment:{experiment.id}",
                )
            )
        elif experiment.outcome in (TestOutcome.FAILURE, TestOutcome.BLOCKED):
            event = EvolutionEvent(
                trigger=EvolutionTrigger.ATTACK_FAILURE,
                reason=(
                    f"Attack blocked: {hypothesis.statement}. "
                    "Path closed; search for alternate paths."
                ),
                from_hypothesis_id=hypothesis.id,
                provenance="evolution.on_experiment",
            )
            self._store.save_knowledge(
                Knowledge(
                    kind=KnowledgeKind.FAILED_STRATEGY,
                    content=f"{hypothesis.origin} was blocked by a defense.",
                    target_id=experiment.target_id,
                    provenance=f"experiment:{experiment.id}",
                )
            )
        else:
            return None

        self._store.save_evolution_event(event)
        return event

    def on_defense(self, defense: Defense, hypothesis: Hypothesis) -> EvolutionEvent:
        """Record that a defense was applied against a hypothesis."""
        event = EvolutionEvent(
            trigger=EvolutionTrigger.DEFENSE_APPLIED,
            reason=(
                f"Defense applied for finding {defense.finding_id}: "
                f"{defense.description}. Hypothesis {hypothesis.id} must be "
                "re-tested (regression)."
            ),
            from_hypothesis_id=hypothesis.id,
            provenance="evolution.on_defense",
        )
        self._store.save_evolution_event(event)
        self._store.save_knowledge(
            Knowledge(
                kind=KnowledgeKind.DEFENSE,
                content=defense.description,
                target_id=hypothesis.target_id,
                provenance=f"finding:{defense.finding_id}",
            )
        )
        return event

    def next_hypothesis(
        self,
        blocked_hypothesis: Hypothesis,
        alternate_weakness_keys: list[str],
    ) -> Hypothesis | None:
        """Generate the next hypothesis from a blocked one.

        A blocked attack tells us an assumption held (the defense blocked us).
        We search for another weakness whose assumption could be false —
        an alternate path that invalidates the defender's assumptions.
        """
        if not alternate_weakness_keys:
            return None

        next_key = alternate_weakness_keys[0]
        existing = self._store.list_hypotheses(blocked_hypothesis.target_id)
        already_tested = {
            h.origin for h in existing
            if h.status in (HypothesisStatus.ACCEPTED, HypothesisStatus.REJECTED)
        }
        for key in alternate_weakness_keys:
            origin = f"strategy:{key}"
            if origin not in already_tested:
                next_key = key
                break

        statement = (
            f"since {blocked_hypothesis.origin} is blocked, "
            f"can {next_key} be demonstrated as a weakness instead?"
        )
        next_hyp = Hypothesis(
            target_id=blocked_hypothesis.target_id,
            statement=statement,
            assumption=f"target assumes {next_key} is safe",
            status=HypothesisStatus.PROPOSED,
            parent_id=blocked_hypothesis.id,
            origin=f"strategy:{next_key}",
            confidence=0.5,
        )
        self._store.save_hypothesis(next_hyp)

        event = EvolutionEvent(
            trigger=EvolutionTrigger.ATTACK_FAILURE,
            reason=(
                f"Evolved from blocked {blocked_hypothesis.origin} to "
                f"alternate path {next_key}."
            ),
            from_hypothesis_id=blocked_hypothesis.id,
            to_hypothesis_id=next_hyp.id,
            provenance="evolution.next_hypothesis",
        )
        self._store.save_evolution_event(event)
        return next_hyp