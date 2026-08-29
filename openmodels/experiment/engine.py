"""Experiment engine — executes hypotheses against a target.

Every experiment is fully recorded and persisted. Failed experiments are
never discarded: a failed attack is valuable information about what the
defender has blocked.
"""

from __future__ import annotations

from openmodels import VERSION
from openmodels.models import (
    Evidence,
    Experiment,
    Hypothesis,
    Target,
    TestResult,
    TestSpec,
    utcnow,
)
from openmodels.target.interface import TargetAdapter
from openmodels.knowledge.store import KnowledgeStore
from openmodels.policy.engine import PolicyEnforcer
from openmodels.policy.models import Operation


class ExperimentEngine:
    """Executes a single hypothesis as a concrete test against the target."""

    def __init__(self, store: KnowledgeStore, policy: PolicyEnforcer) -> None:
        self._store = store
        self._policy = policy

    def run(
        self,
        hypothesis: Hypothesis,
        target: TargetAdapter,
        target_model: Target,
    ) -> Experiment:
        """Run an experiment: plan, execute, collect evidence, persist."""
        test_spec = TestSpec(
            name=f"test-{hypothesis.origin}",
            description=hypothesis.statement,
            parameters={
                "weakness": hypothesis.origin.replace("strategy:", ""),
            },
            expected_outcome=self._expected_outcome(hypothesis),
        )

        self._policy.check(Operation.TEST, target_model)

        result = target.execute_test(test_spec)
        evidence = target.collect_evidence()

        experiment = Experiment(
            hypothesis_id=hypothesis.id,
            target_id=target_model.id,
            openmodels_version=VERSION,
            test=test_spec,
            expected_result=hypothesis.statement,
            observed_result=result.observed_result,
            outcome=result.outcome,
            conclusion=self._build_conclusion(hypothesis, result),
            completed_at=utcnow(),
        )

        self._store.save_experiment(experiment)

        for ev in evidence:
            ev.experiment_id = experiment.id
            self._store.save_evidence(ev)

        experiment.evidence_ids = [ev.id for ev in evidence]
        self._store.save_experiment(experiment)

        return experiment

    @staticmethod
    def _expected_outcome(hypothesis: Hypothesis) -> str:
        return "SUCCESS" if hypothesis.confidence >= 0.5 else "FAILURE"

    @staticmethod
    def _build_conclusion(hypothesis: Hypothesis, result: TestResult) -> str:
        if result.outcome.value == "SUCCESS":
            return (
                f"Hypothesis confirmed: {hypothesis.statement}. "
                f"Weakness is exploitable."
            )
        elif result.outcome.value == "FAILURE":
            return (
                f"Hypothesis rejected: {hypothesis.statement}. "
                f"Attack path is blocked. {result.observed_result}"
            )
        elif result.outcome.value == "BLOCKED":
            return (
                f"Hypothesis blocked: {hypothesis.statement}. "
                f"Policy prevented execution."
            )
        return (
            f"Hypothesis inconclusive: {hypothesis.statement}. "
            f"Result: {result.observed_result}"
        )