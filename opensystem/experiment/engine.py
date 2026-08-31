"""Experiment engine — executes hypotheses against a target.

Every experiment is fully recorded and persisted. Failed experiments are
never discarded: a failed attack is valuable information about what the
defender has blocked.
"""

from __future__ import annotations

from opensystem import VERSION
from opensystem.evidence.engine import EvidenceCollector
from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Experiment,
    Hypothesis,
    Target,
    TestResult,
    TestSpec,
    utcnow,
)
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Operation
from opensystem.target.interface import Capability, TargetAdapter, adapter_capability


class ExperimentEngine:
    """Executes a single hypothesis as a concrete test against the target."""

    def __init__(
        self,
        store: KnowledgeStore,
        policy: PolicyEnforcer,
        collector: EvidenceCollector | None = None,
    ) -> None:
        self._store = store
        self._policy = policy
        self._collector = collector or EvidenceCollector(store)

    def run(
        self,
        hypothesis: Hypothesis,
        target: TargetAdapter,
        target_model: Target,
    ) -> Experiment:
        """Run an experiment: plan, execute, collect evidence, persist.

        The experiment and its evidence are persisted in one transaction; the
        experiment row is written once, with its evidence links included.
        """
        test_spec = self._plan_test(hypothesis, target, target_model)

        self._policy.check(Operation.TEST, target_model)

        result = target.execute_test(test_spec)

        experiment = Experiment(
            hypothesis_id=hypothesis.id,
            target_id=target_model.id,
            opensystem_version=VERSION,
            test=test_spec,
            expected_result=hypothesis.statement,
            observed_result=result.observed_result,
            outcome=result.outcome,
            conclusion=self._build_conclusion(hypothesis, result),
            completed_at=utcnow(),
        )

        with self._store.transaction():
            evidence = self._collector.collect(target, experiment_id=experiment.id)
            experiment.evidence_ids = [ev.id for ev in evidence]
            self._store.save_experiment(experiment)

        return experiment

    @staticmethod
    def _plan_test(
        hypothesis: Hypothesis,
        target: TargetAdapter,
        target_model: Target,
    ) -> TestSpec:
        """Build the concrete TestSpec for a hypothesis.

        Adapters declaring the TEST_PLANNING capability translate the
        hypothesis themselves (protocol-specific parameters). Otherwise the
        default v0.1 mock weakness model applies.
        """
        plan_fn = adapter_capability(target, Capability.TEST_PLANNING, "plan_test")
        if plan_fn is not None:
            return plan_fn(hypothesis, target_model)
        return TestSpec(
            name=f"test-{hypothesis.origin}",
            description=hypothesis.statement,
            parameters={
                "weakness": hypothesis.origin.replace("strategy:", ""),
            },
            expected_outcome=ExperimentEngine._expected_outcome(hypothesis),
        )

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