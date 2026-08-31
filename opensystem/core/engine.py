"""The core adversarial engine (Phase 4).

Implements the fundamental loop:

    OBSERVE → MODEL → HYPOTHESIZE → PLAN → TEST → OBSERVE RESULT
    → ANALYZE → UPDATE KNOWLEDGE → GENERATE NEXT HYPOTHESIS

The reasoning components are intentionally simple and deterministic in v0.1.
They are real, testable implementations — but they are NOT an advanced
autonomous attacker. The architecture is designed so that the mock reasoning
components can be replaced by increasingly capable reasoning systems
(LLM-backed reasoners, cross-component analyzers, etc.) without changing the
loop structure or the storage layer.
"""

from __future__ import annotations

from opensystem import VERSION
from opensystem.attack.planner import AttackPlanner, default_planner
from opensystem.evolution.engine import EvolutionEngine
from opensystem.experiment.engine import ExperimentEngine
from opensystem.finding.engine import FindingEngine
from opensystem.hypothesis.engine import HypothesisEngine
from opensystem.journal.engine import JournalEngine
from opensystem.knowledge.store import KnowledgeStore
from opensystem.models import (
    Experiment,
    Finding,
    Hypothesis,
    HypothesisStatus,
    Knowledge,
    KnowledgeKind,
    ResearchReport,
    Target,
    TestOutcome,
)
from opensystem.observation.engine import ObservationEngine
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Policy, StopReason
from opensystem.target.interface import TargetAdapter


class AdversarialEngine:
    """Orchestrates the adversarial loop against a target adapter."""

    def __init__(
        self,
        store: KnowledgeStore,
        policy: Policy | None = None,
        planner: AttackPlanner | None = None,
    ) -> None:
        self._store = store
        self._policy = policy or Policy()
        self._policy_enforcer = PolicyEnforcer(self._policy)
        self._planner = planner or default_planner(store)

        self._observations = ObservationEngine(store)
        self._hypotheses = HypothesisEngine(store)
        self._experiments = ExperimentEngine(store, self._policy_enforcer)
        self._findings = FindingEngine(store)
        self._evolution = EvolutionEngine(store)
        self._journal = JournalEngine(store)

    @property
    def store(self) -> KnowledgeStore:
        """The knowledge store backing this engine."""
        return self._store

    # ------------------------------------------------------------------ #
    # Research session
    # ------------------------------------------------------------------ #

    def research(self, target: TargetAdapter, rounds: int | None = None) -> ResearchReport:
        """Run a research session against a target adapter.

        The session respects the policy boundary (max rounds, max experiments,
        allowed operations). Returns an evidence-based ResearchReport.
        """
        rounds = rounds if rounds is not None else self._policy.max_rounds

        # 1. DISCOVER / MODEL
        target_model = target.discover()
        self._store.save_target(target_model)

        # 2. OBSERVE
        observations = self._observations.observe(target, target_id=target_model.id)

        # 3. MODEL — persist a description as knowledge
        self._store.save_knowledge(
            Knowledge(
                kind=KnowledgeKind.ASSUMPTION,
                content=f"target model built for {target_model.name}: {target.describe()}",
                target_id=target_model.id,
                provenance="engine.research/model",
            )
        )

        # 4. HYPOTHESIZE
        queue: list[Hypothesis] = self._planner.generate_hypotheses(
            target_model, observations, limit=max(rounds, len(self._planner.strategies))
        )
        for h in queue:
            self._store.save_hypothesis(h)

        report = ResearchReport(
            target_id=target_model.id,
            opensystem_version=VERSION,
            attack_classes_attempted=set(),
        )

        experiments_run = 0
        found_finding: Finding | None = None
        stop_reason = StopReason.MANUAL.value

        # 5-11. PLAN → TEST → OBSERVE → ANALYZE → UPDATE → GENERATE NEXT
        while queue and rounds > 0:
            if self._policy_enforcer.is_exhausted(len(report.attack_classes_attempted), experiments_run):
                stop_reason = StopReason.POLICY_STOP.value
                break

            hypothesis = queue.pop(0)
            self._store.update_hypothesis_status(hypothesis.id, HypothesisStatus.ACTIVE)
            report.hypotheses_formed += 1

            # PLAN + TEST
            experiment = self._experiments.run(hypothesis, target, target_model)
            experiments_run += 1
            report.experiments_run += 1
            report.rounds_executed += 1

            # JOURNAL — record the attack with full methodology + runtime detail.
            self._journal.record_experiment(
                target_model, hypothesis, experiment,
                detail=experiment.test.parameters,
            )

            # OBSERVE RESULT + ANALYZE
            self._hypotheses.evaluate(hypothesis, experiment)
            report.attack_classes_attempted.add(hypothesis.origin)

            if experiment.outcome == TestOutcome.SUCCESS:
                report.successful_tests += 1
                finding = self._findings.create_from_experiment(experiment, target_model.id)
                if finding is not None:
                    report.findings_created += 1
                    report.open_findings += 1
                    found_finding = finding

            elif experiment.outcome == TestOutcome.FAILURE:
                report.failed_tests += 1
            elif experiment.outcome == TestOutcome.BLOCKED:
                report.blocked_tests += 1
            else:
                report.inconclusive_tests += 1

            # UPDATE KNOWLEDGE + EVOLVE
            self._evolution.on_experiment(experiment)
            if experiment.outcome in (TestOutcome.FAILURE, TestOutcome.BLOCKED):
                next_hyp = self._evolve_from_blocked(hypothesis, target_model)
                if next_hyp is not None:
                    queue.append(next_hyp)

            rounds -= 1

            # Stop-on-finding is checked after the experiment's own
            # bookkeeping so the finding is fully recorded; no further
            # hypotheses are tested.
            if (
                found_finding is not None
                and self._policy_enforcer.should_stop_on_finding()
            ):
                stop_reason = StopReason.FINDING_STOP.value
                break

        if stop_reason == StopReason.MANUAL.value:
            if rounds <= 0:
                stop_reason = StopReason.MAX_ROUNDS.value
            elif not queue:
                stop_reason = StopReason.NO_MORE_HYPOTHESES.value

        report.stopped_reason = stop_reason
        self._store.save_knowledge(
            Knowledge(
                kind=KnowledgeKind.PATTERN,
                content=(
                    f"research session ended: {stop_reason}; "
                    f"{report.experiments_run} experiments, "
                    f"{report.findings_created} findings."
                ),
                target_id=target_model.id,
                provenance="engine.research/summary",
            )
        )
        return report

    # ------------------------------------------------------------------ #
    # Single experiment (public API)
    # ------------------------------------------------------------------ #

    def run_experiment(
        self,
        target: TargetAdapter,
        hypothesis: Hypothesis,
    ) -> Experiment:
        """Run a single experiment against a target adapter."""
        target_model = target.discover()
        self._store.save_target(target_model)
        if hypothesis.target_id != target_model.id:
            hypothesis = hypothesis.model_copy(update={"target_id": target_model.id})
        self._store.save_hypothesis(hypothesis)
        experiment = self._experiments.run(hypothesis, target, target_model)
        self._hypotheses.evaluate(hypothesis, experiment)
        self._evolution.on_experiment(experiment)
        self._journal.record_experiment(
            target_model, hypothesis, experiment,
            detail=experiment.test.parameters,
        )
        if experiment.outcome == TestOutcome.SUCCESS:
            self._findings.create_from_experiment(experiment, target_model.id)
        return experiment

    def _evolve_from_blocked(
        self, blocked: Hypothesis, target_model: Target
    ) -> Hypothesis | None:
        """Evolve a blocked hypothesis into an alternate-path hypothesis.

        Only strategies applicable to the target's adapter are considered —
        a weakness strategy from another adapter must never be evolved
        against this target.
        """
        blocked_key = blocked.origin.replace("strategy:", "")
        alternate = [
            s.weakness_key
            for s in self._planner.strategies.values()
            if s.weakness_key is not None
            and s.weakness_key != blocked_key
            and (
                s.applies_to is None
                or target_model.adapter in s.applies_to
            )
        ]
        return self._evolution.next_hypothesis(blocked, alternate)