"""Tests for the experiment engine and lifecycle."""

from __future__ import annotations

from opensystem import VERSION
from opensystem.experiment.engine import ExperimentEngine
from opensystem.models import Hypothesis, HypothesisStatus, TestOutcome
from opensystem.policy.engine import PolicyEnforcer
from opensystem.policy.models import Operation, Policy


def test_experiment_success_persisted(store, http_target, policy):
    engine = ExperimentEngine(store, PolicyEnforcer(policy))
    target_model = http_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="security headers missing",
        origin="strategy:http-security-headers",
        status=HypothesisStatus.ACTIVE,
    )
    store.save_hypothesis(hyp)

    experiment = engine.run(hyp, http_target, target_model)
    assert experiment.outcome == TestOutcome.SUCCESS
    assert experiment.completed_at is not None
    assert experiment.opensystem_version == VERSION

    persisted = store.get_experiments_by_hypothesis(hyp.id)
    assert len(persisted) == 1


def test_inconclusive_experiment_is_retained(store, http_target, policy):
    engine = ExperimentEngine(store, PolicyEnforcer(policy))
    target_model = http_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="unknown test",
        origin="strategy:http-nonexistent",
    )
    store.save_hypothesis(hyp)

    experiment = engine.run(hyp, http_target, target_model)
    assert experiment.outcome == TestOutcome.ERROR

    # Every experiment remains in the record, even failures.
    assert len(store.get_experiments_by_hypothesis(hyp.id)) == 1


def test_experiment_records_conclusion(store, http_target, policy):
    engine = ExperimentEngine(store, PolicyEnforcer(policy))
    target_model = http_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="security headers missing",
        origin="strategy:http-security-headers",
    )
    store.save_hypothesis(hyp)
    experiment = engine.run(hyp, http_target, target_model)
    assert "confirm" in experiment.conclusion.lower()


def test_policy_violation_blocks_experiment(store, http_target):
    strict = Policy(
        target_name="http",
        allowed_operations=[Operation.OBSERVE],
    )
    engine = ExperimentEngine(store, PolicyEnforcer(strict))
    target_model = http_target.discover()
    store.save_target(target_model)
    hyp = Hypothesis(
        target_id=target_model.id,
        statement="x",
        origin="strategy:http-security-headers",
    )
    store.save_hypothesis(hyp)

    from opensystem.policy.engine import PolicyViolation

    try:
        engine.run(hyp, http_target, target_model)
        assert False, "expected PolicyViolation"
    except PolicyViolation:
        pass